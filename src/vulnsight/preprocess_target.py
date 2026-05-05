from __future__ import annotations
import os
import hashlib
import ast
from typing import List, Set, Dict, Callable, Tuple

from .types import CodeBlock, VulnKnowledge, CallGraph
from .callgraph_builder import get_callgraph_builder
from .semantic_reconstruction import safe_json_loads 

LLMFunc = Callable[[str], str]


class LSHConfig:
    def __init__(self, num_perm: int = 64, jaccard_threshold: float = 0.6):
        self.num_perm = num_perm
        self.jaccard_threshold = jaccard_threshold


from .utils import build_file_tree, summarize_block_symbolic

# =========================
#  Java AST 级方法块抽取
# =========================
try:
    from javalang.parse import parse as java_parse
    import javalang
except ImportError:
    java_parse = None
    javalang = None

import re

def _extract_python_blocks_heuristic(file_path: str, code: str) -> List[CodeBlock]:
    """
    在 ast.parse 失败或没有任何函数/类时，启发式按 def/class 切分 Python 文件。

    规则（简单但够用）：
    - 行（去掉左侧空白后）以 'def ' / 'async def ' / 'class ' 开头
    - 用缩进变化确定代码块结束位置
    """
    lines = code.splitlines()
    n_lines = len(lines)
    blocks: List[CodeBlock] = []

    def find_block_end(start_idx: int) -> int:
        """
        从 start_idx 开始，根据缩进找到块结束行（返回 1-based 行号的 end_line）。
        """
        base_line = lines[start_idx]
        base_indent = len(base_line) - len(base_line.lstrip())
        i = start_idx + 1
        while i < n_lines:
            line = lines[i]
            # 允许空行 & 纯注释行留在当前块中
            if not line.strip() or line.lstrip().startswith("#"):
                i += 1
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= base_indent:
                # 下一个顶格/更小缩进的非空行，说明前一个块结束
                break
            i += 1
        return i  # end_line = i

    header_pattern = re.compile(
        r'^(async\s+def|def|class)\s+([A-Za-z_][A-Za-z0-9_]*)'
    )

    for idx, line in enumerate(lines):
        stripped = line.lstrip()
        if not (stripped.startswith("def ")
                or stripped.startswith("async def ")
                or stripped.startswith("class ")):
            continue

        m = header_pattern.match(stripped)
        if m:
            kind_kw = m.group(1)  # def / async def / class
            name = m.group(2)
        else:
            kind_kw = "def"
            name = None

        start_line = idx + 1
        end_idx = find_block_end(idx)
        end_line = max(start_line, end_idx)  # 至少一行

        snippet = "\n".join(lines[idx:end_idx])

        # 映射到和 AST 版本类似的 kind
        if kind_kw.startswith("async"):
            kind = "AsyncFunctionDef"
        elif kind_kw == "class":
            kind = "ClassDef"
        else:
            kind = "FunctionDef"

        block_id = f"py_heur_{os.path.basename(file_path)}_{kind}_{name}_{start_line}_{end_line}"

        blocks.append(
            CodeBlock(
                id=block_id,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                content=snippet,
                language="python",
                metadata={
                    "name": name,
                    "kind": kind,
                    "heuristic": True,
                },
            )
        )

    return blocks


def _extract_java_methods_heuristic(file_path: str, code: str) -> List[CodeBlock]:
    """
    在 javalang 不可用或解析失败时，启发式地按“方法/构造函数”切分 Java 文件。

    大致规则：
    - 方法起始行：同时满足
      * 这一行包含 '(' 和 ')'
      * 这一行以 '{' 结尾（去掉空白后）
      * 这一行不是 if/for/while/switch/catch/do/else/try 等控制语句
    - 从起始行开始用大括号计数找到结束行
    """
    lines = code.splitlines()
    n_lines = len(lines)

    # 粗略找类名（第一个 "class XXX"）
    class_name = None
    m = re.search(r"class\s+([A-Za-z_][A-Za-z0-9_]*)", code)
    if m:
        class_name = m.group(1)

    control_keywords = ("if", "for", "while", "switch", "catch", "do", "else", "try")

    def is_method_header(line: str) -> bool:
        stripped = line.strip()
        if not stripped.endswith("{"):
            return False
        if "(" not in stripped or ")" not in stripped:
            return False
        # 控制语句排除
        for kw in control_keywords:
            if stripped.startswith(kw + " " ) or stripped.startswith(kw + "("):
                return False
        # 不是匿名内部类 new XXX() {
        if stripped.lstrip().startswith("new "):
            return False
        return True

    def find_method_end(start_idx: int) -> int:
        """从 start_idx 开始用大括号计数，返回结束行号（1-based）"""
        brace_depth = 0
        i = start_idx
        while i < n_lines:
            line = lines[i]
            brace_depth += line.count("{")
            brace_depth -= line.count("}")
            if i > start_idx and brace_depth <= 0:
                return i + 1  # 行号 index+1
            i += 1
        return n_lines

    blocks: List[CodeBlock] = []

    for i, line in enumerate(lines):
        if not is_method_header(line):
            continue

        start_line = i + 1
        end_line = find_method_end(i)
        snippet = "\n".join(lines[i:end_line])

        # 提取方法名（非常粗略，但够用了）
        name = None
        header = line.strip()
        m2 = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", header)
        if m2:
            name = m2.group(1)

        kind = "Method"
        if class_name and name == class_name:
            kind = "Constructor"

        block_id = f"java_heur_{os.path.basename(file_path)}_{start_line}_{end_line}"

        blocks.append(
            CodeBlock(
                id=block_id,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                content=snippet,
                language="java",
                metadata={"name": name, "kind": kind, "heuristic": True},
            )
        )

    return blocks

def _extract_java_method_blocks(file_path: str, code: str) -> List[CodeBlock]:
    """
    使用 javalang 从 Java 源文件中抽取方法级代码块。

    优先级：
    1) 若 javalang 可用且解析成功，用 AST 拿 MethodDeclaration / ConstructorDeclaration
    2) 若 javalang 不可用 / 解析失败 / 没有任何方法节点，则启用启发式切分
    """
    # ---------- 情况 1：javalang 完全不可用 ----------
    if java_parse is None:
        return _extract_java_methods_heuristic(file_path, code)

    # ---------- 情况 2：尝试用 javalang AST ----------
    try:
        tree = java_parse(code)
    except Exception:
        # 解析失败，启用启发式
        return _extract_java_methods_heuristic(file_path, code)

    lines = code.splitlines()

    def _guess_end_line(start_idx: int) -> int:
        """
        非严格花括号匹配，从 start_idx 行开始往下扫，
        当大括号配平或遇到文件末尾时停止。
        """
        brace_depth = 0
        i = start_idx
        while i < len(lines):
            line = lines[i]
            brace_depth += line.count("{")
            brace_depth -= line.count("}")
            if i > start_idx and brace_depth <= 0:
                return i + 1  # 行号 = index + 1
            i += 1
        return len(lines)

    blocks: List[CodeBlock] = []

    for _, node in tree.filter(
        (javalang.tree.MethodDeclaration, javalang.tree.ConstructorDeclaration)
    ):
        if not getattr(node, "position", None):
            continue
        start_line = node.position.line
        start_idx = max(0, start_line - 1)
        end_line = _guess_end_line(start_idx)
        snippet = "\n".join(lines[start_idx:end_line])

        block_id = f"java_{os.path.basename(file_path)}_{start_line}_{end_line}"
        blocks.append(
            CodeBlock(
                id=block_id,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                content=snippet,
                language="java",
                metadata={
                    "name": getattr(node, "name", None),
                    "kind": type(node).__name__,
                    "heuristic": False,
                },
            )
        )

    # ---------- 情况 3：AST 解析成功但没找到任何方法 ----------
    if not blocks:
        return _extract_java_methods_heuristic(file_path, code)

    return blocks



def _extract_python_blocks(file_path: str, code: str) -> List[CodeBlock]:
    """
    使用 Python AST 抽取函数 / 方法 / 类级别代码块。
    优先级：
    1) ast.parse 成功 -> 用 AST 取 FunctionDef/AsyncFunctionDef/ClassDef
    2) ast.parse 失败 / 没有节点 -> 启发式按 def/class 切分
    3) 启发式也没找到 -> 整文件一个块
    """
    # ---------- 情况 1：尝试用 AST ----------
    try:
        tree = ast.parse(code)
    except Exception:
        # 解析失败，启用启发式
        blocks = _extract_python_blocks_heuristic(file_path, code)
        if blocks:
            return blocks
        # 启发式也没用，只好整文件一个块
        n_lines = code.count("\n") + 1
        block_id = f"pyfile_{os.path.basename(file_path)}"
        return [
            CodeBlock(
                id=block_id,
                file_path=file_path,
                start_line=1,
                end_line=n_lines,
                content=code,
                language="python",
                metadata={"kind": "Module", "fallback": "whole_file"},
            )
        ]

    lines = code.splitlines()
    n_lines = len(lines)

    def _guess_end_line_from_indent(start_idx: int) -> int:
        """根据缩进估计结束行（兜底策略）"""
        base_indent = len(lines[start_idx]) - len(lines[start_idx].lstrip())
        i = start_idx + 1
        while i < n_lines:
            line = lines[i]
            if not line.strip():
                i += 1
                continue
            indent = len(line) - len(line.lstrip())
            if indent <= base_indent:
                return i
            i += 1
        return n_lines

    blocks: List[CodeBlock] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not hasattr(node, "lineno"):
                continue
            start_line = node.lineno
            start_idx = max(0, start_line - 1)

            if hasattr(node, "end_lineno") and node.end_lineno is not None:
                end_line = node.end_lineno
            else:
                end_line = _guess_end_line_from_indent(start_idx)

            end_line = max(end_line, start_line)
            end_line = min(end_line, n_lines)

            snippet = "\n".join(lines[start_idx:end_line])
            kind = type(node).__name__
            name = getattr(node, "name", None)
            block_id = f"py_{os.path.basename(file_path)}_{kind}_{name}_{start_line}_{end_line}"

            blocks.append(
                CodeBlock(
                    id=block_id,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    content=snippet,
                    language="python",
                    metadata={
                        "name": name,
                        "kind": kind,
                        "heuristic": False,
                    },
                )
            )

    # ---------- 情况 2：AST 成功但没找到任何函数/类 ----------
    if not blocks:
        blocks = _extract_python_blocks_heuristic(file_path, code)
        if blocks:
            return blocks
        # 还是没有，整文件一个块
        block_id = f"pyfile_{os.path.basename(file_path)}"
        return [
            CodeBlock(
                id=block_id,
                file_path=file_path,
                start_line=1,
                end_line=n_lines,
                content=code,
                language="python",
                metadata={"kind": "Module", "fallback": "whole_file"},
            )
        ]

    return blocks

# =========================
#  工程文件枚举 & 块构建
# =========================

def list_project_files(root: str, exts=None) -> List[str]:
    """
    列出项目中的源文件 / 配置文件。
    扩展名覆盖：
      - 代码：.c, .cpp, .h, .hpp, .py, .java, .js, .ts, .go
      - 配置/依赖：.toml, .xml, .yml, .yaml, .ini, .properties, .txt
    """
    if exts is None:
        exts = [
            ".c", ".cpp", ".h", ".hpp",
            ".py", ".java", ".js", ".ts", ".go",
            ".toml", ".xml", ".yml", ".yaml",
            ".ini", ".properties", ".txt",
        ]
    res = []
    for r, _, files in os.walk(root):
        for f in files:
            if any(f.endswith(e) for e in exts):
                res.append(os.path.join(r, f))
    return res


def build_blocks_for_project(root: str) -> List[CodeBlock]:
    """
    统一的工程级代码块构建入口：
    - Java：使用 _extract_java_method_blocks（方法级别）
    - Python：使用 _extract_python_blocks（函数/类级别）
    - 其他/配置文件：整文件一个 CodeBlock
    """
    blocks: List[CodeBlock] = []
    files = list_project_files(root)

    for idx, path in enumerate(files):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            continue

        if path.endswith(".java"):
            java_blocks = _extract_java_method_blocks(path, content)
            if java_blocks:
                # 原有：只加入方法块
                blocks.extend(java_blocks)

                # ✅ 新增：为每个 Java 文件再加一个“头部块”
                lines = content.splitlines()
                # 可以只取前 80 行，基本能覆盖类/接口声明和 import
                header_len = min(80, len(lines))
                header_snippet = "\n".join(lines[:header_len])
                blocks.append(
                    CodeBlock(
                        id=f"java_header_{os.path.basename(path)}",
                        file_path=path,
                        start_line=1,
                        end_line=header_len,
                        content=header_snippet,
                        language="java",
                        metadata={"kind": "header"},
                    )
                )
                continue  # 已经通过 Java AST 处理完

        if path.endswith(".py"):
            py_blocks = _extract_python_blocks(path, content)
            if py_blocks:
                blocks.extend(py_blocks)
                continue  # 已经通过 Python AST 处理完

        # 其他语言 / 配置文件：整文件一个块
        line_count = content.count("\n") + 1
        block_id = f"file_{idx}"
        blocks.append(
            CodeBlock(
                id=block_id,
                file_path=path,
                start_line=1,
                end_line=line_count,
                content=content,
                language=None,
                metadata={"kind": "file"},
            )
        )

    return blocks


# =========================
#  LSH & 相似度候选
# =========================

def tokenize_for_lsh(code: str) -> List[str]:
    import re
    tokens = re.findall(r"[A-Za-z0-9_]+", code)
    grams = tokens[:]
    for i in range(len(tokens) - 1):
        grams.append(tokens[i] + "::" + tokens[i + 1])
    return grams


def minhash_signature(tokens: List[str], num_perm: int) -> List[int]:
    if not tokens:
        return [2**63 - 1] * num_perm
    seeds = list(range(num_perm))
    sig = [2**63 - 1] * num_perm
    for t in set(tokens):
        t_bytes = t.encode("utf-8")
        h_base = int(hashlib.sha1(t_bytes).hexdigest(), 16)
        for i, seed in enumerate(seeds):
            h = h_base ^ seed
            if h < sig[i]:
                sig[i] = h
    return sig


def jaccard_from_sig(sig1: List[int], sig2: List[int]) -> float:
    assert len(sig1) == len(sig2)
    same = sum(1 for a, b in zip(sig1, sig2) if a == b)
    return same / float(len(sig1))


def build_lsh_index(blocks: List[CodeBlock], cfg: LSHConfig):
    index = {}
    for b in blocks:
        tokens = tokenize_for_lsh(b.content)
        sig = minhash_signature(tokens, cfg.num_perm)
        index[b.id] = (b, sig)
    return index


def select_shash(
    target_blocks: List[CodeBlock],
    ref_blocks: List[CodeBlock],
    cfg: LSHConfig,
) -> List[CodeBlock]:
    ref_index = build_lsh_index(ref_blocks, cfg)
    ref_ids = list(ref_index.keys())
    ref_sigs = [ref_index[x][1] for x in ref_ids]

    shash: Set[str] = set()
    for tb in target_blocks:
        tb_sig = minhash_signature(tokenize_for_lsh(tb.content), cfg.num_perm)
        max_sim = 0.0
        for rid, rsig in zip(ref_ids, ref_sigs):
            sim = jaccard_from_sig(tb_sig, rsig)
            if sim > max_sim:
                max_sim = sim
        if max_sim >= cfg.jaccard_threshold:
            shash.add(tb.id)

    id2block = {b.id: b for b in target_blocks}
    return [id2block[i] for i in shash if i in id2block]



def resolve_path(fp: str, target_root: str, all_files: List[str]) -> str | None:
    """
    尝试把 LLM 返回的 file_path 映射成真实文件路径，尽量兼容：
    1) 如果 fp 是绝对路径并且存在 -> 直接返回
    2) 作为相对 target_root 的路径存在 -> 返回
    3) 在 all_files 中按文件名匹配：
       - 若只有一个同名文件 -> 返回
       - 若有多个同名文件 -> 用“路径后缀相似度”挑一个
    4) 再退一步，在 all_files 中按整体后缀匹配
    """

    # 统一规范化（兼容 Windows、/、\）
    norm_fp = fp.replace("\\", "/").lstrip("./")
    basename = os.path.basename(norm_fp)
    norm_fp_lower = norm_fp.lower()

    # 1) 绝对路径
    if os.path.isabs(fp) and os.path.exists(fp):
        return fp

    # 2) 相对 target_root
    cand = os.path.join(target_root, norm_fp)
    if os.path.exists(cand):
        return cand

    # 规范化 all_files
    norm_all = [p.replace("\\", "/") for p in all_files]
    norm_all_lower = [p.lower() for p in norm_all]

    # ---- 辅助函数：公共后缀长度（按字符） ----
    def _common_suffix_len(a: str, b: str) -> int:
        a = a.lower()
        b = b.lower()
        i = 0
        la, lb = len(a), len(b)
        while i < la and i < lb and a[la - 1 - i] == b[lb - 1 - i]:
            i += 1
        return i

    # 3) 先按文件名精确匹配（org/apache/... 不一致也没关系）
    same_name_idxs = [
        i for i, p in enumerate(norm_all)
        if os.path.basename(p) == basename
    ]

    # 只有一个同名文件，直接用它
    if len(same_name_idxs) == 1:
        return all_files[same_name_idxs[0]]

    # 多个同名：根据后缀相似度选一个（相似度高优先，长度短优先）
    if len(same_name_idxs) > 1:
        best_idx = None
        best_score = -1
        best_len = None
        for idx in same_name_idxs:
            score = _common_suffix_len(norm_fp, norm_all[idx])
            if score > best_score or (score == best_score and (best_len is None or len(norm_all[idx]) < best_len)):
                best_score = score
                best_idx = idx
                best_len = len(norm_all[idx])
        if best_idx is not None and best_score > 0:
            return all_files[best_idx]

    # 4) 文件名都对不上时：在 all_files 中按整体后缀匹配
    suffix_idxs = [
        i for i, np in enumerate(norm_all_lower)
        if np.endswith(norm_fp_lower)
    ]
    if len(suffix_idxs) == 1:
        return all_files[suffix_idxs[0]]
    elif len(suffix_idxs) > 1:
        best_idx = None
        best_score = -1
        best_len = None
        for idx in suffix_idxs:
            score = _common_suffix_len(norm_fp, norm_all[idx])
            if score > best_score or (score == best_score and (best_len is None or len(norm_all[idx]) < best_len)):
                best_score = score
                best_idx = idx
                best_len = len(norm_all[idx])
        if best_idx is not None and best_score > 0:
            return all_files[best_idx]

    # 都找不到
    return None

def group_blocks_by_file(blocks: List[CodeBlock]) -> Dict[str, List[CodeBlock]]:
    """
    按文件路径把 CodeBlock 分组，路径用 normpath 统一。
    """
    res: Dict[str, List[CodeBlock]] = {}
    for b in blocks:
        if not b.file_path:
            continue
        key = os.path.normpath(b.file_path)
        res.setdefault(key, []).append(b)
    return res

def llm_expand_target(
    llm: LLMFunc,
    ref_blocks: List[CodeBlock],
    target_root: str,
    desc: str | None = None,
    patch_diff: str | None = None,
    lsh_cfg: LSHConfig | None = None,
    file_blocks_index: Dict[str, List[CodeBlock]] | None = None,
    existing_blocks: List[CodeBlock] | None = None,
) -> List[CodeBlock]:
    """
    LLM 只用来选“可能相关的文件”，真正的代码块由 LSH 在这些文件中重新筛选。
    行号 start_line / end_line 只作为 soft hint，可以完全忽略或将来再用。
    """
    # 1) ref 摘要
    def _blocks_to_str(blocks: List[CodeBlock]) -> str:
        parts = []
        for b in blocks[:20]:
            parts.append(summarize_block_symbolic(b))
        return "\n".join(parts)

    ref_str = _blocks_to_str(ref_blocks)

    if existing_blocks:
        existing_str = _blocks_to_str(existing_blocks)
    else:
        existing_str = "None"

    # 2) 推断语言后缀，列出真实文件（主要是为了 build_file_tree）
    ref_exts = {os.path.splitext(b.file_path)[1] for b in ref_blocks if b.file_path}
    if not ref_exts:
        ref_exts = {".py", ".java", ".c", ".cpp"}

    all_files = list_project_files(target_root, exts=list(ref_exts))
    file_tree = build_file_tree(target_root, max_entries=200, exts=list(ref_exts))

    dv = desc or "N/A"
    pv = patch_diff or "N/A"

    prompt = f"""You are a code understanding assistant.

We are checking whether a known vulnerability may reappear in a TARGET project.

[Official vulnerability description (Dv)]
{dv}

[Patch diff (Pv)]
{pv}

[Reference code summaries from vulnerable/fixed versions (Bv_ref)]
Each line describes a function or code region related to the vulnerability:
{ref_str}

[Target project file structure]
{file_tree}

[Already selected candidate regions in the TARGET project]
These code regions have ALREADY been selected by other heuristics (LSH, same-name, etc.).
You do NOT need to repeat them. Only suggest ADDITIONAL regions if they are relevant:
{existing_str}

Task:
Based on:
- the vulnerability description Dv,
- the patch diff Pv,
- the reference summaries Bv_ref,
- the target project's structure, and
- the already selected candidate regions,

decide which ADDITIONAL functions/methods in the TARGET project should be inspected
to determine whether the vulnerability reappears.

For each suggestion, provide:
- the file path (relative to the project root),
- the function/method/constructor name (if applicable),
- an optional rough line range hint,
- and a short reason.

Return your answer in pure JSON ONLY, e.g.:

[
  {{
    "file_path": "src/main/java/org/dom4j/QName.java",
    "function": "QName", 
    "start_line": 70,
    "end_line": 130,
    "reason": "QName constructors that take user-controlled names and namespaces"
  }},
  {{
    "file_path": "src/main/java/org/dom4j/Namespace.java",
    "function": "Namespace",
    "start_line": 40,
    "end_line": 90,
    "reason": "Namespace constructor that accepts prefix and uri"
  }}
]
""".strip()


    raw = llm(prompt)
    try:
        data = safe_json_loads(raw)
        # print(data)  # 调试用
    except Exception:
        return []

    if not isinstance(data, list):
        return []

    # 如果没传 index 或 cfg，就创建一个
    # 如果没传 index 或 cfg，就创建一个
    if file_blocks_index is None:
        Bt_all = build_blocks_for_project(target_root)
        file_blocks_index = group_blocks_by_file(Bt_all)
    if lsh_cfg is None:
        lsh_cfg = LSHConfig()

    # 已有块（避免重复）
    existing_ids: Set[str] = set()
    existing_keys: Set[Tuple[str, str]] = set()  # (file_path, name)
    if existing_blocks:
        for b in existing_blocks:
            existing_ids.add(b.id)
            name = b.metadata.get("name")
            if name:
                existing_keys.add((os.path.normpath(b.file_path), name))

    result_blocks: Dict[str, CodeBlock] = {}

    for item in data:
        if not isinstance(item, dict):
            continue

        fp = item.get("file_path")
        if not fp:
            continue

        real_fp = resolve_path(fp, target_root, all_files)
        if not real_fp:
            continue

        key = os.path.normpath(real_fp)
        file_blocks = file_blocks_index.get(key, [])
        if not file_blocks:
            # 没有预建索引，兜底整文件一个块
            try:
                with open(real_fp, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue
            n_lines = content.count("\n") + 1
            file_blocks = [
                CodeBlock(
                    id=f"file_{os.path.basename(real_fp)}",
                    file_path=real_fp,
                    start_line=1,
                    end_line=n_lines,
                    content=content,
                    language=None,
                    metadata={"kind": "file"},
                )
            ]

        func_name = (
            item.get("function")
            or item.get("method")
            or item.get("name")
        )
        local_candidates: List[CodeBlock] = []

        # 1) 若提供了函数名，优先按 metadata["name"] 精确匹配
        if func_name:
            for b in file_blocks:
                if b.metadata.get("name") == func_name:
                    local_candidates.append(b)

        # 2) 没有匹配到函数名，就在这个文件里做一次局部 LSH
        if not local_candidates:
            local_candidates = select_shash(file_blocks, ref_blocks, lsh_cfg)

        # 3) 去掉已经在 existing_blocks 里的块
        for b in local_candidates:
            k = (os.path.normpath(b.file_path), b.metadata.get("name"))
            if b.id in existing_ids or (k in existing_keys):
                continue
            if b.id not in result_blocks:
                result_blocks[b.id] = b

    return list(result_blocks.values())




# =========================
#  调用图 & 一跳上下文扩展
# =========================

def build_target_call_graph(target_root: str, language_hint: str = "") -> CallGraph:
    builder = get_callgraph_builder(language_hint)
    return builder.build(target_root, language_hint)


def expand_context_via_callgraph(
    blocks: List[CodeBlock],
    graph: CallGraph,
    node_to_block: Dict[str, CodeBlock] | None = None,
) -> List[CodeBlock]:
    """
    从 blocks 对应的调用图节点出发，取一跳邻居对应的 CodeBlock。
    node_to_block 可以来自对应语言的 callgraph builder。
    当前版本假设节点 ID 在 node_to_block 里已经映射。
    """
    if not graph.nodes or not graph.edges:
        return blocks

    if node_to_block is None:
        node_to_block = {}

    # 起点：node_to_block 中那些与当前 blocks 同文件的节点可以被视为候选
    # （更精细的 block <-> node 映射可以在 callgraph builder 内部实现后再接）
    start_nodes: Set[str] = set()
    for nid, b in node_to_block.items():
        for tb in blocks:
            if tb.file_path == b.file_path:
                start_nodes.add(nid)
                break

    if not start_nodes:
        return blocks

    neighbors = set()
    for e in graph.edges:
        if e.src in start_nodes and e.dst in node_to_block:
            neighbors.add(e.dst)
        if e.dst in start_nodes and e.src in node_to_block:
            neighbors.add(e.src)

    ctx_blocks = [node_to_block[nid] for nid in neighbors if nid in node_to_block]
    return ctx_blocks

def compute_global_symbols(Bt: List[CodeBlock]) -> Dict[str, bool]:
    text = "\n".join(b.content for b in Bt)
    return {
        "has_DecodingException": "DecodingException" in text,
        "has_isPayloadValid": "isPayloadValid" in text,
        # 以后还可以加别的
    }

def expand_block_range(block: CodeBlock, up: int = 0, down: int = 0) -> CodeBlock:
    """
    将给定的 CodeBlock 裁切到“完整函数 / 方法 / 构造函数”级别：
    - 如果是 Java：用 _extract_java_method_blocks 重新解析该文件，找到包含 block.start_line 的方法块；
    - 如果是 Python：用 _extract_python_blocks 重新解析该文件，找到包含 block.start_line 的函数 / 类块；
    - 如果找不到，就退回到原来的“上下扩若干行”的兜底策略。

    参数 up/down：在完整函数的基础上，可选地再向上/向下扩几行（默认 0，即只要完整函数，不加额外上下文）。
    """
    try:
        with open(block.file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        # 文件读不到，直接返回原 block
        return block

    n = len(lines)
    code = "".join(lines)

    chosen: CodeBlock | None = None

    # ---- 1) 按语言尝试找到“完整函数块” ----
    if block.language == "java":
        try:
            method_blocks = _extract_java_method_blocks(block.file_path, code)
            for mb in method_blocks:
                # 找到那个“包住当前块起始行”的方法
                if mb.start_line <= block.start_line <= mb.end_line:
                    chosen = mb
                    break
        except Exception:
            chosen = None

    elif block.language == "python":
        try:
            py_blocks = _extract_python_blocks(block.file_path, code)
            for pb in py_blocks:
                if pb.start_line <= block.start_line <= pb.end_line:
                    chosen = pb
                    break
        except Exception:
            chosen = None

    # ---- 2) 如果成功找到完整函数，就按函数边界来裁切 ----
    if chosen is not None:
        new_start = max(1, chosen.start_line - up)
        new_end = min(n, chosen.end_line + down)
        new_content = "".join(lines[new_start - 1:new_end])

        return CodeBlock(
            id=f"{chosen.id}_cropped_from_{block.id}",
            file_path=block.file_path,
            start_line=new_start,
            end_line=new_end,
            content=new_content,
            language=block.language,
            metadata={**chosen.metadata, "cropped_full_func": True},
        )

    # ---- 3) 找不到函数块，退回老的“扩行”逻辑兜底 ----
    new_start = max(1, block.start_line - up)
    new_end = min(n, block.end_line + down)
    new_content = "".join(lines[new_start - 1:new_end])

    return CodeBlock(
        id=f"{block.id}_expanded_fallback",
        file_path=block.file_path,
        start_line=new_start,
        end_line=new_end,
        content=new_content,
        language=block.language,
        metadata={**block.metadata, "expanded_fallback": True},
    )




# =========================
#  统一候选空间构建入口
# =========================
from .types import VulnKnowledge
def build_candidate_space(
    target_root: str,
    Bvref: List[CodeBlock],
    llm: LLMFunc,
    lsh_cfg: LSHConfig,
    vuln: VulnKnowledge | None = None,
    language_hint: str = "",
):
    # 1) 全项目块
    Bt = build_blocks_for_project(target_root)

    # 按文件分组，后面传给 llm_expand_target
    file_blocks_index = group_blocks_by_file(Bt)

    # 2) LSH（全局 LSH）
    Shash = select_shash(Bt, Bvref, lsh_cfg)

    # 2.5) 同名文件兜底（基于 Bvref 的文件名）
    bt_by_basename: Dict[str, List[CodeBlock]] = {}
    for b in Bt:
        name = os.path.basename(b.file_path)
        bt_by_basename.setdefault(name, []).append(b)

    ref_basenames = {os.path.basename(b.file_path) for b in Bvref if b.file_path}
    SameName: List[CodeBlock] = []
    for name in ref_basenames:
        SameName.extend(bt_by_basename.get(name, []))

    # 初始候选：LSH + 同名文件
    initial_candidates = Shash + SameName

    # 3) 准备 Dv / Pv
    if isinstance(vuln, VulnKnowledge):
        desc = vuln.desc
        patch_diff = vuln.patch_diff
    else:
        desc = None
        patch_diff = None

    # 3.5) LLM 基于已有候选 + 目录树，补充“额外文件/函数”
    Sllm = llm_expand_target(
        llm,
        Bvref,
        target_root,
        desc=desc,
        patch_diff=patch_diff,
        lsh_cfg=lsh_cfg,
        file_blocks_index=file_blocks_index,
        existing_blocks=initial_candidates,
    )

    # 4) 调用图 + 一跳上下文
    builder = get_callgraph_builder(language_hint)
    Gt = builder.build(target_root, language_hint)
    node_to_block: Dict[str, CodeBlock] = {}
    if hasattr(builder, "get_node_to_block"):
        try:
            node_to_block = builder.get_node_to_block() or {}
        except Exception:
            node_to_block = {}

    merged: Dict[str, CodeBlock] = {}

    # 4.1 合并初始候选和 LLM 补充的结果
    for b in (initial_candidates + Sllm):
        if b.id not in merged:
            merged[b.id] = b

    # 4.2 一跳调用图上下文扩展
    Sctx = expand_context_via_callgraph(list(merged.values()), Gt, node_to_block)
    for b in Sctx:
        if b.id not in merged:
            merged[b.id] = b

    # 5) 裁切成完整函数 / 扩展行号
    Scand_raw = [expand_block_range(b) for b in merged.values()]

    # 6) 按 (file_path, start_line, end_line) 去重
    uniq: Dict[Tuple[str, int, int], CodeBlock] = {}
    for b in Scand_raw:
        key = (os.path.normpath(b.file_path), b.start_line, b.end_line)
        if key not in uniq:
            uniq[key] = b

    Scand = list(uniq.values())

    global_signals = compute_global_symbols(Bt)
    return Bt, Scand, global_signals
