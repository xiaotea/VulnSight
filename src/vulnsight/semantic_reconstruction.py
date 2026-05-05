from __future__ import annotations
import os
from typing import List, Tuple, Dict, Any, Callable
from dataclasses import dataclass
from unidiff import PatchSet

from .types import (
    VulnKnowledge,
    CodeBlock,
    CallGraph,
    VulnPattern,
    SafePattern,
    PatternPair,
    CodeSpan,
)
from .callgraph_builder import get_builder_for_language
from .utils import build_file_tree

LLMFunc = Callable[[str], str]


@dataclass
class SemanticReconstructionConfig:
    hits_top_k: int = 20
    llm_batch_size: int = 4000
    language_hint: str = ""


@dataclass
class SemanticReconstructionOutput:
    patterns: PatternPair
    vuln_blocks: List[CodeBlock]
    fix_blocks: List[CodeBlock]


def _strip_diff_prefix(path: str) -> str:
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path.lstrip("./")


def locate_patch_blocks(vuln: VulnKnowledge) -> Tuple[List[CodeBlock], List[CodeBlock]]:
    """使用统一 diff 在漏洞版本 / 修复版本中定位 Bv(0) / Bvfix(0)."""
    if not vuln.patch_diff:
        raise ValueError("patch_diff (Pv) is empty")

    patch = PatchSet(vuln.patch_diff.splitlines(keepends=True))


    Bv0: List[CodeBlock] = []
    Bvfix0: List[CodeBlock] = []
    

    for file_idx, patched_file in enumerate(patch):
        old_rel = _strip_diff_prefix(patched_file.source_file)
        new_rel = _strip_diff_prefix(patched_file.target_file)

        old_abs = os.path.join(vuln.vuln_proj_root, old_rel)
        new_abs = os.path.join(vuln.fix_proj_root, new_rel)


        old_lines: List[str] = []
        new_lines: List[str] = []
        if os.path.exists(old_abs):
            with open(old_abs, "r", encoding="utf-8", errors="ignore") as f:
                old_lines = f.readlines()
        if os.path.exists(new_abs):
            with open(new_abs, "r", encoding="utf-8", errors="ignore") as f:
                new_lines = f.readlines()


        for hunk_idx, hunk in enumerate(patched_file):
            if old_lines and hunk.source_length > 0:
                src_start = hunk.source_start
                src_len = hunk.source_length
                src_end = src_start + src_len - 1
                start_idx = max(src_start - 1, 0)
                end_idx = min(src_start - 1 + src_len, len(old_lines))
                content = "".join(old_lines[start_idx:end_idx])
                Bv0.append(
                    CodeBlock(
                        id=f"vuln_{file_idx}_{hunk_idx}",
                        file_path=old_abs,
                        start_line=src_start,
                        end_line=src_end,
                        content=content,
                        language=None,
                        metadata={
                            "rel_path": old_rel,
                            "hunk_index": hunk_idx,
                            "role": "vuln",
                        },
                    )
                )
            if new_lines and hunk.target_length > 0:
                tgt_start = hunk.target_start
                tgt_len = hunk.target_length
                tgt_end = tgt_start + tgt_len - 1
                start_idx = max(tgt_start - 1, 0)
                end_idx = min(tgt_start - 1 + tgt_len, len(new_lines))
                content = "".join(new_lines[start_idx:end_idx])
                Bvfix0.append(
                    CodeBlock(
                        id=f"fix_{file_idx}_{hunk_idx}",
                        file_path=new_abs,
                        start_line=tgt_start,
                        end_line=tgt_end,
                        content=content,
                        language=None,
                        metadata={
                            "rel_path": new_rel,
                            "hunk_index": hunk_idx,
                            "role": "fix",
                        },
                    )
                )

    return Bv0, Bvfix0


def blocks_overlap(a: CodeBlock, b: CodeBlock) -> bool:
    if os.path.abspath(a.file_path) != os.path.abspath(b.file_path):
        return False
    return not (a.end_line < b.start_line or b.end_line < a.start_line)


def build_context_blocks(
    root_blocks: List[CodeBlock],
    graph: CallGraph,
    node_to_block: Dict[str, CodeBlock],
) -> List[CodeBlock]:
    if not graph.nodes or not node_to_block or not root_blocks:
        return []

    root_nodes = set()
    for node, blk in node_to_block.items():
        for rb in root_blocks:
            if blocks_overlap(rb, blk):
                root_nodes.add(node)
                break

    if not root_nodes:
        return []

    neigh_nodes = graph.neighbors(list(root_nodes))

    ctx_blocks: List[CodeBlock] = []
    seen_ids = set()
    for n in neigh_nodes:
        blk = node_to_block.get(n)
        if blk and blk.id not in seen_ids:
            ctx_blocks.append(blk)
            seen_ids.add(blk.id)

    return ctx_blocks


def hits_scores(
    graph: CallGraph,
    max_iter: int = 50,
    tol: float = 1e-6,
) -> Dict[str, float]:
    nodes = list(graph.nodes)
    n = len(nodes)
    if n == 0:
        return {}

    incoming = {v: [] for v in nodes}
    outgoing = {v: [] for v in nodes}
    for u, v in graph.edges:
        if u in outgoing:
            outgoing[u].append(v)
        if v in incoming:
            incoming[v].append(u)

    auth = {v: 1.0 for v in nodes}
    hub = {v: 1.0 for v in nodes}

    def _normalize(vec: Dict[str, float]):
        norm = sum(x * x for x in vec.values()) ** 0.5
        if norm == 0:
            return vec
        for k in vec:
            vec[k] /= norm
        return vec

    auth = _normalize(auth)
    hub = _normalize(hub)

    for _ in range(max_iter):
        new_auth: Dict[str, float] = {}
        for v in nodes:
            new_auth[v] = sum(hub[u] for u in incoming[v]) if incoming[v] else 0.0
        new_hub: Dict[str, float] = {}
        for v in nodes:
            new_hub[v] = sum(new_auth[w] for w in outgoing[v]) if outgoing[v] else 0.0
        _normalize(new_auth)
        _normalize(new_hub)
        diff = max(abs(new_auth[v] - auth[v]) for v in nodes)
        auth, hub = new_auth, new_hub
        if diff < tol:
            break

    return auth


def select_hits_blocks(
    graph: CallGraph,
    scores: Dict[str, float],
    top_k: int,
    node_to_block: Dict[str, CodeBlock],
) -> List[CodeBlock]:
    if not scores or not node_to_block or top_k <= 0:
        return []

    sorted_nodes = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    res: List[CodeBlock] = []
    seen_ids = set()
    for node, _ in sorted_nodes:
        blk = node_to_block.get(node)
        if not blk:
            continue
        if blk.id in seen_ids:
            continue
        res.append(blk)
        seen_ids.add(blk.id)
        if len(res) >= top_k:
            break
    return res


def llm_expand_blocks(
    llm: LLMFunc,
    init_blocks: List[CodeBlock],
    desc: str,
    patch_diff: str,
    project_root: str,
    role: str = "vuln",
) -> List[CodeBlock]:
    from textwrap import shorten

    # 1) 已有的核心代码块摘要
    block_snippets = []
    for b in init_blocks[:10]:
        snippet = shorten(b.content.replace("\n", " "), width=300, placeholder="...")
        block_snippets.append(
            f"[{b.file_path}:{b.start_line}-{b.end_line}]\n{snippet}"
        )
    blocks_str = "\n\n".join(block_snippets)

    # 2) 项目文件结构树（可以按后缀过滤）
    exts = [os.path.splitext(b.file_path)[1] for b in init_blocks if b.file_path]
    exts = list({e for e in exts if e}) or None
    file_tree = build_file_tree(project_root, max_entries=200, exts=exts)

    # 3) 新 prompt
    prompt = f"""You are a vulnerability analysis assistant.

We are analyzing a vulnerability in the **{role} version** of a project.

[Official description Dv]
{desc}

[Patch diff Pv]
{patch_diff}

[Already extracted core code blocks in the {role} version]
{blocks_str}

[Project file structure tree ({project_root})]
{file_tree}

Task:
Based on Dv, Pv, the existing core blocks, and the project file structure tree,
identify ADDITIONAL code regions that are semantically related to the vulnerability
in this {role} version. These may include:
- Helper functions directly used by the vulnerable logic
- Configuration or wrapper code that affects how the vulnerable logic is invoked
- Alternative implementations of the same API or data handling

Return your answer in pure JSON ONLY, as a list of objects:
[
  {{"file_path": "relative/path/to/file.py", "start_line": 10, "end_line": 50, "brief_reason": "..." }},
  ...
]
""".strip()

    raw = llm(prompt)
    try:
        import json
        data = safe_json_loads(raw)
    except Exception:
        return []

    blocks: List[CodeBlock] = []
    if isinstance(data, list):
        for idx, item in enumerate(data):
            try:
                fp = item["file_path"]
                st = int(item["start_line"])
                ed = int(item["end_line"])
            except Exception:
                continue
            abs_fp = fp if os.path.isabs(fp) else os.path.join(project_root, fp)
            try:
                with open(abs_fp, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except OSError:
                continue
            start_idx = max(st - 1, 0)
            end_idx = min(ed, len(lines))
            content = "".join(lines[start_idx:end_idx])
            blocks.append(
                CodeBlock(
                    id=f"llm_{role}_{idx}",
                    file_path=abs_fp,
                    start_line=st,
                    end_line=ed,
                    content=content,
                    language=None,
                    metadata={"role": role, "reason": item.get("brief_reason", "")},
                )
            )
    return blocks


def safe_json_loads(raw: str):
    """
    尝试从 LLM 输出中提取 JSON：
    1) 去掉 ```...``` Markdown 代码块包裹
    2) 先直接 json.loads
    3) 再从第一个 '{' 到最后一个 '}' 截取
    4) 失败则尝试去掉尾逗号再解析
    """
    import json
    import re

    if not raw or not raw.strip():
        raise ValueError("LLM 返回空字符串或仅包含空白，无法解析 JSON，请检查 my_llm 调用是否成功。")

    text = raw.strip()

    # 1) 去掉 Markdown ``` 包裹
    if text.startswith("```"):
        # 去掉第一行 ``` 或 ```json
        first_nl = text.find("\n")
        if first_nl != -1:
            text = text[first_nl + 1 :]
        text = text.strip()
        # 去掉结尾的 ```
        if text.endswith("```"):
            text = text[:-3].strip()

    # 2) 先尝试直接解析
    try:
        return json.loads(text)
    except Exception:
        pass

    # 3) 从第一个 '{' 到最后一个 '}' 截取
    start = text.find("{")
    end = text.rfind("}")
    candidate = None
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        try:
            return json.loads(candidate)
        except Exception:
            pass

        # 4) 去掉尾逗号再试一次（例如 ..., } 或 ..., ]）
        sanitized = re.sub(r",(\s*[}\]])", r"\1", candidate)
        try:
            return json.loads(sanitized)
        except Exception:
            pass

    # 实在不行，抛出带片段的异常方便调试
    snippet = text[:500].replace("\n", "\\n")
    raise ValueError(f"无法从 LLM 输出中解析 JSON，返回内容前 500 字符为：{snippet}")



def llm_extract_patterns(
    llm: LLMFunc,
    desc: str,
    patch_diff: str,
    vuln_blocks: List[CodeBlock],
    fix_blocks: List[CodeBlock],
) -> PatternPair:
    """
    使用“打标签文本”而不是 JSON，让解析更稳：
    LLM 输出形如：

    [VULN_CAUSE]
    ...
    [VULN_CTRLFLOW]
    ...
    [VULN_DATAFLOW]
    ...
    [POSITIVE_TESTS]
    - case1
    - case2
    [FIX_DESC]
    ...
    [FIX_CTRLFLOW]
    ...
    [FIX_DATAFLOW]
    ...
    [NEGATIVE_TESTS]
    - caseA
    - caseB
    """

    import re

    def _blocks_to_str(blocks: List[CodeBlock]) -> str:
        parts = []
        for b in blocks[:20]:
            snippet = "\n".join(b.content.splitlines()[:50])
            parts.append(f"=== {b.file_path}:{b.start_line}-{b.end_line} ===\n{snippet}")
        return "\n\n".join(parts)

    vuln_code_str = _blocks_to_str(vuln_blocks)
    fix_code_str = _blocks_to_str(fix_blocks)

    template = """
You are an expert vulnerability analyst.

We provide you with:
- Official vulnerability description (Dv)
- Patch diff (Pv)
- Vulnerable version code blocks Bv
- Fixed version code blocks Bv_fix

Your task is to reconstruct *two* semantic patterns.

Please output in the following tagged format exactly:

[VULN_CAUSE]
(one paragraph describing the root cause of the vulnerability)

[VULN_CTRLFLOW]
(one paragraph describing the control-flow conditions that trigger the vulnerability)

[VULN_DATAFLOW]
(one paragraph describing the data-flow conditions that trigger the vulnerability)

[POSITIVE_TESTS]
- one example test input that would reproduce the vulnerability
- search in patch (if possible)

[FIX_DESC]
(one paragraph describing how the fix eliminates or constrains the vulnerability)

[FIX_CTRLFLOW]
(one paragraph describing the control-flow constraints enforced by the fix)

[FIX_DATAFLOW]
(one paragraph describing the data-flow constraints enforced by the fix)

[NEGATIVE_TESTS]
- one example test input that demonstrates the vulnerability is gone
- search in patch (if possible)

Important:
- Use exactly these tags in uppercase square brackets.
- Do NOT add extra tags.
- Do NOT wrap the answer in JSON or markdown code fences.
- Plain text only.

Dv:
{desc}

Pv:
{patch_diff}

Vulnerable code blocks (Bv):
{vuln_code_str}

Fixed code blocks (Bv_fix):
{fix_code_str}
""".strip()

    prompt = template.format(
        desc=desc,
        patch_diff=patch_diff,
        vuln_code_str=vuln_code_str,
        fix_code_str=fix_code_str,
    )

    raw = llm(prompt)

    def extract_tag(tag: str) -> str:
        # 匹配 [TAG] 到下一个 [XXX] 或文本结束
        pattern = rf"\[{tag}\](.*?)(?=\[[A-Z_]+\]|\Z)"
        m = re.search(pattern, raw, re.S)
        return m.group(1).strip() if m else ""

    vuln_cause = extract_tag("VULN_CAUSE")
    vuln_ctrl = extract_tag("VULN_CTRLFLOW")
    vuln_data = extract_tag("VULN_DATAFLOW")
    pos_tests_block = extract_tag("POSITIVE_TESTS")
    fix_desc = extract_tag("FIX_DESC")
    fix_ctrl = extract_tag("FIX_CTRLFLOW")
    fix_data = extract_tag("FIX_DATAFLOW")
    neg_tests_block = extract_tag("NEGATIVE_TESTS")

    def split_bullets(block: str) -> List[str]:
        lines = []
        for line in block.splitlines():
            line = line.strip()
            if not line:
                continue
            # 去掉开头的 -, • 等
            line = line.lstrip("-• \t")
            if line:
                lines.append(line)
        return lines

    pos_tests = split_bullets(pos_tests_block)
    neg_tests = split_bullets(neg_tests_block)

    # key_blocks：先直接用 Bv/Bvfix 的前几个 span 代表关键片段
    vuln_key_spans = [b.span() for b in vuln_blocks[:3]]
    fix_key_spans = [b.span() for b in fix_blocks[:3]]

    vp = VulnPattern(
        key_blocks=vuln_key_spans,
        cause_desc=vuln_cause or "N/A",
        ctrlflow_cond=vuln_ctrl or "N/A",
        dataflow_cond=vuln_data or "N/A",
        positive_tests=pos_tests or [],
    )
    sp = SafePattern(
        key_blocks=fix_key_spans,
        fix_desc=fix_desc or "N/A",
        ctrlflow_fix=fix_ctrl or "N/A",
        dataflow_fix=fix_data or "N/A",
        negative_tests=neg_tests or [],
    )

    return PatternPair(vuln_pattern=vp, safe_pattern=sp)




def reconstruct_semantic_structures(
    vuln: VulnKnowledge,
    llm: LLMFunc,
    cfg: SemanticReconstructionConfig = SemanticReconstructionConfig(),
) -> SemanticReconstructionOutput:
    Bv0, Bvfix0 = locate_patch_blocks(vuln)

    builder_v = get_builder_for_language(cfg.language_hint)
    Gv = builder_v.build(vuln.vuln_proj_root, cfg.language_hint)
    node_to_block_v = builder_v.get_node_to_block()

    builder_fix = get_builder_for_language(cfg.language_hint)
    Gvfix = builder_fix.build(vuln.fix_proj_root, cfg.language_hint)
    node_to_block_fix = builder_fix.get_node_to_block()

    Bv_ctx = build_context_blocks(Bv0, Gv, node_to_block_v)
    Bvfix_ctx = build_context_blocks(Bvfix0, Gvfix, node_to_block_fix)

    scores_v = hits_scores(Gv)
    scores_fix = hits_scores(Gvfix)
    Bv_hits = select_hits_blocks(Gv, scores_v, cfg.hits_top_k, node_to_block_v)
    Bvfix_hits = select_hits_blocks(Gvfix, scores_fix, cfg.hits_top_k, node_to_block_fix)

    Bv_llm = llm_expand_blocks(llm, Bv0, vuln.desc, vuln.patch_diff, vuln.vuln_proj_root, role="vuln")
    Bvfix_llm = llm_expand_blocks(llm, Bvfix0, vuln.desc, vuln.patch_diff, vuln.fix_proj_root, role="fix")

    def _merge_blocks(*lists: List[CodeBlock]) -> List[CodeBlock]:
        merged: Dict[str, CodeBlock] = {}
        for lst in lists:
            for b in lst:
                merged[b.id] = b
        return list(merged.values())

    Bv = _merge_blocks(Bv0, Bv_ctx, Bv_hits, Bv_llm)
    Bvfix = _merge_blocks(Bvfix0, Bvfix_ctx, Bvfix_hits, Bvfix_llm)

    patterns = llm_extract_patterns(llm, vuln.desc, vuln.patch_diff, Bv, Bvfix)
    return SemanticReconstructionOutput(
        patterns=patterns,
        vuln_blocks=Bv,
        fix_blocks=Bvfix,
    )
