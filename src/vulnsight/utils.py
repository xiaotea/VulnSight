# sever/utils.py
import os
from typing import List

def build_file_tree(
    root: str,
    max_entries: int = 200,
    exts: List[str] | None = None,
) -> str:
    """
    生成简化版文件结构树，控制长度避免爆 token。
    exts: 若不为 None，只保留指定后缀的文件。
    """
    lines: list[str] = []
    count = 0
    root = os.path.abspath(root)

    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        indent = "  " * depth

        # 目录行
        if rel == ".":
            lines.append(". /")
        else:
            lines.append(f"{indent}{os.path.basename(dirpath)}/")
        count += 1
        if count >= max_entries:
            lines.append("... (truncated)")
            break

        # 文件行
        for fn in filenames:
            if exts is not None:
                _, ext = os.path.splitext(fn)
                if ext not in exts:
                    continue
            lines.append(f"{indent}  {fn}")
            count += 1
            if count >= max_entries:
                lines.append("... (truncated)")
                break
        if count >= max_entries:
            break

    return "\n".join(lines)


# sever/utils.py (接着上面的文件)
from .types import CodeBlock
from textwrap import shorten
import re

FUNC_RE = re.compile(r"\b(def|function|public|private|static)\s+([A-Za-z0-9_]+)")

def summarize_block_symbolic(b: CodeBlock, max_len: int = 120) -> str:
    """
    从 CodeBlock 中抽一个简短的符号级摘要：
    - 尝试从首行/前几行里提取函数名
    - 再附加一点自然语言描述（首行或注释）
    """
    lines = b.content.splitlines()
    header = lines[0] if lines else ""
    m = FUNC_RE.search("\n".join(lines[:5]))
    func_name = m.group(2) if m else "unknown"

    snippet = shorten(
        " ".join(lines[:3]),
        width=max_len,
        placeholder="...",
    )
    return f"{b.file_path}:{b.start_line}-{b.end_line} :: {func_name} :: {snippet}"
