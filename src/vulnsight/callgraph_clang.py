from __future__ import annotations
import os
from typing import List, Dict, Set, Tuple, Optional
from .types import CallGraph, CodeBlock
from .callgraph_builder import CallGraphBuilder

try:
    import clang.cindex as ci
    from clang.cindex import Cursor, CursorKind
except Exception:
    ci = None
    Cursor = None
    CursorKind = None


class ClangCallGraphBuilder(CallGraphBuilder):
    """使用 libclang 构建 C/C++ 调用图."""

    def __init__(self, compile_args: Optional[List[str]] = None) -> None:
        self.compile_args = compile_args or ["-std=c++17"]
        self._blocks: List[CodeBlock] = []
        self._node_to_block: Dict[str, CodeBlock] = {}

    def build(self, project_root: str, language_hint: str = "") -> CallGraph:
        if ci is None:
            # 未安装 clang 时返回空图
            return CallGraph(nodes=[], edges=[])

        index = ci.Index.create()

        c_files: List[str] = []
        for r, _, files in os.walk(project_root):
            for f in files:
                if f.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")):
                    c_files.append(os.path.join(r, f))

        nodes: Set[str] = set()
        edges: List[Tuple[str, str]] = []

        for path in c_files:
            try:
                tu = index.parse(path, args=self.compile_args)
            except Exception:
                continue
            self._visit_translation_unit(tu, path, nodes, edges)

        return CallGraph(nodes=list(nodes), edges=edges)

    def get_blocks(self) -> List[CodeBlock]:
        return self._blocks

    def get_node_to_block(self) -> Dict[str, CodeBlock]:
        return self._node_to_block

    # internal helpers
    def _func_node_id(self, file_path: str, cursor: Cursor) -> str:
        abs_path = os.path.abspath(file_path)
        return f"{abs_path}:{cursor.spelling}"

    def _make_func_block(self, file_path: str, cursor: Cursor) -> CodeBlock:
        abs_path = os.path.abspath(file_path)
        start_line = cursor.extent.start.line
        end_line = cursor.extent.end.line
        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            lines = []
        content = "".join(lines[start_line - 1:end_line]) if lines else ""
        node_id = self._func_node_id(file_path, cursor)
        return CodeBlock(
            id=node_id,
            file_path=abs_path,
            start_line=start_line,
            end_line=end_line,
            content=content,
            language="c++",
            metadata={"kind": str(cursor.kind), "func_name": cursor.spelling},
        )

    def _visit_translation_unit(
        self,
        tu,
        file_path: str,
        nodes: Set[str],
        edges: List[Tuple[str, str]],
    ) -> None:
        for child in tu.cursor.get_children():
            self._visit_cursor(child, file_path, nodes, edges, current_func_id=None)

    def _is_func_like(self, cursor: Cursor) -> bool:
        if CursorKind is None:
            return False
        return cursor.kind in (
            CursorKind.FUNCTION_DECL,
            CursorKind.CXX_METHOD,
            CursorKind.CONSTRUCTOR,
            CursorKind.DESTRUCTOR,
        )

    def _visit_cursor(
        self,
        cursor: Cursor,
        file_path: str,
        nodes: Set[str],
        edges: List[Tuple[str, str]],
        current_func_id: Optional[str],
    ) -> None:
        if Cursor is None:
            return

        loc_file = cursor.location.file
        if loc_file is not None and os.path.abspath(loc_file.name) != os.path.abspath(file_path):
            return

        new_current = current_func_id
        if self._is_func_like(cursor):
            block = self._make_func_block(file_path, cursor)
            node_id = block.id
            nodes.add(node_id)
            self._blocks.append(block)
            self._node_to_block[node_id] = block
            new_current = node_id

        if new_current is not None and CursorKind is not None and cursor.kind == CursorKind.CALL_EXPR:
            callee_name = cursor.displayname or cursor.spelling
            if callee_name:
                callee_id = f"{os.path.abspath(file_path)}:{callee_name}"
                nodes.add(callee_id)
                edges.append((new_current, callee_id))

        for child in cursor.get_children():
            self._visit_cursor(child, file_path, nodes, edges, new_current)
