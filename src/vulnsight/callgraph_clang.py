from __future__ import annotations
import os
import warnings
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
        self.compile_args = compile_args
        self._language_hint = ""
        self._blocks: List[CodeBlock] = []
        self._node_to_block: Dict[str, CodeBlock] = {}

    def build(self, project_root: str, language_hint: str = "") -> CallGraph:
        self._blocks = []
        self._node_to_block = {}
        self._language_hint = (language_hint or "").lower()

        if ci is None:
            warnings.warn(
                "clang Python bindings are unavailable; returning an empty C/C++ call graph.",
                RuntimeWarning,
            )
            return CallGraph(nodes=[], edges=[])

        try:
            index = ci.Index.create()
        except Exception as exc:
            warnings.warn(
                f"libclang could not be initialized; returning an empty C/C++ call graph: {exc}",
                RuntimeWarning,
            )
            return CallGraph(nodes=[], edges=[])

        c_files: List[str] = []
        for r, _, files in os.walk(project_root):
            for f in files:
                suffix = os.path.splitext(f)[1].lower()
                if suffix in (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"):
                    c_files.append(os.path.join(r, f))

        nodes: Set[str] = set()
        edges: List[Tuple[str, str]] = []

        for path in c_files:
            try:
                compile_args = self._compile_args_for_file(
                    path,
                    project_root,
                    language_hint,
                )
                tu = index.parse(os.path.abspath(path), args=compile_args)
            except Exception as exc:
                warnings.warn(
                    f"libclang failed to parse {path}: {exc}",
                    RuntimeWarning,
                )
                continue

            errors = [
                str(diagnostic)
                for diagnostic in tu.diagnostics
                if diagnostic.severity >= ci.Diagnostic.Error
            ]
            if errors:
                warnings.warn(
                    f"libclang parsed {path} with errors: {'; '.join(errors)}",
                    RuntimeWarning,
                )
            self._visit_translation_unit(tu, path, nodes, edges)

        return CallGraph(nodes=list(nodes), edges=edges)

    def get_blocks(self) -> List[CodeBlock]:
        return self._blocks

    def get_node_to_block(self) -> Dict[str, CodeBlock]:
        return self._node_to_block

    # internal helpers
    def _compile_args_for_file(
        self,
        file_path: str,
        project_root: str,
        language_hint: str,
    ) -> List[str]:
        if self.compile_args is not None:
            return list(self.compile_args)

        suffix = os.path.splitext(file_path)[1].lower()
        lang = (language_hint or "").lower()
        is_c = suffix == ".c" or (suffix == ".h" and lang in ("c",))
        if is_c:
            args = ["-x", "c", "-std=c11"]
        else:
            args = ["-x", "c++", "-std=c++17"]
        args.append(f"-I{os.path.abspath(project_root)}")
        return args

    def _language_for_file(self, file_path: str) -> str:
        suffix = os.path.splitext(file_path)[1].lower()
        is_c = suffix == ".c" or (suffix == ".h" and self._language_hint in ("c",))
        return "c" if is_c else "c++"

    def _func_node_id(self, file_path: str, cursor: Cursor) -> str:
        usr = cursor.get_usr()
        if usr:
            return usr
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
            language=self._language_for_file(file_path),
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
        if self._is_func_like(cursor) and cursor.is_definition():
            block = self._make_func_block(file_path, cursor)
            node_id = block.id
            nodes.add(node_id)
            self._blocks.append(block)
            self._node_to_block[node_id] = block
            new_current = node_id

        if new_current is not None and CursorKind is not None and cursor.kind == CursorKind.CALL_EXPR:
            referenced = cursor.referenced
            if referenced is not None:
                referenced_file = referenced.location.file
                callee_file = referenced_file.name if referenced_file is not None else file_path
                callee_id = self._func_node_id(callee_file, referenced)
                nodes.add(callee_id)
                edge = (new_current, callee_id)
                if edge not in edges:
                    edges.append(edge)

        for child in cursor.get_children():
            self._visit_cursor(child, file_path, nodes, edges, new_current)
