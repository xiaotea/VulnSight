from __future__ import annotations
import os
import json
import tempfile
import subprocess
import ast
from typing import List, Dict, Tuple, Optional, Set

from .types import CallGraph, CodeBlock
from .callgraph_builder import CallGraphBuilder

from .tool.Jarvis.external_interface import jarvis_callgraph_gen


class PyCGCallGraphBuilder(CallGraphBuilder):
    """使用 PyCG 构建 Python 调用图，并用 AST 抽取函数块."""

    def __init__(self, max_iter: int = 3) -> None:
        self.max_iter = max_iter
        self._blocks: List[CodeBlock] = []
        self._node_to_block: Dict[str, CodeBlock] = {}
        self._project_root: Optional[str] = None

    def build(self, project_root: str, language_hint: str = "") -> CallGraph:
        lang = (language_hint or "").lower()
        if lang not in ("py", "python"):
            return CallGraph(nodes=[], edges=[])

        self._project_root = os.path.abspath(project_root)

        py_files: List[str] = []
        for r, _, files in os.walk(project_root):
            for f in files:
                if f.endswith(".py"):
                    py_files.append(os.path.join(r, f))
        if not py_files:
            return CallGraph(nodes=[], edges=[])

        cg_nodes, cg_edges = self._build_callgraph_with_pycg(project_root, py_files)
        blocks = self._extract_function_blocks(py_files)
        node_to_block = self._match_nodes_to_blocks(cg_nodes, blocks)

        self._blocks = blocks
        self._node_to_block = node_to_block

        return CallGraph(nodes=list(cg_nodes), edges=cg_edges)

    def get_blocks(self) -> List[CodeBlock]:
        return self._blocks

    def get_node_to_block(self) -> Dict[str, CodeBlock]:
        return self._node_to_block

    # --- PyCG 调用 ---
    def _build_callgraph_with_pycg(   # 你也可以改名成 _build_callgraph_with_jarvis
        self,
        project_root: str,
        py_files: List[str],
    ) -> Tuple[Set[str], List[Tuple[str, str]]]:
        """
        使用 Jarvis 生成 Python 调用图。

        :param project_root: 工程根目录（传给 jarvis_callgraph_gen 的 package 参数）
        :param py_files: 入口文件列表（传给 jarvis_callgraph_gen 的 entry_points）
        :return: (nodes, edges) 其中
                 nodes 是函数/方法节点 ID 集合，
                 edges 是 (caller, callee) 二元组列表。
        """
        # 没有 Python 文件就直接返回空图
        if not py_files:
            return set(), []

        try:
            # jarvis_callgraph_gen 返回类似：
            # { "caller1": ["callee1", "callee2", ...], ... }
            call_graph = jarvis_callgraph_gen(
                entry_points=py_files,
                package=project_root,
                # 其他参数用默认值，如果你之前有自定义，就在这里补
                # moduleEntry=None, precision=True
            )
        except Exception:
            # 分析失败，兜底返回空
            return set(), []

        nodes: Set[str] = set()
        edges: List[Tuple[str, str]] = []

        # call_graph 形如 { caller: [callee1, callee2, ...] }
        for caller, callees in call_graph.items():
            if caller is None:
                continue
            nodes.add(caller)
            for callee in callees or []:
                if not callee:
                    continue
                nodes.add(callee)
                edges.append((caller, callee))

        return nodes, edges

    # --- AST 抽取函数块 ---
    def _extract_function_blocks(self, py_files: List[str]) -> List[CodeBlock]:
        blocks: List[CodeBlock] = []
        for path in py_files:
            module_name = self._module_name_from_path(path)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    src = f.read()
            except OSError:
                continue
            try:
                tree = ast.parse(src, filename=path)
            except SyntaxError:
                continue

            blocks.extend(
                self._extract_blocks_from_ast(tree, file_path=path,
                                              module_name=module_name, source=src)
            )
        return blocks

    def _module_name_from_path(self, file_path: str) -> str:
        assert self._project_root is not None, "project_root must be set before extracting blocks"
        abs_root = self._project_root
        abs_path = os.path.abspath(file_path)
        rel = os.path.relpath(abs_path, abs_root)
        rel = rel.replace(os.path.sep, "/")
        if rel.endswith(".py"):
            rel = rel[:-3]
        if rel.endswith("/__init__"):
            rel = rel[: -len("/__init__")]
        parts = [p for p in rel.split("/") if p not in ("", ".")]
        if not parts:
            return "module"
        return ".".join(parts)

    def _extract_blocks_from_ast(
        self,
        tree: ast.AST,
        file_path: str,
        module_name: str,
        source: str,
    ) -> List[CodeBlock]:
        blocks: List[CodeBlock] = []
        lines = source.splitlines(keepends=True)

        class FuncVisitor(ast.NodeVisitor):
            def __init__(self, outer) -> None:
                self.outer = outer
                self.stack: List[str] = []

            def generic_visit(self, node):
                import ast as _ast
                if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                    self._handle_function(node)
                    return
                elif isinstance(node, _ast.ClassDef):
                    self.stack.append(node.name)
                    super().generic_visit(node)
                    self.stack.pop()
                    return
                super().generic_visit(node)

            def _handle_function(self, node):
                self.stack.append(node.name)
                qualname = ".".join(self.stack)
                start_line = getattr(node, "lineno", 1)
                end_line = getattr(node, "end_lineno", start_line)
                start_idx = max(start_line - 1, 0)
                end_idx = min(end_line, len(lines))
                content = "".join(lines[start_idx:end_idx])
                node_id = f"{module_name}.{qualname}"
                block = CodeBlock(
                    id=node_id,
                    file_path=os.path.abspath(file_path),
                    start_line=start_line,
                    end_line=end_line,
                    content=content,
                    language="python",
                    metadata={
                        "module": module_name,
                        "qualname": qualname,
                        "func_name": node.name,
                        "kind": "function",
                    },
                )
                blocks.append(block)
                super().generic_visit(node)
                self.stack.pop()

        FuncVisitor(self).visit(tree)
        return blocks

    # --- PyCG 节点名对齐到函数块 ---
    def _match_nodes_to_blocks(
        self,
        cg_nodes: Set[str],
        blocks: List[CodeBlock],
    ) -> Dict[str, CodeBlock]:
        node_to_block: Dict[str, CodeBlock] = {}
        if not cg_nodes or not blocks:
            return node_to_block

        qual_full_to_block: Dict[str, CodeBlock] = {}
        func_name_to_blocks: Dict[str, List[CodeBlock]] = {}

        for b in blocks:
            module = b.metadata.get("module") or ""
            qual = b.metadata.get("qualname") or b.metadata.get("func_name") or ""
            full = f"{module}.{qual}" if module and qual else b.id
            qual_full_to_block[full] = b
            func_name = b.metadata.get("func_name")
            if func_name:
                func_name_to_blocks.setdefault(func_name, []).append(b)

        for node in cg_nodes:
            if node in qual_full_to_block:
                node_to_block[node] = qual_full_to_block[node]
                continue
            last = node.split(".")[-1]
            last = last.split(":")[-1]
            cands = func_name_to_blocks.get(last, [])
            if len(cands) == 1:
                node_to_block[node] = cands[0]

        return node_to_block
