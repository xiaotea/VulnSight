from __future__ import annotations
from typing import Protocol, List, Dict
from .types import CallGraph, CodeBlock


class CallGraphBuilder(Protocol):
    """调用图构建工具统一接口."""

    def build(self, project_root: str, language_hint: str = "") -> CallGraph:
        ...

    def get_blocks(self) -> List[CodeBlock]:
        ...

    def get_node_to_block(self) -> Dict[str, CodeBlock]:
        ...


class DummyCallGraphBuilder(CallGraphBuilder):
    """默认空实现：不支持语言时使用."""

    def __init__(self) -> None:
        self._blocks: List[CodeBlock] = []
        self._node_to_block: Dict[str, CodeBlock] = {}

    def build(self, project_root: str, language_hint: str = "") -> CallGraph:
        return CallGraph(nodes=[], edges=[])

    def get_blocks(self) -> List[CodeBlock]:
        return self._blocks

    def get_node_to_block(self) -> Dict[str, CodeBlock]:
        return self._node_to_block


def get_builder_for_language(language_hint: str) -> CallGraphBuilder:
    lang = (language_hint or "").lower()
    if lang in ("c", "cpp", "c++"):
        from .callgraph_clang import ClangCallGraphBuilder
        return ClangCallGraphBuilder()
    elif lang in ("py", "python"):
        from .callgraph_pycg import PyCGCallGraphBuilder
        return PyCGCallGraphBuilder()
    elif lang in ("java",):
        from .callgraph_java import JavaCallGraphBuilder
        return JavaCallGraphBuilder()
    else:
        return DummyCallGraphBuilder()


def get_callgraph_builder(language_hint: str) -> CallGraphBuilder:
    """兼容旧接口，内部直接调用 get_builder_for_language。"""
    return get_builder_for_language(language_hint)