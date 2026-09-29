from __future__ import annotations
import os
from typing import List, Dict, Tuple, Set

import javalang

from .types import CallGraph, CallGraphNode, CallGraphEdge, CodeBlock


def list_java_files(root: str) -> List[str]:
    res = []
    for r, _, files in os.walk(root):
        for f in files:
            if f.endswith(".java"):
                res.append(os.path.join(r, f))
    return res


class JavaCallGraphBuilder:
    """
    一个简单的 Java 调用图构建器：
    - 节点：method（用 fully-qualified 名称表示）
    - 边：methodA -> methodB 代表在 A 中调用了 B
    同时提供 node_to_block 映射，用于从调用图扩展到 CodeBlock。
    """

    def __init__(self) -> None:
        # node_id -> CodeBlock
        self.node_to_block: Dict[str, CodeBlock] = {}

    def build(self, project_root: str, language_hint: str = "") -> CallGraph:
        java_files = list_java_files(project_root)
        nodes: Dict[str, CallGraphNode] = {}
        edges: List[CallGraphEdge] = []

        for path in java_files:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()
            except OSError:
                continue
            if path.endswith("DiskFileItem.java"):
                print(f"[DEBUG][JavaCG] Found DiskFileItem.java at {path}")

            try:
                tree = javalang.parse.parse(code)
            except javalang.parser.JavaSyntaxError:
                continue

            package_name = ""
            if tree.package:
                package_name = tree.package.name  # com.example.xxx

            # 找出类 / 接口里的方法定义
            for _, type_decl in tree.filter((javalang.tree.ClassDeclaration, javalang.tree.InterfaceDeclaration)):
                type_name = type_decl.name  # 类名

                for method in type_decl.methods:
                    method_name = method.name
                    fq_name = self._make_fq_method_name(package_name, type_name, method_name)

                    # 估计代码块行号（简单：method.position.line 到 body 最后一行）
                    start_line = method.position.line if method.position else 1
                    end_line = start_line
                    if method.body:
                        # 取 body 中所有语句中行号最大的作为 end_line（很粗略，但够用）
                        lines = [start_line]
                        for stmt in method.body:
                            if hasattr(stmt, "position") and stmt.position:
                                lines.append(stmt.position.line)
                        end_line = max(lines)

                    block = CodeBlock(
                        id=fq_name,
                        file_path=path,
                        start_line=start_line,
                        end_line=end_line,
                        content="\n".join(code.splitlines()[start_line - 1 : end_line]),
                        language="java",
                        metadata={},
                    )
                    self.node_to_block[fq_name] = block

                    if path.endswith("DiskFileItem.java"):
                        print(f"[DEBUG][JavaCG] DiskFileItem method node={fq_name}, "
                              f"lines={start_line}-{end_line}")

                    if fq_name not in nodes:
                        nodes[fq_name] = CallGraphNode(id=fq_name, label=fq_name)

                    # 在方法体里找方法调用
                    for _, inv in method.filter(javalang.tree.MethodInvocation):
                        # 这里只能拿到被调用方法名，没法精确解析目标类，先用“同类内的方法”的近似
                        callee_name = inv.member
                        callee_fq = self._make_fq_method_name(package_name, type_name, callee_name)

                        if callee_fq not in nodes:
                            nodes[callee_fq] = CallGraphNode(id=callee_fq, label=callee_fq)

                        edges.append(CallGraphEdge(src=fq_name, dst=callee_fq))

        return CallGraph(nodes=list(nodes.values()), edges=edges)

    def get_node_to_block(self) -> Dict[str, CodeBlock]:
        return self.node_to_block

    @staticmethod
    def _make_fq_method_name(pkg: str, cls: str, method: str) -> str:
        # 例如 com.example.Foo#bar
        if pkg:
            return f"{pkg}.{cls}#{method}"
        return f"{cls}#{method}"
