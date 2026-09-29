import os
import sys
import tempfile
import unittest
from unittest.mock import patch


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_ROOT = os.path.join(PROJECT_ROOT, "src")
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)

from vulnsight.preprocess_target import (
    LSHConfig,
    build_candidate_space,
    expand_context_via_callgraph,
    list_project_files,
)
from vulnsight.types import CallGraph, CodeBlock


class CallGraphExpansionTests(unittest.TestCase):
    def test_project_file_listing_includes_common_cpp_extensions(self):
        with tempfile.TemporaryDirectory() as project_root:
            expected = {"sample.cc", "sample.cxx", "sample.hh", "sample.hxx"}
            for file_name in expected:
                with open(
                    os.path.join(project_root, file_name),
                    "w",
                    encoding="utf-8",
                ):
                    pass

            actual = {
                os.path.basename(file_path)
                for file_path in list_project_files(project_root)
            }

        self.assertTrue(expected.issubset(actual))

    def test_tuple_edges_expand_to_neighbor_blocks(self):
        caller = CodeBlock(
            id="caller",
            file_path=os.path.join(PROJECT_ROOT, "caller.c"),
            start_line=1,
            end_line=3,
            content="void caller(void) {}",
            language="c",
        )
        callee = CodeBlock(
            id="callee",
            file_path=os.path.join(PROJECT_ROOT, "callee.c"),
            start_line=1,
            end_line=3,
            content="void callee(void) {}",
            language="c",
        )
        graph = CallGraph(
            nodes=["caller", "callee"],
            edges=[("caller", "callee")],
        )

        context = expand_context_via_callgraph(
            [caller],
            graph,
            {"caller": caller, "callee": callee},
        )

        self.assertEqual(["callee"], [block.id for block in context])

    def test_c_candidate_space_reuses_clang_function_blocks(self):
        source_path = os.path.join(PROJECT_ROOT, "sample.c")
        config_path = os.path.join(PROJECT_ROOT, "config.txt")
        source_file_block = CodeBlock(
            id="source-file",
            file_path=source_path,
            start_line=1,
            end_line=20,
            content="int helper(void) { return 1; }",
        )
        config_file_block = CodeBlock(
            id="config-file",
            file_path=config_path,
            start_line=1,
            end_line=1,
            content="enabled=true",
        )
        function_block = CodeBlock(
            id="helper",
            file_path=os.path.abspath(source_path),
            start_line=1,
            end_line=1,
            content="int helper(void) { return 1; }",
            language="c",
        )
        builder = _FakeBuilder(function_block)

        with (
            patch(
                "vulnsight.preprocess_target.get_callgraph_builder",
                return_value=builder,
            ),
            patch(
                "vulnsight.preprocess_target.build_blocks_for_project",
                return_value=[source_file_block, config_file_block],
            ),
            patch(
                "vulnsight.preprocess_target.select_shash",
                return_value=[],
            ),
            patch(
                "vulnsight.preprocess_target.llm_expand_target",
                return_value=[],
            ),
        ):
            blocks, candidates, _ = build_candidate_space(
                target_root=PROJECT_ROOT,
                Bvref=[],
                llm=lambda _: "[]",
                lsh_cfg=LSHConfig(),
                language_hint="c",
            )

        self.assertEqual(1, builder.build_count)
        self.assertEqual(
            {"helper", "config-file"},
            {block.id for block in blocks},
        )
        self.assertEqual([], candidates)


class _FakeBuilder:
    def __init__(self, function_block: CodeBlock):
        self.function_block = function_block
        self.build_count = 0

    def build(self, project_root: str, language_hint: str = "") -> CallGraph:
        self.build_count += 1
        return CallGraph(nodes=[self.function_block.id], edges=[])

    def get_blocks(self):
        return [self.function_block]

    def get_node_to_block(self):
        return {self.function_block.id: self.function_block}


if __name__ == "__main__":
    unittest.main()
