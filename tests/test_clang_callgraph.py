import os
import sys
import tempfile
import unittest


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_ROOT = os.path.join(PROJECT_ROOT, "src")
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)

from vulnsight.callgraph_clang import ClangCallGraphBuilder, ci


class ClangCompileArgumentTests(unittest.TestCase):
    def test_c_files_use_c11(self):
        builder = ClangCallGraphBuilder()

        args = builder._compile_args_for_file("sample.c", PROJECT_ROOT, "c")

        self.assertEqual(["-x", "c", "-std=c11"], args[:3])

    def test_cpp_files_use_cpp17(self):
        builder = ClangCallGraphBuilder()

        args = builder._compile_args_for_file("sample.cpp", PROJECT_ROOT, "cpp")

        self.assertEqual(["-x", "c++", "-std=c++17"], args[:3])


class ClangCallGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if ci is None:
            raise unittest.SkipTest("clang Python bindings are unavailable")
        try:
            ci.Index.create()
        except Exception as exc:
            raise unittest.SkipTest(f"libclang is unavailable: {exc}")

    def test_c_functions_and_cross_file_call_are_extracted(self):
        with tempfile.TemporaryDirectory() as project_root:
            self._write(
                project_root,
                "sample.h",
                "int helper(int value);\n",
            )
            self._write(
                project_root,
                "helper.c",
                '#include "sample.h"\n'
                "int helper(int value) {\n"
                "    return value + 1;\n"
                "}\n",
            )
            self._write(
                project_root,
                "caller.c",
                '#include "sample.h"\n'
                "int caller(void) {\n"
                "    return helper(41);\n"
                "}\n",
            )

            builder = ClangCallGraphBuilder()
            graph = builder.build(project_root, "c")
            blocks = builder.get_blocks()
            node_to_block = builder.get_node_to_block()

            function_ids = {
                block.metadata.get("func_name"): node_id
                for node_id, block in node_to_block.items()
            }
            self.assertIn("helper", function_ids)
            self.assertIn("caller", function_ids)
            self.assertIn(
                (function_ids["caller"], function_ids["helper"]),
                graph.edges,
            )
            self.assertTrue(all(block.language == "c" for block in blocks))

    def test_cpp_functions_are_marked_as_cpp(self):
        with tempfile.TemporaryDirectory() as project_root:
            self._write(
                project_root,
                "sample.cpp",
                "class Sample {\n"
                "public:\n"
                "    int value() const { return 1; }\n"
                "};\n"
                "int caller() {\n"
                "    Sample sample;\n"
                "    return sample.value();\n"
                "}\n",
            )

            builder = ClangCallGraphBuilder()
            builder.build(project_root, "cpp")
            blocks = builder.get_blocks()

            function_names = {
                block.metadata.get("func_name")
                for block in blocks
            }
            self.assertIn("value", function_names)
            self.assertIn("caller", function_names)
            self.assertTrue(all(block.language == "c++" for block in blocks))

    def _write(self, project_root: str, file_name: str, content: str) -> None:
        with open(
            os.path.join(project_root, file_name),
            "w",
            encoding="utf-8",
        ) as file:
            file.write(content)


if __name__ == "__main__":
    unittest.main()
