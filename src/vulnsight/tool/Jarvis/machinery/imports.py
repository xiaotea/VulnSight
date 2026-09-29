#
# Copyright (c) 2020 Vitalis Salis.
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

import sys
import ast
import os
import importlib
import copy
import pkg_resources
from ..utils import *


def get_custom_loader(ig_obj):
    """
    Closure which returns a custom loader
    that modifies an ImportManager object
    """

    class CustomLoader(importlib.abc.SourceLoader):
        def __init__(self, fullname, path):
            self.fullname = fullname
            self.path = path

            ig_obj.create_edge(self.fullname)
            if not ig_obj.get_node(self.fullname):
                ig_obj.create_node(self.fullname)
                ig_obj.set_filepath(self.fullname, self.path)

        def get_filename(self, fullname):
            return self.path

        def get_data(self, filename):
            return ""

    return CustomLoader


class ImportManager(object):
    def __init__(self, self_deploy_package=None):
        self.import_graph = dict()
        self.current_module = ""
        self.input_file = ""
        self.mod_dir = None
        self.old_path_hooks = None
        self.old_path = None
        self.module_not_found_set = set()
        self.imports_index = {}
        self.self_mod_dict = {}
        self.self_deploy_package = self_deploy_package
        self.self_package = set(self.self_deploy_package.keys())
        self.module_imports = self_deploy_package
        for module_name in self.self_deploy_package:
            self.create_node(module_name)
            self.set_filepath(module_name, self.self_deploy_package[module_name])

    def set_pkg(self, input_pkg):
        self.mod_dir = input_pkg

    def get_mod_dir(self):
        return self.mod_dir

    def get_node(self, name):
        if name in self.import_graph:
            return self.import_graph[name]

    def create_node(self, name):
        if not name or not isinstance(name, str):
            raise ImportManagerError("Invalid node name")

        if self.get_node(name):
            return

        self.import_graph[name] = {"filename": "", "imports": set()}
        return self.import_graph[name]

    def create_edge(self, dest):
        if not dest or not isinstance(dest, str):
            raise ImportManagerError("Invalid node name")

        node = self.get_node(self._get_module_path())
        if not node:
            return
            # raise ImportManagerError("Can't add edge to a non existing node")

        node["imports"].add(dest)

    def _clear_caches(self):
        importlib.invalidate_caches()
        sys.path_importer_cache.clear()

    def _get_module_path(self):
        return self.current_module

    def set_current_mod(self, name, fname):
        self.current_module = name
        self.input_file = os.path.abspath(fname)

    def get_filepath(self, modname):
        if modname in self.import_graph:
            return self.import_graph[modname]["filename"]

    def set_filepath(self, node_name, filename):
        if not filename or not isinstance(filename, str):
            raise ImportManagerError("Invalid node name")

        node = self.get_node(node_name)
        if not node:
            raise ImportManagerError("Node does not exist")

        node["filename"] = os.path.abspath(filename)

    #   todo 得到版本号
    def set_version(self, node_name, version):
        if not version or not isinstance(version, str):
            raise ImportManagerError("Invalid node name")

        node = self.get_node(node_name)
        if not node:
            raise ImportManagerError("Node does not exist")

        node["version"] = os.path.abspath(version)

    def get_imports(self, modname):
        if not modname in self.import_graph:
            return []
        return self.import_graph[modname]["imports"]

    def _is_init_file(self):
        return self.input_file.endswith("__init__.py")

    def _handle_import_level(self, name, level):
        # add a dot for each level
        current_is_init_file = self._is_init_file()

        package = self._get_module_path().split(".")
        mod_path = self.input_file.split(os.sep)
        if level > len(package) + 1:
            raise ImportError("Attempting import beyond top level package")

        return os.sep.join(mod_path[:-level])

    def is_sys_modules(self, mod_name):
        if mod_name in sys.builtin_module_names:
            self.create_edge(mod_name)
            return True
        if mod_name in sys.modules:
            self.create_edge(mod_name)
            return True

    def import_sys_mod(self, mod_name):
        mod = sys.modules[mod_name]
        self.create_edge(mod_name)
        if not hasattr(mod, "__file__") or not mod.__file__:
            return
        self.create_node(mod_name)
        self.module_imports[mod_name] = sys.modules[mod_name].__file__
        self.set_filepath(mod_name, mod.__file__)
        return sys.modules[mod_name]

    def _do_import(self, mod_name, package):
        if mod_name == 'pdb':
            return
        if self.is_sys_modules(mod_name):
            return self.import_sys_mod(self, mod_name)

        module_spec = importlib.util.find_spec(mod_name, package=package)
        if module_spec is None:
            return importlib.import_module(mod_name, package=package)

        return importlib.util.module_from_spec(module_spec)

    def get_version(self, mod_name):
        tmp = pkg_resources.find_distributions(mod_name, True)
        pass

    def handle_import(self, src_name, level, sort_import_name=None):
        # We currently don't support builtin modules because they're frozen.
        # Add an edge and continue.
        # TODO: identify a way to include frozen modules

        # 如果是内部模块，是直接加入
        root = src_name.split(".")[0]
        if level == 0:
            # 判断是否是标准模块
            if self.is_sys_modules(src_name):
                return
            if self.is_sys_modules(root):
                return
            if src_name in self.self_mod_dict:
                return self.self_mod_dict[src_name]

            # 绝对导入的处理
            # 有可能存在项目根目录导入  项目根目录也是绝对导入
            mod_name = None

            for mod_key in self.self_package:
                if len(src_name.split('.')) == 1 and src_name not in mod_key.split('.'):
                    continue
                if mod_key.endswith(src_name):
                    mod_name = mod_key
                    break
            if not mod_name and sort_import_name != src_name:
                for mod_key in self.self_package:
                    if len(sort_import_name.split('.')) == 1 and sort_import_name not in mod_key.split('.'):
                        continue
                    if mod_key.endswith(sort_import_name):
                        mod_name = mod_key
                        break
            if mod_name:
                mod_file = self.self_deploy_package[mod_name]
                if mod_file.endswith("__init__.py"):
                    mod_file = os.path.split(mod_file)[0]

                self.self_mod_dict[src_name] = to_mod_name(os.path.relpath(mod_file, self.mod_dir))
                return self.self_mod_dict[src_name]

        if level > 0:
            deal_mod_dir = self._handle_import_level(src_name, level)
            # 相对导入的处理
            import_mod = deal_mod_dir + os.sep + os.sep.join(src_name.split('.'))
            mod_length, i = len(src_name.split('.')) + level, 0
            import_mod_file = None
            while (not import_mod_file and mod_length - i > 0):
                if i == 0:
                    _import_mod = import_mod
                else:
                    _import_mod = os.sep.join(import_mod.split(os.sep)[:-i])
                i = i + 1

                py_file = _import_mod + '.py'
                init_file = os.path.join(_import_mod, '__init__.py')

                if os.path.exists(py_file):
                    import_mod_file = py_file
                elif os.path.exists(_import_mod) and os.path.exists(init_file):
                    import_mod_file = init_file

            if import_mod_file:
                fname = import_mod_file
                if import_mod_file.endswith("__init__.py"):
                    fname = os.path.split(import_mod_file)[0]
                _import_mod = to_mod_name(os.path.relpath(fname, self.mod_dir))
                self.module_imports[_import_mod] = import_mod_file
                if not self.get_node(_import_mod):
                    self.create_node(_import_mod)
                    self.set_filepath(_import_mod, import_mod_file)
                return _import_mod

        return None

    def get_import_graph(self):
        return self.import_graph

    def install_hooks(self):
        loader = get_custom_loader(self)
        self.old_path_hooks = copy.deepcopy(sys.path_hooks)
        self.old_path = copy.deepcopy(sys.path)
        loader_details = loader, importlib.machinery.all_suffixes()
        sys.path_hooks.insert(0, importlib.machinery.FileFinder.path_hook(loader_details))
        try:
            sys.path.insert(0, os.path.abspath(self.mod_dir))
            sys.path.append(os.path.abspath(self.mod_dir))
        except Exception as e:
            pass
            # print()
        self._clear_caches()

    def remove_hooks(self):
        sys.path_hooks = self.old_path_hooks
        sys.path = self.old_path

        self._clear_caches()


class ImportManagerError(Exception):
    pass
