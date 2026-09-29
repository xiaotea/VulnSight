import json

from .formats import Simple
from .jarvis import CallGraphGenerator
from .formats import AsGraph
from .formats import Fasten
from .utils.constants import EXT_DEF


def find_graph_differences(graph1, graph2):
    nodes_g1 = set(graph1.keys())
    nodes_g2 = set(graph2.keys())

    # 找出新增和删除的节点
    nodes_added = nodes_g2 - nodes_g1
    nodes_removed = nodes_g1 - nodes_g2

    # 找出所有节点的集合
    all_nodes = nodes_g1.union(nodes_g2)

    # 找出新增和删除的边
    edges_added = set()
    edges_removed = set()

    for node in all_nodes:
        neighbors_g1 = set(graph1.get(node, []))
        neighbors_g2 = set(graph2.get(node, []))

        new_edges = {(node, neighbor) for neighbor in neighbors_g2 - neighbors_g1}
        removed_edges = {(node, neighbor) for neighbor in neighbors_g1 - neighbors_g2}

        edges_added.update(new_edges)
        edges_removed.update(removed_edges)

    return nodes_added, nodes_removed, edges_added, edges_removed


def remove_interior_call(call_graph):
    quick_dict = {}

    def remove_suffix(node):
        if node in quick_dict:
            return quick_dict[node]

        node_list = node.split('.')
        _index = -1
        for index, value in enumerate(node_list):
            if value.endswith(">") and value.startswith("<"):
                _index = index
                break
        if _index == -1:
            return node
        if _index == 0:
            return None
        else:
            quick_dict[node] = '.'.join(node_list[:_index])
            return '.'.join(node_list[:_index])

    new_call_graph = {}
    for node in call_graph:
        new_node = remove_suffix(node)
        if not new_node:
            continue

        if new_node not in new_call_graph:
            new_call_graph[new_node] = []

        for neighbor in call_graph[node]:
            new_neighbor = remove_suffix(neighbor)
            if not new_neighbor or new_neighbor == new_node:
                continue
            if new_neighbor not in new_call_graph[new_node]:
                new_call_graph[new_node].append(new_neighbor)

    node_set = set(new_call_graph.keys())
    for node in node_set:
        init_node = node + '.__init__'
        if init_node in node_set:
            if init_node not in new_call_graph[node]:
                new_call_graph[node].append(init_node)
            if node in new_call_graph[init_node]:
                new_call_graph[init_node].remove(node)

    return new_call_graph


def jarvis_callgraph_gen(entry_points, package=None, moduleEntry=None, precision=True):
    cg = CallGraphGenerator(entry_points, package, decy=False, precision=precision, moduleEntry=moduleEntry)
    cg.analyze()

    formatter = Simple(cg)
    # complete_ex_edge(cg)
    output = formatter.generate()
    as_formatter = AsGraph(cg).generate()

    for node, edges in output.items():
        if node not in as_formatter:
            if node.startswith('<builtin>'):
                continue
            as_formatter[node] = []
        for edge in edges:
            if edge.startswith('<builtin>'):
                continue
            if edge not in as_formatter[node]:
                as_formatter[node].append(edge)

    return remove_interior_call(as_formatter)
    # return Fasten(cg, None, None, None, None, None).generate()
