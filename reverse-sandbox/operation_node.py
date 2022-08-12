import reduced_graph
import non_terminal_node
import terminal_node

import logging.config
import struct
import sys

logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)


class OperationNode():
    """A rule item in the binary sandbox profile

    It may either be a teminal node (end node) or a non-terminal node
    (intermediary node). Each node type uses another class, as defined
    above.
    """

    OPERATION_NODE_TYPE_NON_TERMINAL = 0x00
    OPERATION_NODE_TYPE_TERMINAL = 0x01
    offset = None
    raw = []
    type = None
    terminal = None
    non_terminal = None

    def __init__(self, offset):
        self.offset = offset

    def is_terminal(self):
        return self.type == self.OPERATION_NODE_TYPE_TERMINAL

    def is_non_terminal(self):
        return self.type == self.OPERATION_NODE_TYPE_NON_TERMINAL

    def parse_terminal(self, ios_major_version):
        self.terminal = terminal_node.TerminalNode()
        self.terminal.parent = self
        self.terminal.type = \
            self.raw[2 if ios_major_version < 12 else 1] & 0x01
        self.terminal.flags = \
            self.raw[2 if ios_major_version < 12 else 1] & 0xfe

    def parse_non_terminal(self):
        self.non_terminal = non_terminal_node.NonTerminalNode()
        self.non_terminal.parent = self
        self.non_terminal.filter_id = self.raw[1]
        self.non_terminal.argument_id = self.raw[2] + (self.raw[3] << 8)
        self.non_terminal.match_offset = self.raw[4] + (self.raw[5] << 8)
        self.non_terminal.unmatch_offset = self.raw[6] + (self.raw[7] << 8)

    def parse_raw(self, ios_major_version):
        self.type = self.raw[0]
        if self.is_terminal():
            self.parse_terminal(ios_major_version)
        elif self.is_non_terminal():
            self.parse_non_terminal()

    def convert_filter(self, convert_fn, f, regex_list, ios_major_version,
                       keep_builtin_filters, global_vars, base_addr):
        if self.is_non_terminal():
            self.non_terminal.convert_filter(convert_fn, f, regex_list,
                                             ios_major_version, keep_builtin_filters, global_vars, base_addr)

    def str_debug(self):
        ret = "(%02x) " % (self.offset)
        if self.is_terminal():
            ret += "terminal: "
            ret += str(self.terminal)
        if self.is_non_terminal():
            ret += "non-terminal: "
            ret += str(self.non_terminal)
        return ret

    def __str__(self):
        ret = ""
        if self.is_terminal():
            ret += str(self.terminal)
        if self.is_non_terminal():
            ret += str(self.non_terminal)
        return ret

    def str_not(self):
        ret = ""
        if self.is_terminal():
            ret += str(self.terminal)
        if self.is_non_terminal():
            ret += self.non_terminal.str_not()
        return ret

    def values(self):
        if self.is_terminal():
            return (None, None)
        else:
            return self.non_terminal.values()

    def __eq__(self, other):
        return self.raw == other.raw

    def __hash__(self):
        return struct.unpack('<I', ''.join([chr(v) for v in self.raw[:4]]))[0]


# Operation nodes processed so far.
processed_nodes = []

# Number of regular expressions.
num_regex = 0

# Operation nodes offset.
operations_offset = 0


def has_been_processed(node):
    global processed_nodes
    return node in processed_nodes


def build_operation_node(raw, offset, ios_major_version):
    global operations_offset
    node = OperationNode((offset - operations_offset) / 8)  # why offset / 8 ?
    node.raw = raw
    node.parse_raw(ios_major_version)
    return node


def build_operation_nodes(f, num_operation_nodes, ios_major_version):
    global operations_offset
    operation_nodes = []

    if ios_major_version <= 12:
        operations_offset = 0
    else:
        operations_offset = f.tell()
    for i in range(num_operation_nodes):
        offset = f.tell()
        raw = struct.unpack("<8B", f.read(8))
        operation_nodes.append(build_operation_node(raw, offset,
                                                    ios_major_version))

    # Fill match and unmatch fields for each node in operation_nodes.
    for i in range(len(operation_nodes)):
        if operation_nodes[i].is_non_terminal():
            for j in range(len(operation_nodes)):
                if operation_nodes[i].non_terminal.match_offset == operation_nodes[j].offset:
                    operation_nodes[i].non_terminal.match = operation_nodes[j]
                if operation_nodes[i].non_terminal.unmatch_offset == operation_nodes[j].offset:
                    operation_nodes[i].non_terminal.unmatch = operation_nodes[j]

    return operation_nodes


def find_operation_node_by_offset(operation_nodes, offset):
    for node in operation_nodes:
        if node.offset == offset:
            return node
    return None


def ong_mark_not(g, node, parent_node, nodes_to_process):
    g[node]["not"] = True
    tmp = node.non_terminal.match
    node.non_terminal.match = node.non_terminal.unmatch
    node.non_terminal.unmatch = tmp
    tmp_offset = node.non_terminal.match_offset
    node.non_terminal.match_offset = node.non_terminal.unmatch_offset
    node.non_terminal.unmatch_offset = tmp_offset


def ong_end_path(g, node, parent_node, nodes_to_process):
    g[node]["decision"] = str(node.non_terminal.match.terminal)
    g[node]["type"].add("final")


def ong_add_to_path(g, node, parent_node, nodes_to_process):
    if not has_been_processed(node.non_terminal.match):
        g[node]["list"].add(node.non_terminal.match)
        nodes_to_process.add((node, node.non_terminal.match))


def ong_add_to_parent_path(g, node, parent_node, nodes_to_process):
    if not has_been_processed(node.non_terminal.unmatch):
        if parent_node:
            g[parent_node]["list"].add(node.non_terminal.unmatch)
        nodes_to_process.add((parent_node, node.non_terminal.unmatch))


def build_operation_node_graph(node, default_node):
    if node.is_terminal():
        return None

    if default_node.is_non_terminal():
        return None

    # If node is non-terminal and has already been processed, then it's a jump rule to a previous operation.
    if has_been_processed(node):
        return None

    # Create operation node graph.
    g = {}
    nodes_to_process = set()
    nodes_to_process.add((None, node))
    while nodes_to_process:
        (parent_node, current_node) = nodes_to_process.pop()
        if not current_node in g.keys():
            g[current_node] = {"list": set(), "decision": None,
                               "type": set(["normal"]), "reduce": None, "not": False}
        if not parent_node:
            g[current_node]["type"].add("start")

        if default_node.terminal.is_deny():
            # In case of non-terminal match and deny as unmatch, add match to path.
            if current_node.non_terminal.is_non_terminal_deny():
                ong_add_to_path(g, current_node, parent_node, nodes_to_process)
            # In case of non-terminal match and allow as unmatch, do a not (reverse), end match path and add unmatch to parent path.
            elif current_node.non_terminal.is_non_terminal_allow():
                ong_mark_not(g, current_node, parent_node, nodes_to_process)
                ong_end_path(g, current_node, parent_node, nodes_to_process)
                ong_add_to_parent_path(g, current_node, parent_node, nodes_to_process)
            # In case of non-terminals, add match to path and unmatch to parent path.
            elif current_node.non_terminal.is_non_terminal_non_terminal():
                ong_add_to_path(g, current_node, parent_node, nodes_to_process)
                ong_add_to_parent_path(g, current_node, parent_node, nodes_to_process)
            # In case of allow as match and non-terminal unmatch, end path and add unmatch to parent path.
            elif current_node.non_terminal.is_allow_non_terminal():
                ong_end_path(g, current_node, parent_node, nodes_to_process)
                ong_add_to_parent_path(g, current_node, parent_node, nodes_to_process)
            # In case of deny as match and non-terminal unmatch, do a not (reverse), and add match to path.
            elif current_node.non_terminal.is_deny_non_terminal():
                ong_mark_not(g, current_node, parent_node, nodes_to_process)
                ong_add_to_path(g, current_node, parent_node, nodes_to_process)
            # In case of deny as match and allow as unmatch, do a not (reverse), and end match path (completely).
            elif current_node.non_terminal.is_deny_allow():
                ong_mark_not(g, current_node, parent_node, nodes_to_process)
                ong_end_path(g, current_node, parent_node, nodes_to_process)
            # In case of allow as match and deny as unmatch, end match path (completely).
            elif current_node.non_terminal.is_allow_deny():
                ong_end_path(g, current_node, parent_node, nodes_to_process)
        elif default_node.terminal.is_allow():
            # In case of non-terminal match and deny as unmatch, do a not (reverse), end match path and add unmatch to parent path.
            if current_node.non_terminal.is_non_terminal_deny():
                ong_mark_not(g, current_node, parent_node, nodes_to_process)
                ong_end_path(g, current_node, parent_node, nodes_to_process)
                ong_add_to_parent_path(g, current_node, parent_node, nodes_to_process)
            # In case of non-terminal match and allow as unmatch, add match to path.
            elif current_node.non_terminal.is_non_terminal_allow():
                ong_add_to_path(g, current_node, parent_node, nodes_to_process)
            # In case of non-terminals, add match to path and unmatch to parent path.
            elif current_node.non_terminal.is_non_terminal_non_terminal():
                ong_add_to_path(g, current_node, parent_node, nodes_to_process)
                ong_add_to_parent_path(g, current_node, parent_node, nodes_to_process)
            # In case of allow as match and non-terminal unmatch, do a not (reverse), and add match to path.
            elif current_node.non_terminal.is_allow_non_terminal():
                ong_mark_not(g, current_node, parent_node, nodes_to_process)
                ong_add_to_path(g, current_node, parent_node, nodes_to_process)
            # In case of deny as match and non-terminal unmatch, end path and add unmatch to parent path.
            elif current_node.non_terminal.is_deny_non_terminal():
                ong_end_path(g, current_node, parent_node, nodes_to_process)
                ong_add_to_parent_path(g, current_node, parent_node, nodes_to_process)
            # In case of deny as match and allow as unmatch, end match path (completely).
            elif current_node.non_terminal.is_deny_allow():
                ong_end_path(g, current_node, parent_node, nodes_to_process)
            # In case of allow as match and deny as unmatch, do a not (reverse), and end match path (completely).
            elif current_node.non_terminal.is_allow_deny():
                ong_mark_not(g, current_node, parent_node, nodes_to_process)
                ong_end_path(g, current_node, parent_node, nodes_to_process)

    processed_nodes.append(node)
    print_operation_node_graph(g)
    g = clean_edges_in_operation_node_graph(g)
    while True:
        (g, more) = clean_nodes_in_operation_node_graph(g)
        if more == False:
            break
    logger.debug("*** after cleaning nodes:")
    print_operation_node_graph(g)

    return g


def print_operation_node_graph(g):
    if not g:
        return
    message = ""
    for node_iter in g.keys():
        message += "0x%x (%s) (%s) (decision: %s): [ " % (
        node_iter.offset, str(node_iter), g[node_iter]["type"], g[node_iter]["decision"])
        for edge in g[node_iter]["list"]:
            message += "0x%x (%s) " % (edge.offset, str(edge))
        message += "]\n"
    logger.debug(message)


def remove_edge_in_operation_node_graph(g, node_start, node_end):
    if node_end in g[node_start]["list"]:
        g[node_start]["list"].remove(node_end)
    return g


def remove_node_in_operation_node_graph(g, node_to_remove):
    for n in g[node_to_remove]["list"]:
        g = remove_edge_in_operation_node_graph(g, node_to_remove, n)
    node_list = list(g.keys())
    for n in node_list:
        if node_to_remove in g[n]["list"]:
            g = remove_edge_in_operation_node_graph(g, n, node_to_remove)
    del g[node_to_remove]
    return g


paths = []
current_path = []


def _get_operation_node_graph_paths(g, node):
    global paths, current_path
    logger.debug("getting path for " + node.str_debug())
    current_path.append(node)
    debug_message = "current_path: [ "
    for n in current_path:
        debug_message += n.str_debug() + ", "
    debug_message += "]"
    logger.debug(debug_message)
    if "final" in g[node]["type"]:
        copy_path = list(current_path)
        paths.append(copy_path)
    else:
        for next_node in g[node]["list"]:
            _get_operation_node_graph_paths(g, next_node)
    current_path.pop()


def get_operation_node_graph_paths(g, start_node):
    global paths, current_path
    paths = []
    current_path = []
    _get_operation_node_graph_paths(g, start_node)
    return paths


nodes_traversed_for_removal = []


def _remove_duplicate_node_edges(g, node, start_list):
    global nodes_traversed_for_removal
    nodes_traversed_for_removal.append(node)

    nexts = list(g[node]["list"])
    for n in nexts:
        if n in start_list:
            g = remove_edge_in_operation_node_graph(g, node, n)
        else:
            if not n in nodes_traversed_for_removal:
                _remove_duplicate_node_edges(g, n, start_list)


def remove_duplicate_node_edges(g, start_list):
    for n in start_list:
        logger.debug("removing from node: " + n.str_debug())
        _remove_duplicate_node_edges(g, n, start_list)


def clean_edges_in_operation_node_graph(g):
    """From the initial graph remove edges that are redundant.
    """
    global nodes_traversed_for_removal
    start_nodes = []
    final_nodes = []
    for node_iter in g.keys():
        if "start" in g[node_iter]["type"]:
            start_nodes.append(node_iter)
        if "final" in g[node_iter]["type"]:
            final_nodes.append(node_iter)

    # Remove edges to start nodes.
    for snode in start_nodes:
        for node_iter in g.keys():
            g = remove_edge_in_operation_node_graph(g, node_iter, snode)

    for snode in start_nodes:
        nodes_bag = [snode]
        while True:
            node = nodes_bag.pop()
            nodes_traversed_for_removal = []
            logger.debug("%%% going through " + node.str_debug())
            remove_duplicate_node_edges(g, g[node]["list"])
            nodes_bag.extend(g[node]["list"])
            if not nodes_bag:
                break

    # Traverse graph and built all paths. If end node and start node of
    # two or more paths are similar, remove edges.
    for snode in start_nodes:
        logger.debug("traversing node " + str(snode))
        paths = get_operation_node_graph_paths(g, snode)
        debug_message = "for start node " + str(snode) + str(" paths are")
        for p in paths:
            debug_message += "[ "
            for n in p:
                debug_message += n.str_debug() + " "
            debug_message += "]\n"
        logger.debug(debug_message)

        for i in range(0, len(paths)):
            for j in range(i + 1, len(paths)):
                # Step over equal length paths.
                if len(paths[i]) == len(paths[j]):
                    continue
                elif len(paths[i]) < len(paths[j]):
                    p = paths[i]
                    q = paths[j]
                else:
                    p = paths[j]
                    q = paths[i]
                # If similar final nodes, remove edge.
                debug_message = ""
                debug_message += "short path: ["
                for n in p:
                    debug_message += str(n)
                debug_message += "]\n"
                debug_message += "long path: ["
                for n in q:
                    debug_message += str(n)
                debug_message += "]"
                if p[len(p) - 1] == q[len(q) - 1]:
                    for k in range(0, len(p)):
                        if p[len(p) - 1 - k] == q[len(q) - 1 - k]:
                            continue
                        else:
                            g = remove_edge_in_operation_node_graph(g, q[len(q) - 1 - k], q[len(q) - k])
                            break

    return g


def clean_nodes_in_operation_node_graph(g):
    made_change = False
    node_list = list(g.keys())
    for node_iter in node_list:
        if "final" in g[node_iter]["type"]:
            continue
        if g[node_iter]["list"]:
            continue
        logger.warning("going to remove" + str(node_iter))
        made_change = True
        g = remove_node_in_operation_node_graph(g, node_iter)
    return (g, made_change)


replace_occurred = False


def main():
    if len(sys.argv) != 4:
        print >> sys.stderr, "Usage: %s binary_sandbox_file operations_file ios_version" % (sys.argv[0])
        sys.exit(-1)

    ios_major_version = int(sys.argv[3].split('.')[0])
    # Read sandbox operations.
    sb_ops = [l.strip() for l in open(sys.argv[2])]
    num_sb_ops = len(sb_ops)
    logger.info("num_sb_ops:", num_sb_ops)

    f = open(sys.argv[1], "rb")
    operation_nodes = build_operation_nodes(f, num_sb_ops, ios_major_version)

    global num_regex
    f.seek(4)
    num_regex = struct.unpack("<H", f.read(2))[0]
    logger.debug("num_regex: %02x" % (num_regex))
    f.seek(6)
    sb_ops_offsets = struct.unpack("<%dH" % (num_sb_ops), f.read(2 * num_sb_ops))

    # Extract node for 'default' operation (index 0).
    default_node = find_operation_node_by_offset(operation_nodes, sb_ops_offsets[0])
    print
    "(%s default)" % (default_node.terminal)

    # For each operation expand operation node.
    # for idx in range(1, len(sb_ops_offsets)):
    for idx in range(10, 11):
        offset = sb_ops_offsets[idx]
        operation = sb_ops[idx]
        node = find_operation_node_by_offset(operation_nodes, offset)
        if not node:
            logger.info("operation %s (index %d) has no operation node", operation, idx)
            continue
        logger.debug("expanding operation %s (index %d, offset: %02x)", operation, idx, offset)
        g = build_operation_node_graph(node, default_node)
        logger.debug("reducing operation %s (index %d, offset: %02x)", operation, idx, offset)
        print_operation_node_graph(g)
        if g:
            rg = reduced_graph.reduce_operation_node_graph(g)
            rg.print_vertices_with_operation(operation)
        else:
            if node.terminal:
                if node.terminal.type != default_node.terminal.type:
                    print
                    "(%s %s)" % (node.terminal, operation)


if __name__ == "__main__":
    sys.exit(main())
