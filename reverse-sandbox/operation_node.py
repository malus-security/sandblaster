#!/usr/bin/python3

import sys
import struct
import re
import logging
import logging.config

logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)

class TerminalNode():
    """Allow or Deny end node in binary sandbox format

    A terminal node, when reached, either denies or allows the rule.
    A node has a type (allow or deny) and a set of flags. Flags are
    currently unused.
    """

    TERMINAL_NODE_TYPE_ALLOW = 0x00
    TERMINAL_NODE_TYPE_DENY = 0x01
    type = None
    flags = None

    def __eq__(self, other):
        return self.type == other.type and self.flags == other.flags

    def __str__(self):
        if self.type == self.TERMINAL_NODE_TYPE_ALLOW:
            return "allow"
        elif self.type == self.TERMINAL_NODE_TYPE_DENY:
            return "deny"
        else:
            return "unknown"

    def is_allow(self):
        return self.type == self.TERMINAL_NODE_TYPE_ALLOW

    def is_deny(self):
        return self.type == self.TERMINAL_NODE_TYPE_DENY


class NonTerminalNode():
    """Intermediary node consisting of a filter to match

    The non-terminal node, when matched, points to a new node, and
    when unmatched, to another node.

    A non-terminal node consists of the filter to match, its argument and
    the match and unmatch nodes.
    """

    filter_id = None
    filter = None
    argument_id = None
    argument = None
    match_offset = None
    match = None
    unmatch_offset = None
    unmatch = None

    def __eq__(self, other):
        return self.filter_id == other.filter_id and self.argument_id == other.argument_id and self.match_offset == other.match_offset and self.unmatch_offset == other.unmatch_offset

    def simplify_list(self, arg_list):
        result_list = []
        for a in arg_list:
            if len(a) == 0:
                continue
            tmp_list = list(result_list)
            match_found = False
            for r in tmp_list:
                if len(r) == 0:
                    continue
                if a == r or a+"/" == r or a == r+"/":
                    match_found = True
                    result_list.remove(r)
                    if a[-1] == '/':
                        result_list.append(a + "^^^")
                    else:
                        result_list.append(a + "/^^^")
            if match_found == False:
                result_list.append(a)

        return result_list

    def str_debug(self):
        if self.filter:
            if self.argument:
                if type(self.argument) is list:
                    if len(self.argument) == 1:
                        ret_str = ""
                    else:
                        self.argument = self.simplify_list(self.argument)
                        if len(self.argument) == 1:
                            ret_str = ""
                        else:
                            ret_str = "(require-any "
                    for s in self.argument:
                        curr_filter = self.filter
                        regex_added = False
                        prefix_added = False
                        if len(s) == 0:
                            s = ".+"
                            if not regex_added:
                                regex_added = True
                                if self.filter == "literal":
                                    curr_filter = "regex"
                                else:
                                    curr_filter += "-regex"
                        else:
                            if s[-4:] == "/^^^":
                                curr_filter = "subpath"
                                s = s[:-4]
                            if '\\' in s or '|' in s or ('[' in s and ']' in s) or '+' in s:
                                if curr_filter == "subpath":
                                    s = s + "/?"
                                if self.filter == "literal":
                                    curr_filter = "regex"
                                else:
                                    curr_filter += "-regex"
                                s = s.replace('\\\\.', '[.]')
                                s = s.replace('\\.', '[.]')
                            if "${" in s and "}" in s:
                                if not prefix_added:
                                    prefix_added = True
                                    curr_filter += "-prefix"
                        if "regex" in curr_filter:
                            ret_str += '(%04x, %04x) (%s #"%s")\n' % (self.match_offset, self.unmatch_offset, curr_filter, s)
                        else:
                            ret_str += '(%s "%s")\n' % (curr_filter, s)
                    if len(self.argument) == 1:
                        ret_str = ret_str[:-1]
                    else:
                        ret_str = ret_str[:-1] + ")"
                    return ret_str
                s = self.argument
                curr_filter = self.filter
                if not "regex" in curr_filter:
                    if '\\' in s or '|' in s or ('[' in s and ']' in s) or '+' in s:
                        if self.filter == "literal":
                            curr_filter = "regex"
                        else:
                            curr_filter += "-regex"
                        s = s.replace('\\\\.', '[.]')
                        s = s.replace('\\.', '[.]')
                if "${" in s and "}" in s:
                    if not "prefix" in curr_filter:
                        curr_filter += "-prefix"
                return "(%04x, %04x) (%s %s)" % (self.match_offset, self.unmatch_offset, curr_filter, s)
            else:
                return "(%04x, %04x) (%s)" % (self.match_offset, self.unmatch_offset, self.filter)
        return "(%02x %04x %04x %04x)" % (self.filter_id, self.argument_id, self.match_offset, self.unmatch_offset)

    def __str__(self):
        if self.filter:
            if self.argument:
                if type(self.argument) is list:
                    if len(self.argument) == 1:
                        ret_str = ""
                    else:
                        self.argument = self.simplify_list(self.argument)
                        if len(self.argument) == 1:
                            ret_str = ""
                        else:
                            ret_str = "(require-any "
                    for s in self.argument:
                        curr_filter = self.filter
                        regex_added = False
                        prefix_added = False
                        if len(s) == 0:
                            s = ".+"
                            if not regex_added:
                                regex_added = True
                                if self.filter == "literal":
                                    curr_filter = "regex"
                                else:
                                    curr_filter += "-regex"
                        else:
                            if s[-4:] == "/^^^":
                                curr_filter = "subpath"
                                s = s[:-4]
                            if '\\' in s or '|' in s or ('[' in s and ']' in s) or '+' in s:
                                if curr_filter == "subpath":
                                    s = s + "/?"
                                if self.filter == "literal":
                                    curr_filter = "regex"
                                else:
                                    curr_filter += "-regex"
                                s = s.replace('\\\\.', '[.]')
                                s = s.replace('\\.', '[.]')
                            if "${" in s and "}" in s:
                                if not prefix_added:
                                    prefix_added = True
                                    curr_filter += "-prefix"
                        if "regex" in curr_filter:
                            ret_str += '(%s #"%s")\n' % (curr_filter, s)
                        else:
                            ret_str += '(%s "%s")\n' % (curr_filter, s)
                    if len(self.argument) == 1:
                        ret_str = ret_str[:-1]
                    else:
                        ret_str = ret_str[:-1] + ")"
                    return ret_str
                s = self.argument
                curr_filter = self.filter
                if not "regex" in curr_filter:
                    if '\\' in s or '|' in s or ('[' in s and ']' in s) or '+' in s:
                        if self.filter == "literal":
                            curr_filter = "regex"
                        else:
                            curr_filter += "-regex"
                        s = s.replace('\\\\.', '[.]')
                        s = s.replace('\\.', '[.]')
                if "${" in s and "}" in s:
                    if not "prefix" in curr_filter:
                        curr_filter += "-prefix"
                return "(%s %s)" % (curr_filter, s)
            else:
                return "(%s)" % (self.filter)
        return "(%02x %04x %04x %04x)" % (self.filter_id, self.argument_id, self.match_offset, self.unmatch_offset)

    def str_not(self):
        if self.filter:
            if self.argument:
                if type(self.argument) is list:
                    if len(self.argument) == 1:
                        ret_str = ""
                    else:
                        self.argument = self.simplify_list(self.argument)
                        if len(self.argument) == 1:
                            ret_str = ""
                        else:
                            ret_str = "(require-all "
                    for s in self.argument:
                        curr_filter = self.filter
                        regex_added = False
                        prefix_added = False
                        if len(s) == 0:
                            s = ".+"
                            if not regex_added:
                                regex_added = True
                                if self.filter == "literal":
                                    curr_filter = "regex"
                                else:
                                    curr_filter += "-regex"
                        else:
                            if s[-4:] == "/^^^":
                                curr_filter = "subpath"
                                s = s[:-4]
                            if '\\' in s or '|' in s or ('[' in s and ']' in s) or '+' in s:
                                if curr_filter == "subpath":
                                    s = s + "/?"
                                if self.filter == "literal":
                                    curr_filter = "regex"
                                else:
                                    curr_filter += "-regex"
                                s = s.replace('\\\\.', '[.]')
                                s = s.replace('\\.', '[.]')
                            if "${" in s and "}" in s:
                                if not prefix_added:
                                    prefix_added = True
                                    curr_filter += "-prefix"
                        if "regex" in curr_filter:
                            ret_str += '(require-not (%s #"%s"))\n' % (curr_filter, s)
                        else:
                            ret_str += '(require-not (%s "%s"))\n' % (curr_filter, s)
                    if len(self.argument) == 1:
                        ret_str = ret_str[:-1]
                    else:
                        ret_str = ret_str[:-1] + ")"
                    return ret_str
                s = self.argument
                curr_filter = self.filter
                if not "regex" in curr_filter:
                    if '\\' in s or '|' in s or ('[' in s and ']' in s) or '+' in s:
                        if self.filter == "literal":
                            curr_filter = "regex"
                        else:
                            curr_filter += "-regex"
                        s = s.replace('\\\\.', '[.]')
                        s = s.replace('\\.', '[.]')
                if "${" in s and "}" in s:
                    if not "prefix" in curr_filter:
                        curr_filter += "-prefix"
                return "(%s %s)" % (curr_filter, s)
            else:
                return "(%s)" % (self.filter)
        return "(%02x %04x %04x %04x)" % (self.filter_id, self.argument_id, self.match_offset, self.unmatch_offset)

    def values(self):
        if self.filter:
            return (self.filter, self.argument)
        return ("%02x" % self.filter_id, "%04x" % (self.argument_id))

    def is_entitlement_start(self):
        return self.filter_id == 0x1e or self.filter_id == 0xa0

    def is_entitlement(self):
        return self.filter_id == 0x1e or self.filter_id == 0x1f or self.filter_id == 0x20 or self.filter_id == 0xa0

    def is_last_regular_expression(self):
        return self.filter_id == 0x81 and self.argument_id == num_regex-1

    def convert_filter(self, convert_fn, f, regex_list, ios_major_version,
            keep_builtin_filters, global_vars, base_addr):
        (self.filter, self.argument) = convert_fn(f, ios_major_version,
            keep_builtin_filters, global_vars, regex_list, self.filter_id,
            self.argument_id, base_addr)

    def is_non_terminal_deny(self):
        if self.match.is_non_terminal() and self.unmatch.is_terminal():
            return self.unmatch.terminal.is_deny()

    def is_non_terminal_allow(self):
        if self.match.is_non_terminal() and self.unmatch.is_terminal():
            return self.unmatch.terminal.is_allow()

    def is_non_terminal_non_terminal(self):
        return self.match.is_non_terminal() and self.unmatch.is_non_terminal()

    def is_allow_non_terminal(self):
        if self.match.is_terminal() and self.unmatch.is_non_terminal():
            return self.match.terminal.is_allow()

    def is_deny_non_terminal(self):
        if self.match.is_terminal() and self.unmatch.is_non_terminal():
            return self.match.terminal.is_deny()

    def is_deny_allow(self):
        if self.match.is_terminal() and self.unmatch.is_terminal():
            return self.match.terminal.is_deny() and self.unmatch.terminal.is_allow()

    def is_allow_deny(self):
        if self.match.is_terminal() and self.unmatch.is_terminal():
            return self.match.terminal.is_allow() and self.unmatch.terminal.is_deny()


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
        self.terminal = TerminalNode()
        self.terminal.parent = self
        self.terminal.type = \
            self.raw[2 if ios_major_version <12 else 1] & 0x01
        self.terminal.flags = \
            self.raw[2 if ios_major_version <12 else 1] & 0xfe

    def parse_non_terminal(self):
        self.non_terminal = NonTerminalNode()
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
        ret = "(%02x) " % (int)(self.offset)
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
    node = OperationNode((offset - operations_offset) / 8) # why offset / 8 ?
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
        message += "0x%x (%s) (%s) (decision: %s): [ " % ((int)(node_iter.offset), str(node_iter), g[node_iter]["type"], g[node_iter]["decision"])
        for edge in g[node_iter]["list"]:
            message += "0x%x (%s) " % ((int)(edge.offset), str(edge))
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
        nodes_bag = [ snode ]
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
            for j in range(i+1, len(paths)):
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
                if p[len(p)-1] == q[len(q)-1]:
                    for k in range(0, len(p)):
                        if p[len(p)-1-k] == q[len(q)-1-k]:
                            continue
                        else:
                            g = remove_edge_in_operation_node_graph(g, q[len(q)-1-k], q[len(q)-k])
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
        logger.warn("going to remove" + str(node_iter))
        made_change = True
        g = remove_node_in_operation_node_graph(g, node_iter)
    return (g, made_change)


replace_occurred = False

class ReducedVertice():
    TYPE_SINGLE = "single"
    TYPE_START = "start"
    TYPE_REQUIRE_ANY = "require-any"
    TYPE_REQUIRE_ALL = "require-all"
    TYPE_REQUIRE_ENTITLEMENT = "require-entitlement"
    type = TYPE_SINGLE
    is_not = False
    value = None
    decision = None

    def __init__(self, type=TYPE_SINGLE, value=None, decision=None, is_not=False):
        self.type = type
        self.value = value
        self.decision = decision
        self.is_not = is_not

    def set_value(self, value):
        self.value = value

    def set_type(self, type):
        self.type = type

    def _replace_in_list(self, lst, old, new):
        global replace_occurred
        tmp_list = list(lst)
        for i, v in enumerate(tmp_list):
            if isinstance(v.value, list):
                self._replace_in_list(v.value, old, new)
            else:
                if v == old:
                    lst[i] = new
                    replace_occurred = True
                    return

    def replace_in_list(self, old, new):
        if isinstance(self.value, list):
            self._replace_in_list(self.value, old, new)

    def _replace_sublist_in_list(self, lst, old, new):
        global replace_occurred
        all_found = True
        for v in old:
            if v not in lst:
                all_found = False
                break
        if all_found:
            for v in old:
                lst.remove(v)
            lst.append(new)
            replace_occurred = True
            return

        for i, v in enumerate(lst):
            if isinstance(v.value, list):
                self._replace_sublist_in_list(v.value, old, new)
            else:
                return

    def replace_sublist_in_list(self, old, new):
        if isinstance(self.value, list):
            self._replace_sublist_in_list(self.value, old, new)

    def set_decision(self, decision):
        self.decision = decision

    def set_type_single(self):
        self.type = self.TYPE_SINGLE

    def set_type_start(self):
        self.type = self.TYPE_START

    def set_type_require_entitlement(self):
        self.type = self.TYPE_REQUIRE_ENTITLEMENT

    def set_type_require_any(self):
        self.type = self.TYPE_REQUIRE_ANY

    def set_type_require_all(self):
        self.type = self.TYPE_REQUIRE_ALL

    def set_integrated_vertice(self, integrated_vertice):
        (n, i) = self.value
        self.value = (n, integrated_vertice)

    def is_type_single(self):
        return self.type == self.TYPE_SINGLE

    def is_type_start(self):
        return self.type == self.TYPE_START

    def is_type_require_entitlement(self):
        return self.type == self.TYPE_REQUIRE_ENTITLEMENT

    def is_type_require_all(self):
        return self.type == self.TYPE_REQUIRE_ALL

    def is_type_require_any(self):
        return self.type == self.TYPE_REQUIRE_ANY

    def recursive_str(self, level, recursive_is_not):
        result_str = ""
        if self.is_type_single():
            if self.is_not and not recursive_is_not:
                value = str(self.value)
                if "(require-any" in value:
                    result_str = self.value.str_not()
                else:
                    result_str += "(require-not " + str(self.value) + ")"
            else:
                result_str += str(self.value)
        elif self.is_type_require_entitlement():
            ent_str = ""
            (n, i) = self.value
            if i == None:
                ent_str += str(n.value)
            else:
                ent_str += str(n.value)[:-1] + " "
                ent_str += i.recursive_str(level, self.is_not)
                ent_str += ")"
            if self.is_not:
                result_str += "(require-not " + ent_str + ")"
            else:
                result_str += ent_str
        else:
            if level == 1:
                result_str += "\n" + 13*' '
            result_str += "(" + self.type
            level += 1
            for i, v in enumerate(self.value):
                if i == 0:
                    result_str += " " + v.recursive_str(level, recursive_is_not)
                else:
                    result_str += "\n" + 13*level*' ' + v.recursive_str(level, recursive_is_not)
            result_str += ")"
        return result_str

    def recursive_str_debug(self, level, recursive_is_not):
        result_str = ""
        if self.is_type_single():
            if self.is_not and not recursive_is_not:
                result_str += "(require-not " + self.value.str_debug() + ")"
            else:
                result_str += self.value.str_debug()
        elif self.is_type_require_entitlement():
            ent_str = ""
            (n, i) = self.value
            if i == None:
                ent_str += n.value.str_debug()
            else:
                ent_str += n.value.str_debug()[:-1] + " "
                ent_str += i.recursive_str_debug(level, self.is_not)
                ent_str += ")"
            if self.is_not:
                result_str += "(require-not " + ent_str + ")"
            else:
                result_str += ent_str
        else:
            if level == 1:
                result_str += "\n" + 13*' '
            result_str += "(" + self.type
            level += 1
            for i, v in enumerate(self.value):
                if i == 0:
                    result_str += " " + v.recursive_str_debug(level, recursive_is_not)
                else:
                    result_str += "\n" + 13*level*' ' + v.recursive_str_debug(level, recursive_is_not)
            result_str += ")"
        return result_str

    def recursive_xml_str(self, level, recursive_is_not):
        result_str = ""
        if self.is_type_single():
            if self.is_not and not recursive_is_not:
                result_str += level*"\t" + "<require type=\"require-not\">\n"
                (name, argument) = self.value.values()
                if argument == None:
                    result_str += (level+1)*"\t" + "<filter name=\"" + str(name) + "\" />\n"
                else:
                    arg = str(argument).replace('&', '&amp;').replace('"', '&quot;').replace('\'', '&apos;').replace('<', '&lt;').replace('>', '&gt;')
                    result_str += (level+1)*"\t" + "<filter name=\"" + str(name) + "\" argument=\"" + arg + "\" />\n"
                result_str += level*"\t" + "</require>\n"
            else:
                (name, argument) = self.value.values()
                if argument == None:
                    result_str += level*"\t" + "<filter name=\"" + str(name) + "\" />\n"
                else:
                    arg = str(argument).replace('&', '&amp;').replace('"', '&quot;').replace('\'', '&apos;').replace('<', '&lt;').replace('>', '&gt;')
                    result_str += level*"\t" + "<filter name=\"" + str(name) + "\" argument=\"" + arg + "\" />\n"
        elif self.is_type_require_entitlement():
            if self.is_not:
                result_str += level*"\t" + "<require type=\"require-not\">\n"
                level += 1
            result_str += level*"\t" + "<require type=\"require-entitlement\""
            (n, i) = self.value
            if i == None:
                _tmp = str(n.value)[21:-1].replace('&', '&amp;').replace('"', '&quot;').replace('\'', '&apos;').replace('<', '&lt;').replace('>', '&gt;')
                result_str += " value=\"" + _tmp + "\" />\n"
            else:
                _tmp = str(n.value)[21:-1].replace('&', '&amp;').replace('"', '&quot;').replace('\'', '&apos;').replace('<', '&lt;').replace('>', '&gt;')
                result_str += " value=\"" + _tmp + "\">\n"
                result_str += i.recursive_xml_str(level+1, self.is_not)
                result_str += level*"\t" + "</require>\n"
            if self.is_not:
                level -= 1
                result_str += level*"\t" + "</require>\n"
        else:
            result_str += level*"\t" + "<require type=\"" + self.type + "\">\n"
            for i, v in enumerate(self.value):
                result_str += v.recursive_xml_str(level+1, recursive_is_not)
            result_str += level*"\t" + "</require>\n"
        return result_str

    def __str__(self):
        return self.recursive_str(1, False)

    def str_debug(self):
        return self.recursive_str_debug(1, False)

    def str_simple(self):
        if self.is_type_single():
            return self.value.str_debug()
        elif self.is_type_require_any():
            return "require-any"
        elif self.is_type_require_all():
            return "require-all"
        elif self.is_type_require_entitlement():
            return self.value.str_debug()[1:-1]
        elif self.is_type_start():
            return "start"
        else:
            return "unknown-type"

    def str_print_debug(self):
        if self.is_type_single():
            return (self.value.str_debug(), None)
        elif self.is_type_require_any():
            return ("(require-any", ")")
        elif self.is_type_require_all():
            return ("(require-all", ")")
        elif self.is_type_require_entitlement():
            return (self.value.str_debug()[:-1], ")")
        elif self.is_type_start():
            return (None, None)
        else:
            return ("unknown-type", None)

    def str_print(self):
        if self.is_type_single():
            return (str(self.value), None)
        elif self.is_type_require_any():
            return ("(require-any", ")")
        elif self.is_type_require_all():
            return ("(require-all", ")")
        elif self.is_type_require_entitlement():
            return (str(self.value)[:-1], ")")
        elif self.is_type_start():
            return (None, None)
        else:
            return ("unknown-type", None)

    def str_print_not(self):
        result_str = ""
        if self.is_type_single():
            if self.is_not:
                value = str(self.value)
                if "(require-any" in value:
                    result_str = self.value.str_not()
                else:
                    result_str += "(require-not " + str(self.value) + ")"
        return result_str

    def xml_str(self):
        return self.recursive_xml_str(3, False)


class ReducedEdge():
    start = None
    end = None

    def __init__(self, start=None, end=None):
        self.start = start
        self.end = end

    def str_debug(self):
        return self.start.str_debug() + " -> " + self.end.str_debug()

    def str_simple(self):
        #print "start: %s" % (self.start.str_simple())
        #print "end: %s" % (self.end.str_simple())
        return "%s -----> %s" % (self.start.str_simple(), self.end.str_simple())

    def __str__(self):
        return str(self.start) + " -> " + str(self.end)


class ReducedGraph():
    vertices = []
    edges = []
    final_vertices = []
    reduce_changes_occurred = False

    def __init__(self):
        self.vertices = []
        self.edges = []
        self.final_vertices = []
        self.reduce_changes_occurred = False

    def add_vertice(self, v):
        self.vertices.append(v)

    def add_edge(self, e):
        self.edges.append(e)

    def add_edge_by_vertices(self, v_start, v_end):
        e = ReducedEdge(v_start, v_end)
        self.edges.append(e)

    def set_final_vertices(self):
        self.final_vertices = []
        for v in self.vertices:
            is_final = True
            for e in self.edges:
                if v == e.start:
                    is_final = False
                    break
            if is_final:
                self.final_vertices.append(v)

    def contains_vertice(self, v):
        return v in self.vertices

    def contains_edge(self, e):
        return e in self.edges

    def contains_edge_by_vertices(self, v_start, v_end):
        for e in self.edges:
            if e.start == v_start and e.end == v_end:
                return True
        return False

    def get_vertice_by_value(self, value):
        for v in self.vertices:
            if v.is_type_single():
                if v.value == value:
                    return v

    def get_edge_by_vertices(self, v_start, v_end):
        for e in self.edges:
            if e.start == v_start and e.end == v_end:
                return e
        return None

    def remove_vertice(self, v):
        edges_copy = list(self.edges)
        for e in edges_copy:
            if e.start == v or e.end == v:
                self.edges.remove(e)
        if v in self.vertices:
            self.vertices.remove(v)

    def remove_vertice_update_decision(self, v):
        edges_copy = list(self.edges)
        for e in edges_copy:
            if e.start == v:
                self.edges.remove(e)
            if e.end == v:
                e.start.decision = v.decision
                self.edges.remove(e)
        if v in self.vertices:
            self.vertices.remove(v)

    def remove_edge(self, e):
        if e in self.edges:
            self.edges.remove(e)

    def remove_edge_by_vertices(self, v_start, v_end):
        e = self.get_edge_by_vertices(v_start, v_end)
        if e:
            self.edges.remove(e)

    def replace_vertice_in_edge_start(self, old, new):
        global replace_occurred
        for e in self.edges:
            if e.start == old:
                e.start = new
                replace_occurred = True
            else:
                if isinstance(e.start.value, list):
                    e.start.replace_in_list(old, new)
                    if replace_occurred:
                        e.start.decision = new.decision

    def replace_vertice_in_edge_end(self, old, new):
        global replace_occurred
        for e in self.edges:
            if e.end == old:
                e.end = new
                replace_occurred = True
            else:
                if isinstance(e.end.value, list):
                    e.end.replace_in_list(old, new)
                    if replace_occurred:
                        e.end.decision = new.decision

    def replace_vertice_in_single_vertices(self, old, new):
        for v in self.vertices:
            if len(self.get_next_vertices(v)) == 0 and len(self.get_prev_vertices(v)) == 0:
                if isinstance(v.value, list):
                    v.replace_in_list(old, new)

    def replace_vertice_list(self, old, new):
        for v in self.vertices:
            if isinstance(v.value, list):
                v.replace_sublist_in_list(old, new)
            if set(self.get_next_vertices(v)) == set(old):
                for n in old:
                    self.remove_edge_by_vertices(v, n)
                self.add_edge_by_vertices(v, new)
            if set(self.get_prev_vertices(v)) == set(old):
                for n in old:
                    self.remove_edge_by_vertices(n, v)
                self.add_edge_by_vertices(new, v)

    def get_next_vertices(self, v):
        next_vertices = []
        for e in self.edges:
            if e.start == v:
                next_vertices.append(e.end)
        return next_vertices

    def get_prev_vertices(self, v):
        prev_vertices = []
        for e in self.edges:
            if e.end == v:
                prev_vertices.append(e.start)
        return prev_vertices

    def get_start_vertices(self):
        start_vertices = []
        for v in self.vertices:
            if not self.get_prev_vertices(v):
                start_vertices.append(v)
        return start_vertices

    def get_end_vertices(self):
        end_vertices = []
        for v in self.vertices:
            if not self.get_next_vertices(v):
                end_vertices.append(v)
        return end_vertices

    def reduce_next_vertices(self, v):
        next_vertices = self.get_next_vertices(v)
        if len(next_vertices) <= 1:
            return
        self.reduce_changes_occurred = True
        new_vertice = ReducedVertice("require-any", next_vertices, next_vertices[0].decision)
        add_to_final = False
        for n in next_vertices:
            self.remove_edge_by_vertices(v, n)
        self.replace_vertice_list(next_vertices, new_vertice)
        for n in next_vertices:
            if n in self.final_vertices:
                self.final_vertices.remove(n)
                add_to_final = True
            # If no more next vertices, remove vertice.
            if not self.get_next_vertices(n):
                if n in self.vertices:
                    self.vertices.remove(n)
        self.add_edge_by_vertices(v, new_vertice)
        self.add_vertice(new_vertice)
        if add_to_final:
            self.final_vertices.append(new_vertice)

    def reduce_prev_vertices(self, v):
        prev_vertices = self.get_prev_vertices(v)
        if len(prev_vertices) <= 1:
            return
        self.reduce_changes_occurred = True
        new_vertice = ReducedVertice("require-any", prev_vertices, v.decision)
        for p in prev_vertices:
            self.remove_edge_by_vertices(p, v)
        self.replace_vertice_list(prev_vertices, new_vertice)
        for p in prev_vertices:
            # If no more prev vertices, remove vertice.
            if not self.get_prev_vertices(p):
                if p in self.vertices:
                    self.vertices.remove(p)
        self.add_vertice(new_vertice)
        self.add_edge_by_vertices(new_vertice, v)

    def reduce_vertice_single_prev(self, v):
        global replace_occurred
        prev = self.get_prev_vertices(v)
        if len(prev) != 1:
            logger.debug("not a single prev for node")
            return
        p = prev[0]
        nexts = self.get_next_vertices(p)
        if len(nexts) > 1 or nexts[0] != v:
            logger.debug("multiple nexts for prev")
            return
        require_all_vertices = []
        if p.is_type_require_all():
            require_all_vertices.extend(p.value)
        else:
            require_all_vertices.append(p)
        if v.is_type_require_all():
            require_all_vertices.extend(v.value)
        else:
            require_all_vertices.append(v)
        new_vertice = ReducedVertice("require-all", require_all_vertices, v.decision)
        self.remove_edge_by_vertices(p, v)
        replace_occurred = False
        self.replace_vertice_in_edge_start(v, new_vertice)
        self.replace_vertice_in_edge_end(p, new_vertice)
        self.replace_vertice_in_single_vertices(p, new_vertice)
        self.replace_vertice_in_single_vertices(v, new_vertice)
        self.remove_vertice(p)
        self.remove_vertice(v)
        if not replace_occurred:
            self.add_vertice(new_vertice)
        if v in self.final_vertices:
            self.final_vertices.remove(v)
            self.final_vertices.append(new_vertice)

    def reduce_vertice_single_next(self, v):
        global replace_occurred
        next = self.get_next_vertices(v)
        if len(next) != 1:
            return
        n = next[0]
        prevs = self.get_prev_vertices(n)
        if len(prevs) > 1 or prevs[0] != v:
            return
        require_all_vertices = []
        if v.is_type_require_all():
            require_all_vertices.extend(v.value)
        else:
            require_all_vertices.append(v)
        if n.is_type_require_all():
            require_all_vertices.extend(n.value)
        else:
            require_all_vertices.append(n)
        new_vertice = ReducedVertice("require-all", require_all_vertices, n.decision)
        self.remove_edge_by_vertices(v, n)
        replace_occurred = False
        self.replace_vertice_in_edge_start(n, new_vertice)
        self.replace_vertice_in_edge_end(e, new_vertice)
        self.replace_vertice_in_single_vertices(v, new_vertice)
        self.replace_vertice_in_single_vertices(n, new_vertice)
        self.remove_vertice(v)
        self.remove_vertice(n)
        if not replace_occurred:
            self.add_vertice(new_vertice)
        if n in self.final_vertices:
            self.final_vertices.remove(n)
            self.final_vertices.append(new_vertice)

    def reduce_graph(self):
        self.set_final_vertices()

        logger.debug("before everything:\n" + self.str_simple())
        # Do until no more changes.
        while True:
            self.reduce_changes_occurred = False
            copy_vertices = list(self.vertices)
            for v in copy_vertices:
                self.reduce_next_vertices(v)
            if self.reduce_changes_occurred == False:
                break
        logger.debug("after next:\n" + self.str_simple())
        # Do until no more changes.
        while True:
            self.reduce_changes_occurred = False
            copy_vertices = list(self.vertices)
            for v in copy_vertices:
                self.reduce_prev_vertices(v)
            if self.reduce_changes_occurred == False:
                break
        logger.debug("after next/prev:\n" + self.str_simple())

        # Reduce graph starting from final vertices. Keep going until
        # final vertices don't change during an iteration.
        while True:
            copy_final_vertices = list(self.final_vertices)
            for v in copy_final_vertices:
                logger.debug("reducing single prev vertex: " + v.str_debug())
                self.reduce_vertice_single_prev(v)
                logger.debug("### new graph is:")
                logger.debug(self.str_simple())
            if set(copy_final_vertices) == set(self.final_vertices):
                break
        for e in self.edges:
            v = e.end
            logger.debug("reducing single prev vertex: " + v.str_debug())
            self.reduce_vertice_single_prev(v)
        logger.debug("after everything:\n" + self.str_simple())

    def reduce_graph_with_metanodes(self):
        # Add require-any metanode if current node has multiple successors.
        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            nlist = self.get_next_vertices(v)
            if len(nlist) >= 2:
                new_node = ReducedVertice("require-any", None, None)
                self.add_vertice(new_node)
                self.add_edge_by_vertices(v, new_node)
                for n in nlist:
                    self.remove_edge_by_vertices(v, n)
                    self.add_edge_by_vertices(new_node, n)

        start_list = self.get_start_vertices()
        new_node = ReducedVertice("start", None, None)
        self.add_vertice(new_node)
        for s in start_list:
            self.add_edge_by_vertices(new_node, s)

        # Add require-all metanode if current node has a require-any as a predecessor and is followed by another node.
        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            prev_vertices = list(self.get_prev_vertices(v))
            next_vertices = list(self.get_next_vertices(v))
            for p in prev_vertices:
                if (p.is_type_require_any() or p.is_type_start()) and next_vertices:
                    # Except for when a require-entitlement ending block.
                    if v.is_type_require_entitlement():
                        has_next_nexts = False
                        for n in next_vertices:
                            if n.is_type_require_any():
                                for n2 in self.get_next_vertices(n):
                                    if self.get_next_vertices(n2):
                                        has_next_nexts = True
                                        break
                            else:
                                if self.get_next_vertices(n):
                                    has_next_nexts = True
                                    break
                        if not has_next_nexts:
                            continue
                    new_node = ReducedVertice("require-all", None, None)
                    self.add_vertice(new_node)
                    self.remove_edge_by_vertices(p, v)
                    self.add_edge_by_vertices(p, new_node)
                    self.add_edge_by_vertices(new_node, v)

    def str_simple_with_metanodes(self):
        logger.debug("==== vertices:\n")
        for v in self.vertices:
            logger.debug(v.str_simple())
        logger.debug("==== edges:\n")
        for e in self.edges:
            logger.debug(e.str_simple())

    def str_simple(self):
        message = "==== vertices:\n"
        for v in self.vertices:
            message += "decision: " + str(v.decision) + "\t" + v.str_debug() + "\n"
        message += "==== final vertices:\n"
        for v in self.final_vertices:
            message += "decision: " + str(v.decision) + "\t" + v.str_debug() + "\n"
        message += "==== edges:\n"
        for e in self.edges:
            message += "\t" + e.str_debug() + "\n"
        return message

    def __str__(self):
        result_str = ""
        for v in self.vertices:
            result_str += "(" + str(v.decision) + " "
            if len(self.get_next_vertices(v)) == 0 and len(self.get_next_vertices(v)) == 0:
                if v in self.final_vertices:
                    result_str += str(v) + "\n"
            result_str += ")\n"
        for e in self.edges:
            result_str += str(e) + "\n"
        result_str += "\n"
        return result_str

    def remove_builtin_filters(self):
        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            if re.search("###\$\$\$\*\*\*", str(v)):
                self.remove_vertice_update_decision(v)

    def reduce_integrated_vertices(self, integrated_vertices):
        if len(integrated_vertices) == 0:
            return (None, None)
        if len(integrated_vertices) > 1:
            return (ReducedVertice("require-any", integrated_vertices, integrated_vertices[0].decision), integrated_vertices[0].decision)
        require_all_vertices = []
        v = integrated_vertices[0]
        decision = None
        while True:
            if not re.search("entitlement-value #t", str(v)):
                require_all_vertices.append(v)
            next_vertices = self.get_next_vertices(v)
            if decision == None and v.decision != None:
                decision = v.decision
            self.remove_vertice(v)
            if v in self.final_vertices:
                self.final_vertices.remove(v)
            if next_vertices:
                v = next_vertices[0]
            else:
                break
        if len(require_all_vertices) == 0:
            return (None, v.decision)
        if len(require_all_vertices) == 1:
            return (ReducedVertice(value=require_all_vertices[0].value, decision=require_all_vertices[0].decision, is_not=require_all_vertices[0].is_not), v.decision)
        return (ReducedVertice("require-all", require_all_vertices, require_all_vertices[len(require_all_vertices)-1].decision), v.decision)

    def aggregate_require_entitlement(self, v):
        next_vertices = []
        prev_vertices = self.get_prev_vertices(v)
        integrated_vertices = []
        for n in self.get_next_vertices(v):
            if not re.search("entitlement-value", str(n)):
                next_vertices.append(n)
                break
            integrated_vertices.append(n)
            current_list = [ n ]
            while current_list:
                current = current_list.pop()
                for n2 in self.get_next_vertices(current):
                    if not re.search("entitlement-value", str(n2)):
                        self.remove_edge_by_vertices(current, n2)
                        next_vertices.append(n2)
                    else:
                        current_list.append(n2)
        new_vertice = ReducedVertice(type="require-entitlement", value=(v, None), decision=None, is_not=v.is_not)
        for p in prev_vertices:
            self.remove_edge_by_vertices(p, v)
            self.add_edge_by_vertices(p, new_vertice)
        for n in next_vertices:
            self.remove_edge_by_vertices(v, n)
            self.add_edge_by_vertices(new_vertice, n)
        for i in integrated_vertices:
            self.remove_edge_by_vertices(v, i)
        self.remove_vertice(v)
        self.add_vertice(new_vertice)
        if v in self.final_vertices:
            self.final_vertices.remove(v)
            self.final_vertices.append(new_vertice)
        (new_integrate, decision) = self.reduce_integrated_vertices(integrated_vertices)
        for i in integrated_vertices:
            self.remove_vertice(i)
            if i in self.final_vertices:
                self.final_vertices.remove(i)
        new_vertice.set_integrated_vertice(new_integrate)
        new_vertice.set_decision(decision)

    def aggregate_require_entitlement_nodes(self):
        copy_vertices = list(self.vertices)
        idx = 0
        while idx < len(copy_vertices):
            v = copy_vertices[idx]
            if re.search("require-entitlement", str(v)):
                self.aggregate_require_entitlement(v)
            idx += 1

    def cleanup_filters(self):
        self.remove_builtin_filters()
        self.aggregate_require_entitlement_nodes()

    def remove_builtin_filters_with_metanodes(self):
        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            if re.search("###\$\$\$\*\*\*", v.str_simple()):
                self.remove_vertice(v)
            elif re.search("entitlement-value #t", v.str_simple()):
                self.remove_vertice(v)
            elif re.search("entitlement-value-regex #\"\.\"", v.str_simple()):
                v.value.non_terminal.argument = "#\".+\""
            elif re.search("global-name-regex #\"\.\"", v.str_simple()):
                v.value.non_terminal.argument = "#\".+\""
            elif re.search("local-name-regex #\"\.\"", v.str_simple()):
                v.value.non_terminal.argument = "#\".+\""

    def replace_require_entitlement_with_metanodes(self, v):
        prev_list = self.get_prev_vertices(v)
        next_list = self.get_next_vertices(v)
        new_node = ReducedVertice(type="require-entitlement", value=v.value, decision=None, is_not=v.is_not)
        self.add_vertice(new_node)
        self.remove_vertice(v)
        for p in prev_list:
            self.add_edge_by_vertices(p, new_node)
        for n in next_list:
            self.add_edge_by_vertices(new_node, n)

    def aggregate_require_entitlement_with_metanodes(self):
        copy_vertices = list(self.vertices)
        for v in copy_vertices:
            if re.search("require-entitlement", str(v)):
                self.replace_require_entitlement_with_metanodes(v)

    def cleanup_filters_with_metanodes(self):
        self.remove_builtin_filters_with_metanodes()
        self.aggregate_require_entitlement_with_metanodes()

    def print_vertices_with_operation(self, operation, out_f):
        allow_vertices = [v for v in self.vertices if v.decision == "allow"]
        deny_vertices = [v for v in self.vertices if v.decision == "deny"]
        if allow_vertices:
            out_f.write("(allow %s " % (operation))
            if len(allow_vertices) > 1:
                for v in allow_vertices:
                    out_f.write("\n" + 8*" " + str(v))
            else:
                out_f.write(str(allow_vertices[0]))
            out_f.write(")\n")
        if deny_vertices:
            out_f.write("(deny %s " % (operation))
            if len(deny_vertices) > 1:
                for v in deny_vertices:
                    out_f.write("\n" + 8*" " + str(v))
            else:
                out_f.write(str(deny_vertices[0]))
            out_f.write(")\n")

    def print_vertices_with_operation_metanodes(self, operation, default_is_allow, out_f):
        # Return if only start node in list.
        if len(self.vertices) == 1 and self.vertices[0].is_type_start():
            return
        # Use reverse of default rule.
        if default_is_allow:
            out_f.write("(deny %s" % (operation))
        else:
            out_f.write("(allow %s" % (operation))
        vlist = []
        start_list = self.get_start_vertices()
        start_list.reverse()
        vlist.insert(0, (None, 0))
        for s in start_list:
            vlist.insert(0, (s, 1))
        while True:
            if not vlist:
                break
            (cnode, indent) = vlist.pop(0)
            if not cnode:
                out_f.write(")")
                continue
            (first, last) = cnode.str_print()
            if first:
                if cnode.is_not:
                    if cnode.str_print_not() != "":
                        out_f.write("\n" + indent * "\t" + cnode.str_print_not())
                    else:
                        out_f.write("\n" + indent * "\t" + "(require-not " + first)
                        if cnode.is_type_require_any() or cnode.is_type_require_all() or cnode.is_type_require_entitlement():
                            vlist.insert(0, (None, indent))
                        else:
                            out_f.write(")")
                else:
                    out_f.write("\n" + indent * "\t" + first)
            if last:
                vlist.insert(0, (None, indent))
            next_vertices_list = self.get_next_vertices(cnode)
            if next_vertices_list:
                if cnode.is_type_require_any() or cnode.is_type_require_all() or cnode.is_type_require_entitlement():
                    indent += 1
                next_vertices_list.reverse()
                if cnode.is_type_require_entitlement():
                    pos = 0
                    for n in next_vertices_list:
                        if (n.is_type_single() and not re.search("entitlement-value", n.str_simple())) or \
                                n.is_type_require_entitlement():
                            vlist.insert(pos + 1, (n, indent-1))
                        else:
                            vlist.insert(0, (n, indent))
                            pos += 1
                else:
                    for n in next_vertices_list:
                        vlist.insert(0, (n, indent))
        out_f.write("\n")

    def dump_xml(self, operation, out_f):
        allow_vertices = [v for v in self.vertices if v.decision == "allow"]
        deny_vertices = [v for v in self.vertices if v.decision == "deny"]
        if allow_vertices:
            out_f.write("\t<operation name=\"%s\" action=\"allow\">\n" % (operation))
            out_f.write("\t\t<filters>\n")
            for v in allow_vertices:
                out_f.write(v.xml_str())
            out_f.write("\t\t</filters>\n")
            out_f.write("\t</operation>\n")
        if deny_vertices:
            out_f.write("\t<operation name=\"%s\" action=\"deny\">\n" % (operation))
            out_f.write("\t\t<filters>\n")
            for v in deny_vertices:
                out_f.write(v.xml_str())
            out_f.write("\t\t</filters>\n")
            out_f.write("\t</operation>\n")


def reduce_operation_node_graph(g):
    # Create reduced graph.
    rg = ReducedGraph()
    for node_iter in g.keys():
        rv = ReducedVertice(value=node_iter, decision=g[node_iter]["decision"], is_not=g[node_iter]["not"])
        rg.add_vertice(rv)

    for node_iter in g.keys():
        rv = rg.get_vertice_by_value(node_iter)
        for node_next in g[node_iter]["list"]:
            rn = rg.get_vertice_by_value(node_next)
            rg.add_edge_by_vertices(rv, rn)

    # Handle special case for require-not (require-enitlement (...)).
    l = len(g.keys())
    for idx, node_iter in enumerate(g.keys()):
        rv = rg.get_vertice_by_value(node_iter)
        if not re.search("require-entitlement", str(rv)):
            continue
        if not rv.is_not:
            continue
        c_idx = idx
        while True:
            c_idx += 1
            if c_idx >= l:
                break
            rn = rg.get_vertice_by_value(list(g.keys())[c_idx])
            if not re.search("entitlement-value", str(rn)):
                break
            prevs_rv = rg.get_prev_vertices(rv)
            prevs_rn = rg.get_prev_vertices(rn)
            if sorted(prevs_rv) != sorted(prevs_rn):
                continue
            for pn in prevs_rn:
                rg.remove_edge_by_vertices(rn, pn)
            rg.add_edge_by_vertices(rv, rn)

    rg.cleanup_filters_with_metanodes()
    for node_iter in g.keys():
        rv = rg.get_vertice_by_value(node_iter)
    rg.reduce_graph_with_metanodes()
    return rg


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
    sb_ops_offsets = struct.unpack("<%dH" % (num_sb_ops), f.read(2*num_sb_ops))

    # Extract node for 'default' operation (index 0).
    default_node = find_operation_node_by_offset(operation_nodes, sb_ops_offsets[0])
    print("(%s default)" % (default_node.terminal))

    # For each operation expand operation node.
    #for idx in range(1, len(sb_ops_offsets)):
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
            rg = reduce_operation_node_graph(g)
            rg.print_vertices_with_operation(operation)
        else:
            if node.terminal:
                if node.terminal.type != default_node.terminal.type:
                    print("(%s %s)" % (node.terminal, operation))


if __name__ == "__main__":
    sys.exit(main())
