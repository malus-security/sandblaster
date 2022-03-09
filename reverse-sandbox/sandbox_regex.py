#!/usr/bin/env python3

import struct
import logging
import logging.config

logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)

from regex_parser_v1 import RegexParser as RegexParserV1
from regex_parser_v2 import RegexParser as RegexParserV2
from regex_parser_v3 import RegexParser as RegexParserV3

class Node():
    """Representation of a node inside a regex non-deterministic automaton

    The most important attribute is the node type, which may be any of
    the four macros TYPE_... below.
    """

    TYPE_JUMP_FORWARD = 1
    TYPE_JUMP_BACKWARD = 2
    TYPE_CHARACTER = 3
    TYPE_END = 4
    FLAG_WHITE = 1
    FLAG_GREY = 2
    FLAG_BLACK = 3
    name = ""
    type = None
    value = None
    flag = "white"

    def __init__(self, name=None, type=None, value=''):
        self.name = name
        self.type = type
        self.value = value
        self.flag = self.FLAG_WHITE

    def set_name(self, name):
        self.name = name

    def set_type_jump_forward(self):
        self.type = self.TYPE_JUMP_FORWARD

    def set_type_jump_backward(self):
        self.type = self.TYPE_JUMP_BACKWARD

    def set_type_character(self):
        self.type = self.TYPE_CHARACTER

    def set_type_end(self):
        self.type = self.TYPE_END

    def is_type_end(self):
        return self.type == self.TYPE_END

    def is_type_jump(self):
        return self.type == self.TYPE_JUMP_BACKWARD or self.type == self.TYPE_JUMP_FORWARD

    def is_type_jump_backward(self):
        return self.type == self.TYPE_JUMP_BACKWARD

    def is_type_jump_forward(self):
        return self.type == self.TYPE_JUMP_FORWARD

    def is_type_character(self):
        return self.type == self.TYPE_CHARACTER

    def set_value(self, value):
        self.value = value

    def set_flag_white(self):
        self.flag = self.FLAG_WHITE

    def set_flag_grey(self):
        self.flag = self.FLAG_GREY

    def set_flag_black(self):
        self.flag = self.FLAG_BLACK

    def __str__(self):
        if self.type == self.TYPE_JUMP_BACKWARD:
            return "(%s: jump backward)" % (self.name)
        elif self.type == self.TYPE_JUMP_FORWARD:
            return "(%s: jump forward)" % (self.name)
        elif self.type == self.TYPE_END:
            return "(%s: end)" % (self.name)
        else:
            return "(%s: %s)" % (self.name, self.value)


class Graph():
    """Representation of a regex NDA (Non-Deterministic Automaton)

    Use this class to convert a regex list of items into its canonical
    regular expression string.
    """

    graph_dict = {}
    canon_graph_dict = {}
    node_list = []
    start_node = None
    end_states = []
    start_state = 0
    regex = []
    unified_regex = ""

    def __init__(self):
        self.graph_dict = {}

    def add_node(self, node, next_list=None):
        self.graph_dict[node] = next_list

    def has_node(self, node):
        return node in graph_dict.keys()

    def update_node(self, node, next_list):
        self.graph_dict[node] = next_list

    def add_new_next_to_node(self, node, next):
        self.graph_dict[node].append(next)

    def __str__(self):
        # Get maximum node number.
        max = -1
        for node in self.graph_dict.keys():
            if max < int(node.name):
                max = int(node.name)

        # Create graph list for ordered listing of nodes.
        graph_list = [None] * (max+1)
        for node in self.graph_dict.keys():
            actual_string = str(node) + ":"
            for next_node in self.graph_dict[node]:
                actual_string += " " + str(next_node)
            graph_list[int(node.name)] = actual_string

        # Store node graph in ret_string.
        ret_string = "\n-- Node graph --\n"
        for s in graph_list:
            if s:
                ret_string += s + "\n"

        # Store canonical graph in ret_string.
        ret_string += "\n-- Canonical graph --\n"
        for state in self.canon_graph_dict.keys():
            if state == self.start_state:
                ret_string += "> "
            elif state in self.end_states:
                ret_string += "# "
            else:
                ret_string += "  "
            ret_string += "%d: %s\n" % (state, self.canon_graph_dict[state])
        ret_string += "\n"
        return ret_string

    def get_node_for_idx(self, idx):
        if idx >= len(self.node_list) or idx < 0:
            return None
        return self.node_list[idx]

    def get_re_index_for_pos(self, regex_list, pos):
        for idx, item in enumerate(regex_list):
            if item["pos"] == pos:
                return idx
        for idx, item in enumerate(regex_list):
            if item["pos"]-1 == pos:
                return idx
        return -1

    def get_next_idx_for_regex_item(self, regex_list, regex_item):
        result = self.get_re_index_for_pos(regex_list, regex_item["nextpos"])
        assert(result >= 0)
        return result

    def fill_from_regex_list(self, regex_list):
        # First create list of nodes. No pointers/links at this point.
        # Create a node for each item.
        self.node_list = []
        for idx, item in enumerate(regex_list):
            node = Node(name="%s" % (idx))
            if item["type"] == "jump_backward":
                node.set_type_jump_backward()
            elif item["type"] == "jump_forward":
                node.set_type_jump_forward()
            elif item["type"] == "end":
                node.set_type_end()
            else:
                node.set_type_character()
                node.set_value(item["value"])

            if 'start_node' in item and item['start_node'] == True:
                assert(self.start_node == None)
                self.start_node = node
            self.node_list.append(node)

        self.graph_dict = {}
        for idx, node in enumerate(self.node_list):
            # If node is end node ignore.
            if node.is_type_end():
                 self.graph_dict[node] = []
            elif node.is_type_character():
                next = self.get_node_for_idx(
                    self.get_next_idx_for_regex_item(regex_list, regex_list[idx]))
                if next:
                    self.graph_dict[node] = [ next ]
                else:
                    self.graph_dict[node] = []
            # Node is jump node.
            elif node.is_type_jump_backward():
                next_idx = self.get_re_index_for_pos(regex_list, regex_list[idx]["value"])
                next = self.get_node_for_idx(next_idx)
                if next:
                    self.graph_dict[node] = [next]
                else:
                    self.graph_dict[node] = []
            elif node.is_type_jump_forward():
                next_idx1 = self.get_next_idx_for_regex_item(
                    regex_list, regex_list[idx])
                next_idx2 = self.get_re_index_for_pos(regex_list, regex_list[idx]["value"])
                next1 = self.get_node_for_idx(next_idx1)
                next2 = self.get_node_for_idx(next_idx2)
                self.graph_dict[node] = []
                if next1:
                    self.graph_dict[node].append(next1)
                if next2:
                    self.graph_dict[node].append(next2)

    def get_character_nodes(self, node):
        node_list = []
        for next in self.graph_dict[node]:
            if next.is_type_character() or next.is_type_end():
                node_list.append(next)
            else:
                node_list = list(set(node_list).union(self.get_character_nodes(next)))
        return node_list

    def find_node_type_jump(self, current_node, node, backup_dict):
        if not current_node.is_type_jump():
            return False
        if current_node == node:
            return True
        if not self.graph_dict[current_node]:
            return False
        for next_node in backup_dict[current_node]:
            if self.find_node_type_jump(next_node, node, backup_dict):
                return True
        return False

    def reduce(self):
        for node in self.graph_dict.keys():
            if node.is_type_character():
                self.graph_dict[node] = self.get_character_nodes(node)
        old_dict = dict(self.graph_dict)
        backup_dict = dict(self.graph_dict)
        for node in old_dict.keys():
            if node.is_type_jump():
                if self.find_node_type_jump(self.start_node,
                        node, backup_dict):
                    continue
                del self.graph_dict[node]

    def get_edges(self, node):
        edges = []
        is_end_state = False
        for next in self.graph_dict[node]:
            if next.is_type_end():
                is_end_state = True
            else:
                edges.append((next.value, int(next.name)))
        return is_end_state, edges

    def convert_to_canonical(self):
        self.end_states = []
        for node in self.graph_dict.keys():
            if node.is_type_end():
                continue
            state_idx = int(node.name)
            is_end_state, self.canon_graph_dict[state_idx] = self.get_edges(node)
            if is_end_state == True:
                self.end_states.append(state_idx)
        for node in self.graph_dict.keys():
            if node.name == "0":
                self.start_state = -1
                self.canon_graph_dict[-1] = [ (node.value, 0) ]
        logger.debug(self.canon_graph_dict)
        logger.debug("end_states:")
        logger.debug(self.end_states)
        logger.debug("start_state:")
        logger.debug(self.start_state)

    def need_use_plus(self, initial_string, string_to_add):
        if not string_to_add.endswith("*"):
            return False

        if string_to_add.startswith("(") and string_to_add[-2:-1] == ")":
            actual_part = string_to_add[1:-2]
        else:
            actual_part = string_to_add[:-1]
        if initial_string.endswith(actual_part):
            return True
        if initial_string.endswith(string_to_add):
            return True

        return False

    def unify_two_strings(self, s1, s2):
        # Find largest common starting substring.
        lcss = ""
        for i in range(1, len(s1)+1):
            if s2.find(s1[:i], 0, i) != -1:
                lcss = s1[:i]
        if lcss:
            s1 = s1[len(lcss):]
            s2 = s2[len(lcss):]
        # Find largest common ending substring.
        lces = ""
        for i in range(1, len(s1)+1):
            if s2.find(s1[-i:], len(s2)-i, len(s2)) != -1:
                lces = s1[-i:]
        if lces:
            s1 = s1[:len(s1)-len(lces)]
            s2 = s2[:len(s2)-len(lces)]

        if not s1 and not s2:
            return lcss + lces

        if s1 and s2:
            return lcss + "(" + s1 + "|" + s2 + ")" + lces

        # Make s1 the empty string.
        if not s2:
            aux = s1
            s1 = s2
            s2 = aux

        if s2[-1] == '+':
            s2 = s2[:-1] + '*'
        else:
            if len(s2) > 1:
                s2 = "(" + s2 + ")?"
            else:
                s2 = s2 + '?'

        return lcss + s2 + lces

    def unify_strings(self, string_list):
        unified = ""
        if not string_list:
            return None
        if len(string_list) == 1:
            return string_list[0]
        # We now know we have multiple strings. Merge two at a time.
        current = string_list[0]
        for s in string_list[1:]:
            current = self.unify_two_strings(current, s)
        return current

    def remove_state(self, state_to_remove):
        itself_string = ""
        for (next_string, next_state) in self.canon_graph_dict[state_to_remove]:
            if next_state == state_to_remove:
                if len(next_string) > 1:
                    itself_string = "(%s)*" % next_string
                else:
                    itself_string = "%s*" % next_string

        # Create list of to_strings indexed by to_states.
        to_strings = {}
        for to_state in self.canon_graph_dict.keys():
            to_strings[to_state] = []
            if to_state == state_to_remove:
                continue
            for (iter_to_string, iter_to_state) in self.canon_graph_dict[state_to_remove]:
                if iter_to_state == to_state:
                    to_strings[to_state].append(iter_to_string)

        # Unify multiple strings leading to the same to_state.
        unified_to_string = {}
        for to_state in to_strings.keys():
            unified_to_string[to_state] = self.unify_strings(to_strings[to_state])

        # Go through all graph edges.
        for from_state in self.canon_graph_dict.keys():
            # Pass current state to remove.
            if from_state == state_to_remove:
                continue
            items_to_remove_list = []
            for (next_string, next_state) in self.canon_graph_dict[from_state]:
                # Only if edge points to state_to_remove.
                if next_state != state_to_remove:
                    continue
                # Plan edge to remove. Create new edge bypassing state_to_remove.
                items_to_remove_list.append((next_string, next_state))
                for to_state in self.canon_graph_dict.keys():
                    if len(to_strings[to_state]) == 0:
                        continue
                    to_string = unified_to_string[to_state]
                #for (to_string, to_state) in self.canon_graph_dict[state_to_remove]:
                #    # If state points to itself, do not add edge.
                #    if to_state == state_to_remove:
                #        continue
                    # Add new edge, consider if state points to itself.
                    if self.need_use_plus(next_string, itself_string):
                        self.canon_graph_dict[from_state].append((next_string + "+" + to_string, to_state))
                        continue
                    self.canon_graph_dict[from_state].append((next_string + itself_string + to_string, to_state))
            for (next_string, next_state) in items_to_remove_list:
                self.canon_graph_dict[from_state].remove((next_string, next_state))

        del self.canon_graph_dict[state_to_remove]

    def simplify(self):
        tmp_dict = dict(self.canon_graph_dict)
        for state in tmp_dict.keys():
            if state != self.start_state and state not in self.end_states:
                self.remove_state(state)

    def combine_start_end_nodes(self):
        working_strings = self.canon_graph_dict[self.start_state]
        final_strings = []
        string_added = True
        while string_added == True:
            string_added = False
            initial_strings = working_strings
            working_strings = []
            for (start_string, start_next_state) in initial_strings:
                if not start_next_state in self.end_states:
                    continue
                if self.canon_graph_dict[start_next_state]:
                    for (next_string, next_state) in self.canon_graph_dict[start_next_state]:
                        if next_state == start_next_state:
                            next_string = "(%s)*" % next_string
                            if self.need_use_plus(start_string, next_string):
                                final_strings.append((start_string + "+", None))
                            else:
                                final_strings.append((start_string + next_string, None))
                        else:
                            final_strings.append((start_string + next_string, None))
                            working_strings.append((start_string + next_string, next_state))
                else:
                    final_strings.append((start_string, None))
                string_added = True
        self.regex = [x[0] for x in final_strings]
        self.unified_regex = self.unify_strings(self.regex)



def create_regex_list(re):
    """Convert binary regex to list of items.

    Each item stores character position inside the binary regex (useful
    for jumps), character type and the value (either character or
    jump offset).
    """

    regex_list = []

    version = struct.unpack('>I', ''.join([chr(x) for x in re[:4]]))[0]
    logger.debug("re.version: 0x%x", version)

    i = 4
    if version == 1:
        RegexParserV1.parse(re, i, regex_list)
    elif version == 2:
        RegexParserV2.parse(re, i, regex_list)
    elif version == 3:
        RegexParserV3.parse(re, i, regex_list)
    else:
        logger.critical("No parser available for regex version {:x}".format(version))



    return regex_list


def parse_regex(re):
    """Parse binary form for regular expression into canonical string.

    The input binary format is the one stored in the sandbox profile
    file. The out format is a canonical regular expression string using
    standard ASCII characters and metacharacters such as ^, $, +, *, etc.
    """

    regex_list = create_regex_list(re)
    g = Graph()
    g.fill_from_regex_list(regex_list)
    g.reduce()
    g.convert_to_canonical()
    g.simplify()
    g.combine_start_end_nodes()
    logger.debug(g)
    return g.regex


import sys
import struct


def main():
    """Parse regular expressions in binary file."""

    if len(sys.argv) != 2:
        print >> sys.stderr, "Usage: %s <regex-binary-file>" % (sys.argv[0])
        sys.exit(1)

    with open(sys.argv[1]) as f:
        re_count = struct.unpack("<H", f.read(2))[0]
        for i in range(re_count):
            re_length = struct.unpack("<I", f.read(4))[0]
            re = struct.unpack("<%dB" % re_length, f.read(re_length))
            logger.info("total_re_length: 0x%x", re_length)
            re_debug_str = "re: [", ", ".join([hex(i) for i in re]), "]"
            logger.info(re_debug_str)
            print(parse_regex(re))


if __name__ == "__main__":
    sys.exit(main())
