import sys
import struct
import logging
import logging.config
import os

dir_path = os.path.dirname(__file__) or "."
logging.config.fileConfig(dir_path + "/logger.config")
logger = logging.getLogger(__name__)


class NonTerminalNode:
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
        """ Eq override.

            For two non-terminal nodes given, verify if the IDs, argument IDs,
            the match offsets and the unmatch offsets are equal.

            Args:
                other: Another instance of this class.

            Returns:
                True: if those above are equal.
                False: otherwise.
        """

        id_bool = self.filter_id == other.filter_id
        arg_bool = self.argument_id == other.argument_id
        match_bool = self.match_offset == other.match_offset
        unmatch_bool = self.unmatch_offset == other.unmatch_offset

        return id_bool and arg_bool and match_bool and unmatch_bool

    def simplify_list(self, arg_list):
        """
            Deletes the duplicate arguments from a given list.

            The arguments can differ by an additional '/'. This function
            removes such duplicates and keeps only one argument.

            Args:
                arg_list: A list of arguments.

            Returns:
                A list without duplicates.
        """

        result_list = []
        for arg in arg_list:
            if len(arg) == 0:
                continue

            tmp_list = list(result_list)
            match_found = False

            for tmp_res in tmp_list:
                if len(tmp_res) == 0:
                    continue

                if arg == tmp_res or arg + "/" == tmp_res or \
                        arg == tmp_res + "/":

                    match_found = True
                    result_list.remove(tmp_res)

                    if arg[-1] == '/':
                        result_list.append(arg + "^^^")
                    else:
                        result_list.append(arg + "/^^^")

            if not match_found:
                result_list.append(arg)

        return result_list

    def _prefix_adder(self, curr_filter, prefix_added, s):
        """
            Appends a prefix if it is needed.

            If the filter contains "${" and "}" and it does not have a prefix
            already added, then append "-prefix."

            Args:
                curr_filter: The current filter.
                prefix_added: A bool that indicates if a prefix was already
                              added.
                s: The string to be added.
        """

        if "${" in s and "}" in s:
            if not prefix_added:
                prefix_added = True
                curr_filter += "-prefix"
        return curr_filter

    def _cur_filter_identifier(self, curr_filter, s):
        """
            Identifies the current filter and updates the string as following:

            If the strings ends with "/^^^" then the current filter is a
            subpath.

            If the string contains '\\' or '|' or '['and ']' or
             '+' then the string should be appended with "/?".

             If the instance filter is "literal" then current filter should
             be updated with "regex". Else, append "-regex" to the current
             filter.

             Args:
                 curr_filter: The current filter.
                 s: The string that the identifying is based on.

            Returns:
                The updated current filter and string.
        """

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
        return curr_filter, s

    def _identify_subpath(self, arg, curr_filter):
        """
            Updates the argument and also the filter if it is needed.

            If the argument ends with "/^^^" then the filter given should be
            updated to "subpath".

            If the argument contains '\\' or '|' or '[' or ']' or '+' and it
            is a subpath, then it should be appended with '/?'.

            If the self instance is literal, then the given filter should be
            updated to "regex" else, it should be appended with "-regex".

            If the argument has '${' or '}' then -prefix should
            be appended.

            Args:
                arg: An argument.
                curr_filter: A filter.

            Returns:
                The updated argument and given filter.
        """

        curr_filter, s = self._cur_filter_identifier(curr_filter, arg)

        prefix_added = False

        curr_filter = self._prefix_adder(curr_filter, prefix_added, arg)

        return arg, curr_filter

    def regex_adder(self, curr_filter, regex_added):
        """
            It updates the current filter if it is needed.

            If the regex was not already checked, then:
                If the current filter is "literal" update it to "regex".
                Else, append "-regex" to the current filter.

            Args:
                curr_filter: The current filter.
                regex_added: A boolean that indicates if the regex was already
                             checked.
        """

        if not regex_added:
            regex_added = True  # useless to put it at True because we don't return it
            if self.filter == "literal":
                curr_filter = "regex"
            else:
                curr_filter += "-regex"
        return curr_filter

    def _identify_subpath_and_filter(self, ret_str):
        """
            For a given string, it checks if the instance's filter is a literal
            or not. If it is a literal, then the current filter should be
            updated to "regex". Also, it calls identify subpath to update the
            argument and filter.

            Args:
                ret_str: A string.
            Returns:
                A string with updated filter and argument.
        """
        for arg in self.argument:
            curr_filter = self.filter
            regex_added = False
            if len(arg) == 0:
                arg = ".+"
                curr_filter = self.regex_adder(curr_filter, regex_added)

            else:
                arg, curr_filter = self._identify_subpath(arg, curr_filter)

            if "regex" in curr_filter:
                ret_str += '(%04x, %04x) (%s #"%s")\n' % (self.match_offset,
                                                          self.unmatch_offset,
                                                          curr_filter, arg)
            else:
                ret_str += '(%s "%s")\n' % (curr_filter, arg)
        if len(self.argument) == 1:
            ret_str = ret_str[:-1]  # supress the last character which is the "\n"
        else:
            ret_str = ret_str[:-1] + ")"
        return ret_str

    def _single_argument_regex(self, arg, curr_filter):
        """
            For a single argument (not a list) updates the argument and filter.

            It checks if the argument contains '\\' or '|' or '[' or ']' or
            '+'. If so, then check the instance's filter and update the current
             filter accordingly.

            Args:
                arg: A singular argument.
                curr_filter: The filter that should be updated.
            Returns:
                The updated argument and filter.
        """

        if "regex" not in curr_filter:
            if '\\' in arg or '|' in arg or ('[' in arg and ']' in arg) or '+' in arg:
                if self.filter == "literal":
                    curr_filter = "regex"
                else:
                    curr_filter += "-regex"
                arg = arg.replace('\\\\.', '[.]')
                arg = arg.replace('\\.', '[.]')
        return arg, curr_filter

    def _str_initializer(self):
        """
            For a list it initializes the string.

            Returns:
                A string initialised with "(require-any " if the argument
                is multiple.
        """

        if len(self.argument) == 1:
            ret_str = ""
        else:
            ret_str = "(require-any "
        return ret_str

    def str_debug(self):
        """
            Updates the return string and the filter.

            Returns:
                Modulo between (%02x %04x %04x %04x) and NonTerminalNode's
                 fields.
        """

        if not self.filter:
            return "(%02x %04x %04x %04x)" % (self.filter_id,
                                              self.argument_id,
                                              self.match_offset,
                                              self.unmatch_offset)

        if self.argument:

            self.argument = self.simplify_list(self.argument)  # so self.argument is necessarily a list ?
            if type(self.argument) is list:
                ret_str = self._str_initializer()
                ret_str = self._identify_subpath_and_filter(ret_str)
                return ret_str

            arg = self.argument
            curr_filter = self.filter
            arg, curr_filter = self._single_argument_regex(arg, curr_filter)
            prefix_added = False
            self._prefix_adder(curr_filter, prefix_added, arg)  # MUST return curr_filter ?!

            return "(%04x, %04x) (%s %s)" % (self.match_offset, self.unmatch_offset, curr_filter, arg)
        else:
            return "(%04x, %04x) (%s)" % (self.match_offset, self.unmatch_offset, self.filter)

    def _filter_accumulator(self, s):
        """
            Updates the string and calls all the filters identifiers.

            Args:
                s: The string to be updated.

            Returns:
                The updated filter and the updated string.
        """

        curr_filter = self.filter
        regex_added = False
        prefix_added = False
        if len(s) == 0:
            s = ".+"
            curr_filter = self.regex_adder(curr_filter, regex_added)
        else:
            curr_filter, s = self._cur_filter_identifier(curr_filter, s)
            curr_filter = self._prefix_adder(curr_filter, prefix_added, s)
        return curr_filter, s

    def _str__(self):
        """
            Returns the string representation of the node.

            First, it updates the current filter.

            If it not a list then it just identifies the regex and adds the
            prefix.

            If it is a list, then it initalizes the string, it computes the
            current filter and if it is regex, it appends to the string.

            Returns:
                The string representation of the node.
        """

        if not self.filter:
            return "(%02x %04x %04x %04x)" % (self.filter_id,
                                              self.argument_id,
                                              self.match_offset,
                                              self.unmatch_offset)
        if not self.argument:
            return "(%s)" % self.filter

        if type(self.argument) is not list:
            s = self.argument
            curr_filter = self.filter
            curr_filter, s = self._not_regex(curr_filter, s)
            prefix_added = False
            self._prefix_adder(curr_filter, prefix_added, s)
            return "(%s %s)" % (curr_filter, s)

        self.argument = self.simplify_list(self.argument)
        ret_str = self._str_initializer()

        for s in self.argument:
            curr_filter, s = self._filter_accumulator(s)
            if "regex" in curr_filter:
                ret_str += '(%s #"%s")\n' % (curr_filter, s)
            else:
                ret_str += '(%s "%s")\n' % (curr_filter, s)

        if len(self.argument) == 1:
            ret_str = ret_str[:-1]
        else:
            ret_str = ret_str[:-1] + ")"
        return ret_str

    def str_not(self):
        """
            Works similar to __str__, but for what is not required.

            Returns:
                A string that shows what is not required.

        """
        if not self.filter:
            return "(%02x %04x %04x %04x)" % (self.filter_id,
                                              self.argument_id,
                                              self.match_offset,
                                              self.unmatch_offset)

        if not self.argument:
            return "(%s)" % self.filter

        if type(self.argument) is list:
            if len(self.argument) == 1:
                ret_str = ""
            else:
                self.argument = self.simplify_list(self.argument)  # if it is not a list so simplify_list is useless
                if len(self.argument) == 1:  # we need a list here
                    ret_str = ""
                else:
                    ret_str = "(require-all "

            for s in self.argument:  # so it must be list
                curr_filter, s = self.__filter_accumulator(s)
                if "regex" in curr_filter:
                    ret_str += '(require-not (%s #"%s"))\n' % \
                               (curr_filter, s)
                else:
                    ret_str += '(require-not (%s "%s"))\n' % (curr_filter, s)
            if len(self.argument) == 1:
                ret_str = ret_str[:-1]
            else:
                ret_str = ret_str[:-1] + ")"
            return ret_str

    def cor_str_not(self):
        """
            Attempt of correction of the function 'str_not(self)'

        """
        if not self.filter:
            return "(%02x %04x %04x %04x)" % (self.filter_id,
                                              self.argument_id,
                                              self.match_offset,
                                              self.unmatch_offset)

        if not self.argument:
            return "(%s)" % self.filter

        ret_str = ""
        if type(self.argument) is not list:
            if len(self.argument) == 1:
                ret_str = ""
            return ret_str
        else:
            self.argument = self.simplify_list(self.argument)
            if len(self.argument) == 1:
                ret_str = ""
            else:
                ret_str = "(require-all "
            for s in self.argument:
                curr_filter, s = self._filter_accumulator(s)
                if "regex" in curr_filter:
                    ret_str += '(require-not (%s #"%s"))\n' % \
                               (curr_filter, s)
                else:
                    ret_str += '(require-not (%s "%s"))\n' % (curr_filter, s)
            if len(self.argument) == 1:
                ret_str = ret_str[:-1]
            else:
                ret_str = ret_str[:-1] + ")"
            return ret_str

    def values(self):
        if self.filter:
            return self.filter, self.argument
        return "%02x" % self.filter_id, "%04x" % self.argument_id

    def is_entitlement_start(self):
        return self.filter_id == 0x1e or self.filter_id == 0xa0

    def is_entitlement(self):
        return self.filter_id == 0x1e or self.filter_id == 0x1f or self.filter_id == 0x20 or self.filter_id == 0xa0

    def is_last_regular_expression(self):
        return self.filter_id == 0x81 and self.argument_id == num_regex - 1  # num_regex is not defined

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