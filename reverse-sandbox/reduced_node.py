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