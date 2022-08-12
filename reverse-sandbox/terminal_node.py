class TerminalNode():
    """Allow or Deny end node in binary sandbox format.

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