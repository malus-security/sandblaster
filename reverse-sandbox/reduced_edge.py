class ReducedEdge:
    start = None
    end = None

    def __init__(self, start=None, end=None):
        self.start = start
        self.end = end

    def str_debug(self):
        return self.start.str_debug() + " -> " + self.end.str_debug()

    def str_simple(self):
        return "%s -----> %s" % (self.start.str_simple(), self.end.str_simple())

    def __str__(self):
        return str(self.start) + " -> " + str(self.end)
