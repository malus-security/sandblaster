import sys
import struct
import logging
import time


logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)


class ReverseStringState:
    binary_string = ""
    len = 0
    pos = 0
    base = ""
    base_stack = []
    token = ""
    token_stack = []
    output_strings = []
    STATE_UNKNOWN = 0
    STATE_TOKEN_BYTE_READ = 1
    STATE_CONCAT_BYTE_READ = 2
    STATE_CONCAT_SAVE_BYTE_READ = 3
    STATE_END_BYTE_READ = 4
    STATE_SPLIT_BYTE_READ = 5
    STATE_TOKEN_READ = 6
    STATE_RANGE_BYTE_READ = 7
    STATE_CONSTANT_READ = 8
    STATE_SINGLE_BYTE_READ = 9
    STATE_PLUS_READ = 10
    STATE_RESET_STRING = 11
    state_stack = []
    state = STATE_UNKNOWN
    state_byte = 0x00

    def __init__(self, binary_string):
        self.binary_string = binary_string
        self.len = 0
        self.pos = 0
        self.base = ""
        self.token = ""
        self.tokens = []
        self.token_stack = []
        self.base_stack = []
        self.output_strings = []
        self.state_stack = []
        self.state = self.STATE_UNKNOWN
        self.state_byte = 0x00

    def update_state_unknown(self):
        self.state_stack.append(self.state)
        self.state = self.STATE_UNKNOWN

    def update_state_token_byte_read(self):
        self.state_stack.append(self.state)
        self.state = self.STATE_TOKEN_BYTE_READ

    def update_state_concat_byte_read(self):
        self.state_stack.append(self.state)
        self.state = self.STATE_CONCAT_BYTE_READ

    def update_state_concat_save_byte_read(self):
        self.state_stack.append(self.state)
        self.state = self.STATE_CONCAT_SAVE_BYTE_READ

    def update_state_end_byte_read(self):
        self.state_stack.append(self.state)
        self.state = self.STATE_END_BYTE_READ

    def update_state_split_byte_read(self):
        self.state_stack.append(self.state)
        self.state = self.STATE_SPLIT_BYTE_READ

    def update_state_range_byte_read(self):
        self.state_stack.append(self.state)
        self.state = self.STATE_RANGE_BYTE_READ

    def update_state_token_read(self):
        self.state_stack.append(self.state)
        self.state = self.STATE_TOKEN_READ

    def update_state_reset_string(self):
        self.state_stack.append(self.state)
        self.state = self.STATE_RESET_STRING

    def update_state_constant_read(self):
        self.state_stack.append(self.state)
        self.state = self.STATE_CONSTANT_READ

    def update_state_single_byte_read(self):
        self.state_stack.append(self.state)
        self.state = self.STATE_SINGLE_BYTE_READ

    def update_state_plus_read(self):
        self.state_stack.append(self.state)
        self.state = self.STATE_PLUS_READ

    def update_state(self, b):
        self.state_byte = b
        if b == 0x0a:
            self.update_state_end_byte_read()
        elif b == 0x0f:
            self.update_state_concat_byte_read()
        elif b >= 0x80:
            self.update_state_split_byte_read()
        elif b == 0x00 or b == 0x07:
            self.update_state_unknown()
        elif b == 0x05:
            self.update_state_reset_string()
        elif b == 0x08:
            self.update_state_concat_save_byte_read()
            # XXX: Read two bytes. I don't know what they do.
            self.get_next_byte()
            self.get_next_byte()
        elif b >= 0x10 and b < 0x3f:
            self.update_state_constant_read()
        elif b == 0x0b:
            self.update_state_range_byte_read()
        elif b == 0x02:
            self.update_state_plus_read()
        elif b == 0x06:
            self.update_state_reset_string()
        else:
            self.update_state_token_byte_read()

    def get_next_byte(self):
        if self.is_end():
            return 0x00
        b = struct.unpack("<B", self.binary_string[self.pos:self.pos+1])[0]
        logger.debug("read byte 0x{:02x}".format(b))
        self.pos += 1
        return b

    def get_length_minus_1(self):
        b = struct.unpack("<B", self.binary_string[self.pos-1:self.pos])[0]
        logger.debug("b is 0x{:02x} ({:d})".format(b, b))
        if b == 0x04:
            b = struct.unpack("<B", self.binary_string[self.pos:self.pos+1])[0]
            logger.debug("got larger length 0x{:02x} ({:d})".format(b, b))
            self.pos += 1
            return b + 0x41
        else:
            logger.debug("got length 0x{:02x} ({:d})".format(b, b))
            return b - 0x3f

    def read_token(self, substr_len):
        self.token_stack.append(self.token)
        self.token = self.binary_string[self.pos:self.pos+substr_len]
        logger.debug("got token \"{:s}\"".format(self.token))
        self.pos += substr_len

    def update_base(self):
        self.base += self.token
        self.token = ""
        logger.debug("update base to \"{:s}\"".format(self.base))

    def update_base_stack(self):
        self.base_stack.append(self.base)
        self.update_base()

    def end_current_token(self):
        self.output_strings.append(self.base+self.token)
        logger.debug("output string \"{:s}\"".format(self.base+self.token))
        self.token = ""

    def get_last_byte(self):
        return struct.unpack("<B", self.binary_string[self.pos-1:self.pos])[0]

    def get_substring(self, substr_len):
        substr = self.binary_string[self.pos:self.pos+substr_len]
        logger.debug(" ".join("0x{:02x}".format(ord(c)) for c in substr))
        self.pos += substr_len
        return substr

    def end_with_subtokens(self, subtokens):
        for s in subtokens:
            self.output_strings.append(self.base+self.token+s)
            logger.debug("output string with subtokens \"{:s}\"".format(self.base+self.token+s))
        self.token = ""

    def is_end(self):
        if self.pos >= len(self.binary_string):
            return True
        return False

    def reset_base(self):
        if len(self.base_stack) >= 1:
            self.base = self.base_stack.pop()

    def reset_base_full(self):
        self.base_stack = []
        self.base = ""


class SandboxString:
    rss_stack = []


    def parse_byte_string(self, s, global_vars):
        rss = ReverseStringState(s)
        base = ""
        reset_base = False
        tokens = []
        token = ""

        while True:
            if rss.state == rss.STATE_UNKNOWN:
                logger.debug("state is STATE_UNKNOWN")
                b = rss.get_next_byte()
                rss.update_state(b)
            elif rss.state == rss.STATE_TOKEN_READ:
                logger.debug("state is STATE_TOKEN_READ")
                b = rss.get_next_byte()
                rss.update_state(b)
            elif rss.state == rss.STATE_TOKEN_BYTE_READ:
                logger.debug("state is STATE_TOKEN_BYTE_READ")
                # String starts with length.
                prev_state = rss.state_stack[len(rss.state_stack)-1]
                if prev_state != rss.STATE_TOKEN_READ:
                    token_len = rss.get_length_minus_1()
                    rss.read_token(token_len)
                    rss.update_state_token_read()
                else:
                    logger.warn("read token byte from token state")
                    break
            elif rss.state == rss.STATE_CONSTANT_READ:
                logger.debug("state is STATE_CONSTANT_READ")
                b = rss.get_last_byte()
                if b >= 0x10 and b < 0x3f:
                    rss.token = "${" + global_vars[b-0x10] + "}"
                b = rss.get_next_byte()
                rss.update_state(b)
            elif rss.state == rss.STATE_CONCAT_BYTE_READ:
                logger.debug("state is STATE_CONCAT_BYTE_READ")
                if rss.state_stack[len(rss.state_stack)-1] == rss.STATE_TOKEN_READ or \
                        rss.state_stack[len(rss.state_stack)-1] == rss.STATE_CONSTANT_READ or \
                        rss.state_stack[len(rss.state_stack)-1] == rss.STATE_RANGE_BYTE_READ or \
                        rss.state_stack[len(rss.state_stack)-1] == rss.STATE_SINGLE_BYTE_READ or \
                        rss.state_stack[len(rss.state_stack)-1] == rss.STATE_PLUS_READ:
                    rss.update_base()
                b = rss.get_next_byte()
                rss.update_state(b)
            elif rss.state == rss.STATE_CONCAT_SAVE_BYTE_READ:
                logger.debug("state is STATE_CONCAT_SAVE_BYTE_READ")
                if rss.state_stack[len(rss.state_stack)-1] == rss.STATE_TOKEN_READ or \
                        rss.state_stack[len(rss.state_stack)-1] == rss.STATE_CONSTANT_READ or \
                        rss.state_stack[len(rss.state_stack)-1] == rss.STATE_RANGE_BYTE_READ or \
                        rss.state_stack[len(rss.state_stack)-1] == rss.STATE_SINGLE_BYTE_READ or \
                        rss.state_stack[len(rss.state_stack)-1] == rss.STATE_PLUS_READ:
                    rss.update_base_stack()
                b = rss.get_next_byte()
                rss.update_state(b)
            elif rss.state == rss.STATE_END_BYTE_READ:
                logger.debug("state is STATE_END_BYTE_READ")
                rss.end_current_token()
                rss.reset_base()
                b = rss.get_next_byte()
                rss.update_state(b)
            elif rss.state == rss.STATE_RANGE_BYTE_READ:
                logger.debug("state is STATE_RANGE_BYTE_READ")
                rss.update_base_stack()
                b = rss.get_next_byte()
                b_array = []
                all_ascii = True
                token = ""
                for i in range(0, b+1):
                    b1 = rss.get_next_byte()
                    b2 = rss.get_next_byte()
                    if b1 < 0x20 or b1 > 0x7f or b2 < 0x20 or b2 > 0x7f:
                        all_ascii = False
                    b_array.append((b1,b2))
                if all_ascii == False:
                    (b1, b2) = b_array[0]
                    (b3, b4) = b_array[1]
                    if b2 == 0xff and b3 == 0x00:
                        if b1-1 == b4+1:    # single char exclude
                            token = "[^{:c}]".format(b1-1)
                        else:               # range exclude
                            token = "[^{:c}-{:c}]".format(b4+1, b1-1)
                    else:
                        token = "[TODO]"
                else:
                    token = "["
                    for (b1, b2) in b_array:
                        token += "{:c}-{:c}".format(b1, b2)
                    token += "]"
                rss.token = token
                b = rss.get_next_byte()
                rss.update_state(b)
            elif rss.state == rss.STATE_SPLIT_BYTE_READ:
                logger.debug("state is STATE_SPLIT_BYTE_READ")
                substr_len = rss.get_last_byte() - 0x7f
                substr = rss.get_substring(substr_len)
                subtokens = self.parse_byte_string(substr, global_vars)
                rss.end_with_subtokens(subtokens)
                b = rss.get_next_byte()
                rss.update_state(b)
            elif rss.state == rss.STATE_SINGLE_BYTE_READ:
                logger.debug("state is STATE_SINGLE_BYTE_READ")
                rss.read_token(1)
                b = rss.get_next_byte()
                rss.update_state(b)
            elif rss.state == rss.STATE_RESET_STRING:
                logger.debug("state is STATE_RESET_STRING")
                rss.end_current_token()
                rss.reset_base_full()
                b = rss.get_next_byte()
                rss.update_state(b)
            elif rss.state == rss.STATE_PLUS_READ:
                logger.debug("state is STATE_PLUS_READ")
                if rss.state_stack[len(rss.state_stack)-1] == rss.STATE_CONCAT_BYTE_READ:
                    rss.token = "+"
                    rss.update_base()
                else:
                    logger.warn("previous state is not concat")
                rss.read_token(1)
                b = rss.get_next_byte()
                rss.update_state(b)
            else:
                logger.warn("unknown state ({:d})".format(rss.state))
                break

            if rss.is_end():
                break

        # String must end in a STATE_END_BYTE_READ byte.
        if rss.state == rss.STATE_END_BYTE_READ:
            logger.debug("state is STATE_END_BYTE_READ")
            rss.end_current_token()
        elif rss.state == rss.STATE_UNKNOWN or rss.state == rss.STATE_CONCAT_BYTE_READ:
            pass
        elif rss.state_stack[len(rss.state_stack)-1] == rss.STATE_END_BYTE_READ:
            pass
        else:
            logger.warn("last state is not STATE_END_BYTE_READ ({:d})".format(rss.state))
            logger.warn("previous state ({:d})".format(rss.state_stack[len(rss.state_stack)-1]))

        logger.info("initial string: " + " ".join("0x{:02x}".format(ord(c)) for c in s))
        logger.info("output_strings (num: {:d}): {:s}".format(len(rss.output_strings), ",".join('"{:s}"'.format(s) for s in rss.output_strings)))
        return rss.output_strings


    def __init__(self):
        self.rss_stack = []


def main():
    s = sys.stdin.read()
    ss = SandboxString()
    my_global_vars = ["FRONT_USER_HOME", "HOME", "PROCESS_TEMP_DIR"]
    l = ss.parse_byte_string(s[4:], my_global_vars)
    print(list(set(l)))


if __name__ == "__main__":
    sys.exit(main())
