import logging
import struct

logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)

def parse_character(re, i, regex_list):
    value = chr(re[i+1])
    if value == ".":
        value = "[.]"
    regex_list.append({
        "pos": i-6,
        "nextpos": i+2-6,
        "type": "character",
        "value": value}
        )
    return i + 1

def parse_beginning_of_line(i, regex_list):
    regex_list.append({
        "pos": i-6,
        "nextpos": i+1-6,
        "type": "character",
        "value": "^"}
        )

def parse_end_of_line(i, regex_list):
    regex_list.append({
        "pos": i-6,
        "nextpos": i+1-6,
        "type": "character",
        "value": "$"}
        )

def parse_any_character(i, regex_list):
    regex_list.append({
        "pos": i-6,
        "nextpos": i+1-6,
        "type": "character",
        "value": "."}
        )

def parse_jump_forward(re, i, regex_list):
    jump_to = re[i+1] + (re[i+2] << 8)
    regex_list.append({
        "pos": i-6,
        "nextpos": i+3-6,
        "type": "jump_forward",
        "value": jump_to}
        )
    return i + 2

def parse_jump_backward(re, i, regex_list):
    jump_to = re[i+1] + (re[i+2] << 8)
    regex_list.append({
        "pos": i-6,
        "nextpos": i+3-6,
        "type": "jump_backward",
        "value": jump_to}
        )
    logger.debug("(0xa) i: %d (0x%x), re[i, i+1, i+2]: 0x%x, 0x%x, 0x%x", i, i, re[i], re[i+1], re[i+2])
    logger.debug("value: 0x%x", jump_to)
    return i+2

def parse_character_class(re, i, regex_list):
    num = (re[i] >> 4)
    i = i+1
    logger.debug("i: %d, num: %d", i, num)
    values = []
    value = "["
    for j in range(0, num):
        values.append(re[i+2*j])
        values.append(re[i+2*j+1])
    first = values[0]
    last = values[2*num-1]
    # In case of excludes.
    if (first > last):
        node_type = "class_exclude"
        value += "^"
        for j in range(len(values)-1, 0, -1):
            values[j] = values[j-1]
        values[0] = last
        for j in range(0, len(values)):
            if j % 2 == 0:
                values[j] = values[j]+1
            else:
                values[j] = values[j]-1
    else:
        node_type = "class"
    for j in range(0, len(values), 2):
        if values[j] < values[j+1]:
            value += "%s-%s" % (chr(values[j]), chr(values[j+1]))
        else:
            value += "%s" % (chr(values[j]))
    value += "]"
    regex_list.append({
        "pos": i-6-1,
        "nextpos": i + 2 * num - 6,
        "type": node_type,
        "value": value
        })
    message = "values: [", ", ".join([hex(j) for j in values]), "]"
    logger.debug(message)

    return i + 2 * num - 1

def parse_end(re, i, regex_list):
    regex_list.append({
        "pos": i-6,
        "nextpos": i+2-6,
        "type": "end",
        "value": 0
        })
    return i + 1

def parse(re, i, regex_list):
    # Actual character.
    if re[i] == 0x02:
        i = parse_character(re, i, regex_list)
    # Beginning of line.
    elif re[i] == 0x19:
        parse_beginning_of_line(i, regex_list)
    # End of line.
    elif re[i] == 0x29:
        parse_end_of_line(i, regex_list)
    # Any character.
    elif re[i] == 0x09:
        parse_any_character(i, regex_list)
    # Jump forward.
    elif re[i] == 0x2f:
        i = parse_jump_forward(re, i, regex_list)
    # Jump backward.
    elif re[i] & 0xf == 0xa:
        i = parse_jump_backward(re, i, regex_list)
    # Character class.
    elif re[i] & 0xf == 0xb:
        i = parse_character_class(re, i, regex_list)
    elif re[i] & 0xf == 0x5:
        i = parse_end(re, i, regex_list)
    else:
        logger.warning("##########unknown", hex(re[i]))

    return i + 1

class RegexParser(object):

    @staticmethod
    def parse(re, i, regex_list):
        length = struct.unpack('<H', ''.join([chr(x) for x in re[i:i+2]]))[0]
        logger.debug("re.length: 0x%x", length)
        i += 2
        assert(length == len(re)-i)
        while i < len(re):
            i = parse(re, i, regex_list)

        regex_list[0]["start_node"]=True

