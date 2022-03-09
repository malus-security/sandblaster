import logging
import struct

logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)

def parse_character(node_type, node_arg, node_transition, node_idx):
    value = chr(node_arg & 0xff)
    if value == ".":
        value = "[.]"
    return {
        "pos": node_idx,
        "nextpos": node_transition,
        "type": "character",
        "value": value}

def parse_end(node_type, node_arg, node_transition, node_idx):
    return {
        "pos": node_idx,
        "nextpos": node_transition,
        "type": "end",
        "value": 0}

def parse_jump_forward(node_type, node_arg, node_transition, node_idx):
    jump_to = node_arg
    return {
        "pos": node_idx,
        "nextpos": node_transition,
        "type": "jump_forward",
        "value": jump_to}

def parse_jump_backward(node_type, node_arg, node_transition, node_idx):
    jump_to = node_transition
    return {
        "pos": node_idx,
        "nextpos": node_transition,
        "type": "jump_backward",
        "value": jump_to}

def parse_beginning_of_line(node_type, node_arg, node_transition, node_idx):
    return {
        "pos": node_idx,
        "nextpos": node_transition,
        "type": "character",
        "value": "^"}

def parse_end_of_line(node_type, node_arg, node_transition, node_idx):
    return {
        "pos": node_idx,
        "nextpos": node_transition,
        "type": "character",
        "value": "$"}

def parse_dot(node_type, node_arg, node_transition, node_idx):
    return {
        "pos": node_idx,
        "nextpos": node_transition,
        "type": "character",
        "value": "."}

def parse_character_class(node_type, node_arg, node_transition, node_idx):
    return {
        "pos": node_idx,
        "nextpos": node_transition,
        "type": "class",
        "value": node_arg}

def parse_character_neg_class(node_type, node_arg, node_transition, node_idx):
    return {
        "pos": node_idx,
        "nextpos": node_transition,
        "type": "class_exclude",
        "value": node_arg}

def parse_parantheses_open(node_type, node_arg, node_transition, node_idx):
    return parse_jump_backward(node_type, node_arg, node_transition,
        node_idx)
    '''
    return {
        "pos": node_idx,
        "nextpos": node_transition,
        "type": "character",
        "value": "("}
    '''

def parse_parantheses_close(node_type, node_arg, node_transition, node_idx):
    return parse_jump_backward(node_type, node_arg, node_transition,
        node_idx)
    '''
    return {
        "pos": node_idx,
        "nextpos": node_transition,
        "type": "character",
        "value": ")"}
    '''

node_type_dispatch_table = {
  0x10: parse_character,
  0x22: parse_end,
  0x23: parse_parantheses_close,
  0x24: parse_parantheses_open,
  0x25: parse_jump_forward,
  0x30: parse_dot,
  0x31: parse_jump_backward,
  0x32: parse_beginning_of_line,
  0x33: parse_end_of_line,
  0x34: parse_character_class,
  0x35: parse_character_neg_class,
}


def node_parse(re, i, regex_list, node_idx):
    node_type = struct.unpack('>I',
        ''.join([chr(x) for x in re[i:i+4]]))[0]
    node_transition = struct.unpack('>I',
        ''.join([chr(x) for x in re[i+4:i+8]]))[0]
    node_arg = struct.unpack('>I',
        ''.join([chr(x) for x in re[i+8:i+12]]))[0]
    i += 12

    logger.debug('node idx:{:#010x} type: {:#02x} arg: {:#010x}' \
        ' transition: {:#010x}'.format(node_idx, node_type,node_arg,
            node_transition))
    assert(node_type in node_type_dispatch_table)
    regex_list.append(
        node_type_dispatch_table[node_type](
            node_type, node_arg, node_transition, node_idx))
    return i

def class_parse(re, i, classes, class_idx):
    def transform(x):
        c = chr(x)
        if c in '[]-':
            return '\\' + c
        else:
            return c

    class_size = struct.unpack('>I',
        ''.join([chr(x) for x in re[i:i+4]]))[0]
    i += 0x4
    content = struct.unpack('>{}I'.format(class_size),
        ''.join([chr(x) for x in re[i:i+4*class_size]]))
    i += 0x4 * class_size
    assert(class_size % 2 == 0)

    cls = ''
    for idx in range(0, class_size, 2):
        start = content[idx]
        end = content[idx+1]
        if start != end:
            cls += '{}-{}'.format(transform(start), transform(end))
        else:
            cls += transform(start)

    logger.debug('class idx = {:#x} size = {:#x} content=[{}]'.format(
        class_idx, class_size, cls))
    classes.append(cls)
    return i

class RegexParser(object):

    @staticmethod
    def parse(re, i, regex_list):
        node_count = struct.unpack('>I',
            ''.join([chr(x) for x in re[i:i+0x4]]))[0]
        logger.debug('node count = {:#x}'.format(node_count))

        start_node = struct.unpack('>I',
            ''.join([chr(x) for x in re[i+0x4:i+0x8]]))[0]
        logger.debug('start node = {:#x}'.format(start_node))

        end_node = struct.unpack('>I',
            ''.join([chr(x) for x in re[i+0x8:i+0xC]]))[0]
        logger.debug('end node = {:#x}'.format(end_node))

        cclass_count = struct.unpack('>I',
            ''.join([chr(x) for x in re[i+0xC:i+0x10]]))[0]
        logger.debug('character class count = {:#x}'.format(cclass_count))

        submatch_count = struct.unpack('>I',
            ''.join([chr(x) for x in re[i+0x10:i+0x14]]))[0]
        i += 0x14
        logger.debug('submatch count = {:#x}'.format(submatch_count))


        for node_idx in range(node_count):
            i = node_parse(re, i, regex_list, node_idx)

        classes = []
        for class_idx in range(cclass_count):
            i = class_parse(re, i, classes, class_idx)

        for node in regex_list:
            if node['type'] == 'class':
                node['value'] = '[{}]'.format(classes[node['value']])
            elif node['type'] == 'class_exclude':
                node['value'] = '[{}]'.format(classes[node['value']])

        regex_list[start_node]['start_node'] = True

