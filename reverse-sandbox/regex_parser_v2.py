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
  0x25: parse_jump_forward,
  0x26: parse_jump_forward,
  0x27: parse_jump_forward,
  0x28: parse_jump_forward,
  0x30: parse_dot,
  0x31: parse_jump_backward,
  0x32: parse_beginning_of_line,
  0x33: parse_end_of_line,
  0x34: parse_character_class,
  0x35: parse_character_neg_class,
}


def node_parse(re, i, regex_list, node_idx):
    node_type = struct.unpack('<B',
        ''.join([chr(x) for x in re[i:i+1]]))[0]
    node_transition = struct.unpack('<H',
        ''.join([chr(x) for x in re[i+1:i+3]]))[0]
    pad = struct.unpack('<B',
        ''.join([chr(x) for x in re[i+3:i+4]]))[0]
    node_arg = struct.unpack('<I',
        ''.join([chr(x) for x in re[i+4:i+8]]))[0]
    i += 8

    logger.debug('node idx:{:#06x} type: {:#02x} arg: {:#010x}' \
        ' transition: {:#06x}'.format(node_idx, node_type,node_arg,
            node_transition))

    assert(pad == 0 or node_type == 0x22)
    assert(node_type in node_type_dispatch_table)
    regex_list.append(
        node_type_dispatch_table[node_type](
            node_type, node_arg, node_transition, node_idx))
    return i

def classes_parse(re, i, cclass_count):
    def transform(x):
        c = chr(x)
        if c in '[]-':
            return '\\' + c
        else:
            return c
    def transform_range(start, end):
        if start != end:
            return '{}-{}'.format(transform(start), transform(end))
        return transform(start)
    def transform_content(content):
        cls = ''
        assert(len(content) % 2 == 0)
        for idx in range(0, len(content), 2):
            start = content[idx]
            end = content[idx+1]
            cls += transform_range(start, end)
        return cls

    if cclass_count == 0:
        return

    classes_magic, classes_size = struct.unpack('<II',
        ''.join([chr(x) for x in re[i:i+8]]))
    i += 0x8
    logger.debug('classes magic = {:#x} size = {:#x}'.format(
        classes_magic, classes_size))
    assert(len(re) - i == classes_size)
    starts = struct.unpack('<{}I'.format(cclass_count),
        ''.join([chr(x) for x in re[i:i+4*cclass_count]]))
    i += 0x4 * cclass_count

    lens = struct.unpack('<{}B'.format(cclass_count),
        ''.join([chr(x) for x in re[i:i+cclass_count]]))
    i += cclass_count

    contents = [re[i+start:i+start+clen] for start, clen in zip(starts, lens)]
    return [transform_content(content) for content in contents]

class RegexParser(object):

    @staticmethod
    def parse(re, i, regex_list):
        magic = struct.unpack('<I',
            ''.join([chr(x) for x in re[i:i+0x4]]))[0]
        logger.debug('magic = {:#x}'.format(magic))

        node_count = struct.unpack('<I',
            ''.join([chr(x) for x in re[i+0x4:i+0x8]]))[0]
        logger.debug('node count = {:#x}'.format(node_count))

        start_node = struct.unpack('<I',
            ''.join([chr(x) for x in re[i+0x8:i+0xC]]))[0]
        logger.debug('start node = {:#x}'.format(start_node))

        end_node = struct.unpack('<I',
            ''.join([chr(x) for x in re[i+0xC:i+0x10]]))[0]
        logger.debug('end node = {:#x}'.format(end_node))

        cclass_count = struct.unpack('<I',
            ''.join([chr(x) for x in re[i+0x10:i+0x14]]))[0]
        logger.debug('character class count = {:#x}'.format(cclass_count))
        i += 0x14

        for node_idx in range(node_count):
            i = node_parse(re, i, regex_list, node_idx)

        classes = classes_parse(re, i, cclass_count)

        for node in regex_list:
            if node['type'] == 'class':
                node['value'] = '[{}]'.format(classes[node['value']])
            elif node['type'] == 'class_exclude':
                node['value'] = '[{}]'.format(classes[node['value']])

        regex_list[start_node]['start_node'] = True

