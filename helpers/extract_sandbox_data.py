#!/usr/bin/env python3

import sys
import argparse
import struct
import lief

CSTRING_SECTION = '__cstring'
CONST_SECTION = '__const'
DATA_SECTION = '__data'

def get_cstring_section(binary):
    seg = binary.get_segment('__TEXT')
    if seg:
        sects = [s for s in seg.sections if s.name == CSTRING_SECTION]
        assert(len(sects) == 1)
        return sects[0]
    return binary.get_section(CSTRING_SECTION)

def get_tables_section(binary):
    str_sect = get_cstring_section(binary)
    strs = str_sect.search_all('default')
    assert(len(strs) == 1)
    vaddr_str = str_sect.virtual_address + strs[0]
    xref_vaddr = binary.xref(vaddr_str)
    if len(xref_vaddr) > 0:
        sect = binary.section_from_virtual_address(xref_vaddr[0])
        return sect
    seg = binary.get_segment('__DATA')
    if seg:
        sects = [s for s in seg.sections if s.name == CONST_SECTION]
        assert(len(sects) <= 1)
        if len(sects) == 1:
            return sects[0]
    return binary.get_section(CONST_SECTION)

def get_data_section(binary):
    seg = binary.get_segment('__DATA')
    if seg:
        sects = [s for s in seg.sections if s.name == DATA_SECTION]
        assert(len(sects) == 1)
        return sects[0]
    return binary.get_section(DATA_SECTION)


def is_vaddr_in_section(vaddr, section):
    return vaddr >= section.virtual_address \
        and vaddr < section.virtual_address + section.size

def get_string(binary, vaddr):
    section = get_cstring_section(binary)

    s = ''
    while True:
        if not is_vaddr_in_section(vaddr, section):
            return None
        byte = binary.get_content_from_virtual_address(vaddr, 1)[0]
        if byte == None or byte == 0:
            break
        vaddr += 1
        s += chr(byte)
    return s

def get_addr_size(binary):
    assert(binary.header.magic in
        [lief.MachO.MACHO_TYPES.MAGIC, lief.MachO.MACHO_TYPES.MAGIC_64])
    return 4 if binary.header.magic == lief.MachO.MACHO_TYPES.MAGIC else 8

def unpack(bytes_list):
    return struct.unpack('<I' if len(bytes_list) == 4 else '<Q',
        bytes(bytes_list))[0]

def extract_data_tables_from_section(binary, to_data, section):
    addr_size = get_addr_size(binary)
    startaddr = section.virtual_address
    endaddr = section.virtual_address + section.size
    tables = []
    vaddr = startaddr
    while vaddr <= endaddr - addr_size:
        ptr = unpack(
            binary.get_content_from_virtual_address(vaddr, addr_size))
        data = to_data(binary, ptr)
        if data == None:
            vaddr += addr_size
            continue
        table = [data]
        vaddr += addr_size
        while vaddr <= endaddr - addr_size:
            ptr = unpack(
                binary.get_content_from_virtual_address(vaddr, addr_size))
            data = to_data(binary, ptr)
            if data == None:
                break
            table.append(data)
            vaddr += addr_size
        if table not in tables:
            tables.append(table)
        vaddr += addr_size
    return tables

def extract_string_tables(binary):
    return extract_data_tables_from_section(binary,
        get_string, get_tables_section(binary))

def extract_profiles(binary, string_tables):
    def get_profile_names():
        def transform(v):
            if len(v) <= 3:
                return None
            r = []
            tmp =[]
            for val in v:
                if val in ['default', '0123456789abcdef']:
                    r.append(tmp)
                    tmp = []
                else:
                    tmp.append(val)
            r.append(tmp)
            return r
        def get_sol(posible):
            r = [v for v in posible
                if 'com.apple.sandboxd' in v ]
            assert(len(r) == 1)
            return r[0]

        profile_names_v = [transform(v) for v in string_tables]
        profile_names_v = [v for v in profile_names_v if v != None]
        profile_names_v = [x for v in profile_names_v for x in v]
        return get_sol(profile_names_v)

    def get_profile_contents():
        def get_profile_content(binary, vaddr):
            addr_size = get_addr_size(binary)
            section = get_data_section(binary)
            if not is_vaddr_in_section(vaddr, section):
                return None
            data = binary.get_content_from_virtual_address(vaddr, 2*addr_size)
            if len(data) != 2*addr_size:
                return None
            data_vaddr = unpack(data[:addr_size])
            size = unpack(data[addr_size:])
            if not is_vaddr_in_section(vaddr, section):
                return None
            data = binary.get_content_from_virtual_address(data_vaddr, size)
            if len(data) != size:
                return None
            return bytes(data)
        contents_v = [v for v in extract_data_tables_from_section(binary, 
                get_profile_content, get_tables_section(binary))
            if len(v) > 3]
        assert(len(contents_v) == 1)
        return contents_v[0]

    profile_names = get_profile_names()
    profile_contents = get_profile_contents()
    print(len(profile_names),len(profile_contents))
    assert(len(profile_names) == len(profile_contents))
    return zip(profile_names, profile_contents)

def extract_sbops(binary, string_tables):
    def transform(v):
        if len(v) <= 3:
            return None
        idxs = []
        for idx,val in enumerate(v):
            if val == 'default':
                idxs.append(idx)
        return [v[idx:] for idx in idxs]

    def get_sol(posible):
        assert(len(posible) > 1)
        cnt = min(len(v) for v in posible)
        sol = []
        for vals in zip(*[v[:cnt] for v in posible]):
            if not all(v == vals[0] for v in vals):
                break
            sol.append(vals[0])
        return sol

    sbops_v = [transform(v) for v in string_tables]
    sbops_v = [v for v in sbops_v if v != None]
    sbops_v = [x for v in sbops_v for x in v]
    return get_sol(sbops_v)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Sandbox profiles and operations extraction tool(iOS <9)')
    parser.add_argument('binary', metavar='BINARY', type=lief.MachO.parse,
        help='path to sandboxd(iOS 5-8)/sandbox exenstion(iOS 4)/' +
        'seatbelt extension(iOS 2-3)')
    parser.add_argument('-o','--output-sbops', dest='sbops_file', type=str,
        default=None,
        help='path to sandbox profile operations store file')
    parser.add_argument('-O','--output-profiles', dest='sbs_dir', type=str,
        default=None,
        help='path to directory in which sandbox profiles should be stored')

    args = parser.parse_args()
    if type(args.binary) == lief.MachO.FatBinary:
        assert(args.binary.size == 1)
        binary = args.binary.at(0)
    else:
        binary = args.binary

    string_tables = extract_string_tables(binary)
    if args.sbops_file != None:
        sbops = extract_sbops(binary, string_tables)
        sbops_str = '\n'.join(sbops)
        if args.sbops_file == '-':
            print(sbops_str)
        else:
            try:
                with open(args.sbops_file, 'w') as f:
                    f.write(sbops_str+'\n')
            except IOError as e:
                retcode = e.errno
                print(e, file=sys.stderr)
    if args.sbs_dir != None:
        profiles = extract_profiles(binary, string_tables)
        for name, content in profiles:
            try:
                with open(args.sbs_dir + '/' + name + '.sb.bin', 'wb') as f:
                    f.write(content)
            except IOError as e:
                retcode = e.errno
                print(e, file=sys.stderr)

