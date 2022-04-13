#!/usr/bin/env python3

import sys
import argparse
import struct
import lief

CSTRING_SECTION = '__cstring'
CONST_SECTION = '__const'
DATA_SECTION = '__data'


def binary_get_word_size(binary: lief.MachO.Binary):
    """Gets the word size of the given binary

    The Mach-O binary has 'magic' bytes. These bytes can be used for checking
    whether the binary is 32bit or 64bit.
    Note: iOS 4 and 5 are different to the other sandbox profiles as they have
    no magic values.

    Args:
        binary: A sandbox profile in its binary form.

    Returns:
        4: for 32bit MachO binaries
        8: for 64bit MachO binaries
    """

    assert (binary.header.magic in
            [lief.MachO.MACHO_TYPES.MAGIC, lief.MachO.MACHO_TYPES.MAGIC_64])

    return 4 if binary.header.magic == lief.MachO.MACHO_TYPES.MAGIC else 8


def unpack(bytes_list):
    """Unpacks bytes

    The information is stored as little endian so '<' is needed.
    For 32bit 'I' is needed and for 64bit 'Q'.

    Args:
        bytes_list: A packed list of bytes.

    Returns:
        The unpacked 'higher-order' equivalent.
    """

    if len(bytes_list) == 4:
        return struct.unpack('<I', bytes(bytes_list))[0]

    return struct.unpack('<Q', bytes(bytes_list))[0]


def binary_get_string_from_address(binary: lief.MachO.Binary, vaddr: int):
    """Returns the string from a given MachO binary at a given virtual address.

        Note: The virtual address must be in the CSTRING section.

        Args:
            binary: A sandbox profile in its binary form.
            vaddr: An address.

        Returns:
            A string with the content stored at the given virtual address.

        Raises:
            LIEF_ERR("Can't find a segment associated with the virtual address
             0x{:x}", address);
    """

    section = get_section_from_segment(binary, "__TEXT", CSTRING_SECTION)
    if not is_vaddr_in_section(vaddr, section):
        return None

    str = ''
    while True:
        try:
            byte = binary.get_content_from_virtual_address(vaddr, 1)
        except(Exception,):
            return None

        if byte is None or len(byte) == 0:
            return None

        byte = byte[0]
        if byte == 0:
            break

        vaddr += 1
        str += chr(byte)

    return str


def untag_pointer(tagged_pointer):
    """Returns the untagged pointer.

    On iOS 12 the first 16 bits(MSB) of a pointer are used to store extra
    information. We say that the pointers from iOS 12 are tagged.
    The pointers should have the 2 first bytes 0xffff, the next digits should
    be fff0 and the pointed-to values should be multiple of 4.
    More information can be found here:
    https://bazad.github.io/2018/06/ios-12-kernelcache-tagged-pointers/

    Args:
        tagged_pointer: a pointer with the first 16 bits used to store extra
                        information.

    Returns:
        A pointer with the 'tag' removed and starting with 0xffff
        (the traditional way).
    """

    return (tagged_pointer & ((1 << 48) -1)) | (0xffff << 48)


def get_section_from_segment(binary: lief.MachO.FatBinary,
                             segment_name: str, section_name: str):
    """This can be used for retrieving const, cstring and data sections.
    Const section contains two tables: one with the names of the sandbox
    profile and one with the content of the sandbox profile.
    This section is in the __DATA segment.

    Constant string section (cstring) contains the names of the profiles.
    This section is in the __TEXT segment.

    Data section contains the structures describing the content of the
    profiles and the content itself.
    This section is in the __DATA segment.

    Args:
        binary: A sandbox profile in its binary form.
        segment_name: The segment name (can be __DATA or __TEXT).
        section_name: The section name (can be CSTRING_SECTION, CONST_SECTION,
                      DATA_SECTION, all of them are macros)

    Returns:
        A binary section with the name given.
    """

    seg = binary.get_segment(segment_name)

    if seg:
        sects = [s for s in seg.sections if s.name == section_name]
        assert len(sects) == 1
        return sects[0]

    return None


def get_xref(binary: lief.MachO.Binary, vaddr: int):
    """Custom cross reference implementation which supports tagged pointers
    from iOS 12. Searches for pointers in the given MachO binary to the given
    virtual address.

    Args:
        binary: A sandbox profile in its binary form.
        vaddr: An address.

    Returns:
        A list with all the pointers to the given virtual address.
    """

    ans = []
    word_size = binary_get_word_size(binary)
    i = 0

    for sect in binary.sections:
        content = sect.content[:len(sect.content) - len(sect.content) % word_size]
        content = [unpack(content[i:i + word_size])
                   for i in range(0, len(content), word_size)]

        if word_size == 8:
            content = [untag_pointer(p) for p in content]

        ans.extend((sect.virtual_address + i * word_size
                    for i, p in enumerate(content) if p == vaddr))

    return ans


def get_tables_section(binary: lief.MachO.Binary):
    """Searches for the section containing the sandbox operations table and
    the sandbox binary profiles for older versions of iOS.

    Args:
        binary: A sandbox profile in its binary form.

    Returns:
        A binary section.
    """

    str_sect = get_section_from_segment(binary, "__TEXT", CSTRING_SECTION)
    strs = str_sect.search_all('default\x00')

    if len(strs) > 0:
        vaddr_str = str_sect.virtual_address + strs[0]
        xref_vaddrs = get_xref(binary, vaddr_str)

        if len(xref_vaddrs) > 0:
            sects = [binary.section_from_virtual_address(x) for x in xref_vaddrs]
            sects = [s for s in sects if 'const' in s.name.lower()]
            assert len(sects) >= 1 and all([sects[0] == s for s in sects])
            return sects[0]

    seg = binary.get_segment('__DATA')
    if seg:
        sects = [s for s in seg.sections if s.name == CONST_SECTION]
        assert len(sects) <= 1

        if len(sects) == 1:
            return sects[0]

    return binary.get_section(CONST_SECTION)


def is_vaddr_in_section(vaddr, section):
    """Checks if given virtual address is inside given section.

    Args:
        vaddr: A virtual address.
        section: A section of the binary.

    Returns:
        True: if the address is inside the section
        False: Otherwise
    """

    return vaddr >= section.virtual_address \
        and vaddr < section.virtual_address + section.size


def unpack_pointer(addr_size, binary, vaddr):
    """Unpacks a pointer and untags it if it is necessary.

    Args:
        binary: A sandbox profile in its binary form.
        vaddr: A virtual address.
        addr_size: The size of an address (4 or 8).

    Returns:
        A pointer.
    """

    ptr = unpack(
        binary.get_content_from_virtual_address(vaddr, addr_size))
    if addr_size == 8:
        ptr = untag_pointer(ptr)
    return ptr


def extract_data_tables_from_section(binary: lief.MachO.Binary, to_data, section):
    """ Generic implementation of table search. A table is formed of adjacent
    pointers to data.

    Args:
        binary: A sandbox profile in its binary form.
        to_data: Function that checks if the data is valid. This function
                 returns None for invalid data and anything else otherwise.
        section: A section of the binary.

    Returns:
            An array of tables (arrays of data).
    """

    addr_size = binary_get_word_size(binary)
    start_addr = section.virtual_address
    end_addr = section.virtual_address + section.size
    tables = []
    vaddr = start_addr

    while vaddr <= end_addr - addr_size:
        ptr = unpack_pointer(addr_size, binary, vaddr)

        data = to_data(binary, ptr)
        if data is None:
            vaddr += addr_size
            continue

        table = [data]
        vaddr += addr_size

        while vaddr <= end_addr - addr_size:
            ptr = unpack_pointer(addr_size, binary, vaddr)

            data = to_data(binary, ptr)
            if data is None:
                break

            table.append(data)
            vaddr += addr_size

        if table not in tables:
            tables.append(table)

        vaddr += addr_size

    return tables


def extract_string_tables(binary: lief.MachO.Binary):
    """Extracts string tables from the given MachO binary.

    Args:
        binary: A sandbox profile in its binary form.

    Returns:
        The string tables.
    """

    return extract_data_tables_from_section(binary,
                                            binary_get_string_from_address,
                                            get_tables_section(binary))


def extract_separated_profiles(binary, string_tables):
    """Extract separated profiles from given MachO binary. It requires all
    string tables. This function is intended to be used for older version
    of iOS(<=7) because in newer versions the sandbox profiles are bundled.

    Args:
        binary: A sandbox profile in its binary form.
        string_tables: The extracted string tables.

    Returns:
        A zip object with profiles.
    """

    def get_profile_names():
        """Extracts the profile names.

            Returns:
                A list with the names of the sandbox profiles.
        """

        def transform(arr):
            if len(arr) <= 3:
                return None

            ans = []
            tmp = []
            for val in arr:
                if val in ['default', '0123456789abcdef']:
                    ans.append(tmp)
                    tmp = []
                else:
                    tmp.append(val)
            ans.append(tmp)
            return ans

        def get_sol(posible):
            ans = [arr for arr in posible
                   if 'com.apple.sandboxd' in arr]
            assert len(ans) == 1
            return ans[0]

        profile_names_v = [transform(v) for v in string_tables]
        profile_names_v = [v for v in profile_names_v if v is not None]
        profile_names_v = [x for v in profile_names_v for x in v]
        return get_sol(profile_names_v)

    def get_profile_contents():
        """Extracts the profile names.

            Returns:
                 The contents of the sandbox profiles.
        """

        def get_profile_content(binary, vaddr):
            addr_size = binary_get_word_size(binary)
            section = get_section_from_segment(binary, "__DATA", DATA_SECTION)

            if not is_vaddr_in_section(vaddr, section):
                return None

            data = binary.get_content_from_virtual_address(vaddr, 2 * addr_size)
            if len(data) != 2 * addr_size:
                return None

            data_vaddr = unpack(data[:addr_size])
            size = unpack(data[addr_size:])
            if not is_vaddr_in_section(vaddr, section):
                return None

            data = binary.get_content_from_virtual_address(data_vaddr, size)
            if len(data) != size:
                return None
            return bytes(data)

        contents_v = [v for v in
                      extract_data_tables_from_section(binary,
                                                       get_profile_content,
                                                       get_tables_section(binary))
                      if len(v) > 3]

        assert len(contents_v) == 1
        return contents_v[0]

    profile_names = get_profile_names()
    profile_contents = get_profile_contents()

    assert len(profile_names) == len(profile_contents)
    return zip(profile_names, profile_contents)


def extract_sbops(string_tables):
    """ Extracts sandbox operations from a given MachO binary.
    If the sandbox profiles are stored either in sandboxd or sandbox kernel
    extension, the operations are stored always in the kernel extension.
    The sandbox operations are stored similar to the separated sandbox profiles
    but this time we have only one table: the name table.

    Args:
        string_tables: The binary's string tables.

    Returns:
        The sandbox operations.
    """

    def transform(arr):
        if len(arr) <= 3:
            return None

        idxs = []
        for idx, val in enumerate(arr):
            if val == 'default':
                idxs.append(idx)

        return [arr[idx:] for idx in idxs]

    def get_sol(possible):
        assert len(possible) >= 1

        sol = []
        if len(possible) > 1:
            cnt = min(len(arr) for arr in possible)
            for vals in zip(*[val[:cnt] for val in possible]):
                if not all(val == vals[0] for val in vals):
                    break
                sol.append(vals[0])
        else:
            sol.append(possible[0][0])
            for pos in possible[0][1:]:
                if pos in ['HOME', 'default']:
                    break
                sol.append(pos)

        return sol

    sbops_v = [transform(v) for v in string_tables]
    sbops_v = [v for v in sbops_v if v is not None and v != []]
    sbops_v = [x for v in sbops_v for x in v]

    return get_sol(sbops_v)


def get_ios_major_version(version: str):
    """Extracts the major iOS version from a given version.

        Args:
            version: A string with the 'full' version.
        Returns:
            An integer with the major iOS version.

    """

    return int(version.split('.')[0])


def findall(searching, pattern):
    """Finds all the substring in the given string.

    Args:
        searching: A string.
        pattern: A pattern that needs to be searched in the searching string.

    Returns:
        The indexes of all substrings equal to pattern inside searching string.
    """

    i = searching.find(pattern)
    while i != -1:
        yield i
        i = searching.find(pattern, i + 1)


def check_regex(data: bytes, base_index: int, ios_version: int):
    """ Checks if the regular expression (from sandbox profile) at offset
    base_index from data is valid for newer versions of iOS(>=8).

    Args:
        data: An array of bytes.
        base_index: The starting index.
        ios_version: An integer representing the iOS version.

    Returns:
        True: if the regular expression is valid for iOS version >= 8.
        False: otherwise.
    """

    if base_index + 0x10 > len(data):
        return False

    if ios_version >= 13:
        size = struct.unpack('<H', data[base_index: base_index + 0x2])[0]
        version = struct.unpack('>I', data[base_index + 0x2: base_index + 0x6])[0]
    else:
        size = struct.unpack('<I', data[base_index: base_index + 0x4])[0]
        version = struct.unpack('>I', data[base_index + 0x4: base_index + 0x8])[0]

    if size > 0x1000 or size < 0x8 or base_index + size + 4 > len(data):
        return False

    if version != 3:
        return False

    if ios_version >= 13:
        sub_size = struct.unpack('<H', data[base_index + 0x6: base_index + 0x8])[0]
    else:
        sub_size = struct.unpack('<H', data[base_index + 0x8: base_index + 0xa])[0]

    return size == sub_size + 6


def unpack_for_newer_ios(base_index, count, data):
    """Unpacking for newer iOS versions (>= 13).

    Args:
        base_index: The starting index.
        count: Bundle size.
        data: An array of bytes.
    Returns:
        The new base index and an offset.
    """

    re_offset = base_index + 12
    op_nodes_count = struct.unpack('<H', data[base_index + 2:base_index + 4])[0]
    sb_ops_count = struct.unpack('<H', data[base_index + 4:base_index + 6])[0]
    sb_profiles_count = struct.unpack('<H', data[base_index + 6:base_index + 8])[0]
    global_table_count = struct.unpack('<B', data[base_index + 10:base_index + 11])[0]
    debug_table_count = struct.unpack('<B', data[base_index + 11:base_index + 12])[0]
    # base_index will be now at the of op_nodes
    base_index += 12 + (count + global_table_count + debug_table_count) * 2 + \
                  (2 + sb_ops_count) * 2 * sb_profiles_count + \
                  op_nodes_count * 8 + 4

    return base_index, re_offset


def check_bundle(data: bytes, base_index: int, ios_version: int):
    """Checks if the sandbox profile bundle at offset base_index from data
    is valid for the given ios_version. Note that sandbox profile bundles are
    used for newer versions of iOS(>=8).

    Args:
        data: An array of bytes.
        base_index: The starting index.
        ios_version: An integer representing the iOS version.

    Returns:
        True: if the sandbox profile bundle is valid.
        False: otherwise.
    """

    if len(data) - base_index < 50:
        return False
    re_offset, aux = struct.unpack('<2H', data[base_index + 2:base_index + 6])

    if ios_version >= 13:
        count = struct.unpack('<H', data[base_index + 8:base_index + 10])[0]
        if count < 0x10:
            return False
    elif ios_version >= 12:
        count = (aux - re_offset) * 4
        # bundle should be big
        if count < 0x10:
            return False
    else:
        count = aux

    if count > 0x1000 or re_offset < 0x10:
        return False

    if ios_version >= 13:
        base_index, re_offset = unpack_for_newer_ios(base_index, count, data)

    else:
        re_offset = base_index + re_offset * 8
        if len(data) - re_offset < count * 2:
            return False

    for off_index in range(re_offset, re_offset + 2 * count, 2):
        index = struct.unpack('<H', data[off_index:off_index + 2])[0]
        if index == 0:
            if off_index < re_offset + 2 * count - 4:
                return False
            continue

        index = base_index + index * 8

        if not check_regex(data, index, ios_version):
            return False

    return True


def extract_bundle_profiles(binary: lief.MachO.Binary, ios_version: int):
    """Extracts sandbox profile bundle from the given MachO binary which was
    extracted from a device with provided ios version.

    Args:
        binary: A sandbox profile in its binary form.
        ios_version: The major ios version.

    Returns:
        The sandbox profile bundle.
    """

    matches = []
    for section in binary.sections:
        if section.name == '__text':
            continue

        content = bytes(section.content)
        for index in findall(content, b'\x00\x80'):
            if check_bundle(content, index, ios_version):
                matches.append(content[index:])

    assert len(matches) == 1
    return matches[0]


def main(args):
    if type(args.binary) == lief.MachO.FatBinary:
        assert args.binary.size == 1
        binary = args.binary.at(0)
    else:
        binary = args.binary

    retcode = 0
    string_tables = extract_string_tables(binary)

    if args.sbops_file is not None:
        sbops = extract_sbops(string_tables)
        sbops_str = '\n'.join(sbops)
        if args.sbops_file == '-':
            print(sbops_str)
        else:
            try:
                with open(args.sbops_file, 'w') as file:
                    file.write(sbops_str + '\n')
            except IOError as exception:
                retcode = exception.errno
                print(exception, file=sys.stderr)

    if args.sbs_dir is not None:
        if args.version <= 8:
            profiles = extract_separated_profiles(binary, string_tables)
            for name, content in profiles:
                try:
                    with open(args.sbs_dir + '/' + name + '.sb.bin', 'wb') as file:
                        file.write(content)
                except IOError as exception:
                    retcode = exception.errno
                    print(exception, file=sys.stderr)
        else:
            content = extract_bundle_profiles(binary, args.version)
            try:
                with open(args.sbs_dir + '/sandbox_bundle', 'wb') as file:
                    file.write(content)
            except IOError as exception:
                retcode = exception.errno
                print(exception, file=sys.stderr)
    exit(retcode)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Sandbox profiles and operations extraction tool(iOS <9)')
    parser.add_argument('binary', metavar='BINARY', type=lief.MachO.parse,
                        help='path to sandbox(seatbelt) kernel exenstion' +
                        '(iOS 4-12) in order to extract sandbox operations OR ' +
                        'path to sandboxd(iOS 5-8) / sandbox(seatbelt) kernel extension' +
                        '(iOS 4 and 9-12) in order to extract sandbox profiles')
    parser.add_argument('version', metavar='VERSION',
                        type=get_ios_major_version, help='iOS version for given binary')
    parser.add_argument('-o', '--output-sbops', dest='sbops_file', type=str,
                        default=None,
                        help='path to sandbox profile operations store file')
    parser.add_argument('-O', '--output-profiles', dest='sbs_dir', type=str,
                        default=None,
                        help='path to directory in which sandbox profiles should be stored')

    args = parser.parse_args()
    exit(main(args))
