#!/usr/bin/env python3

"""
iOS/OS X sandbox decompiler

Heavily inspired from Dion Blazakis' previous work
    https://github.com/dionthegod/XNUSandbox/tree/master/sbdis
Excellent information from Stefan Essers' slides and work
    http://www.slideshare.net/i0n1c/ruxcon-2014-stefan-esser-ios8-containers-sandboxes-and-entitlements
    https://github.com/sektioneins/sandbox_toolkit
"""

import sys
import struct
import logging
import logging.config
import argparse
import os
import re
import operation_node
import sandbox_filter
import sandbox_regex


logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)


def extract_string_from_offset(f, offset, ios_version):
    """Extract string (literal) from given offset."""
    if ios_version >= 13:
        f.seek(get_base_addr(f, ios_version) + offset * 8)
        len = struct.unpack("<H", f.read(2))[0]-1
    else:
        f.seek(offset * 8)
        len = struct.unpack("<I", f.read(4))[0]-1
    return '%s' % f.read(len)


def create_operation_nodes(infile, regex_list, num_operation_nodes,
        ios_major_version, keep_builtin_filters, global_vars):
    # Read sandbox operations.
    operation_nodes = operation_node.build_operation_nodes(infile,
        num_operation_nodes, ios_major_version)
    logger.info("operation nodes")
    
    for idx, node in enumerate(operation_nodes):
        logger.info("%d: %s", idx, node.str_debug())
    
    for n in operation_nodes:
        n.convert_filter(sandbox_filter.convert_filter_callback, infile,
                    regex_list, ios_major_version, keep_builtin_filters,
                    global_vars, get_base_addr(infile, ios_major_version))
    logger.info("operation nodes after filter conversion")
    for idx, node in enumerate(operation_nodes):
        logger.info("%d: %s", idx, node.str_debug())

    return operation_nodes


def process_profile(infile, outfname, sb_ops, ops_to_reverse, op_table, operation_nodes):
    outfile = open(outfname, "wt")
    outfile_xml = open(outfname + ".xml", "wt")

    # Print version.
    outfile.write("(version 1)\n")

    outfile_xml.write('<?xml version="1.0" encoding="us-ascii" standalone="yes"?>\n')
    outfile_xml.write('<!DOCTYPE operations [\n')
    outfile_xml.write('<!ELEMENT operations (operation*)>\n')
    outfile_xml.write('<!ELEMENT operation (filters?)>\n')
    outfile_xml.write('<!ELEMENT filters (filter | require)*>\n')
    outfile_xml.write('<!ELEMENT require (filter | require)*>\n')
    outfile_xml.write('<!ELEMENT filter (#PCDATA)>\n')
    outfile_xml.write('<!ATTLIST operation\n')
    outfile_xml.write('\tname CDATA #REQUIRED\n')
    outfile_xml.write('\taction (deny|allow) #REQUIRED>\n')
    outfile_xml.write('<!ATTLIST require\n')
    outfile_xml.write('\ttype (require-all|require-any|require-not|require-entitlement) #REQUIRED\n')
    outfile_xml.write('\tvalue CDATA #IMPLIED>\n')
    outfile_xml.write('<!ATTLIST filter\n')
    outfile_xml.write('\tname CDATA #REQUIRED\n')
    outfile_xml.write('\targument CDATA #IMPLIED>\n')
    outfile_xml.write(']>\n')
    outfile_xml.write("<operations>\n")

    # Extract node for 'default' operation (index 0).
    default_node = operation_node.find_operation_node_by_offset(operation_nodes, op_table[0])
    outfile.write("(%s default)\n" % (default_node.terminal))
    outfile_xml.write("\t<operation name=\"default\" action=\"%s\" />\n" % (default_node.terminal))

    # For each operation expand operation node.
    for idx in range(1, len(op_table)):
        offset = op_table[idx]
        operation = sb_ops[idx]
        # Go past operations not in list, in case list is not empty.
        if ops_to_reverse:
            if operation not in ops_to_reverse:
                continue
        logger.info("parsing operation %s (index %d)", operation, idx)
        node = operation_node.find_operation_node_by_offset(operation_nodes, offset)
        if not node:
            logger.info("operation %s (index %d) has no operation node", operation, idx)
            continue
        g = operation_node.build_operation_node_graph(node, default_node)
        if g:
            rg = operation_node.reduce_operation_node_graph(g)
            rg.str_simple_with_metanodes()
            rg.print_vertices_with_operation_metanodes(operation, default_node.terminal.is_allow(), outfile)
            #rg.dump_xml(operation, outfile_xml)
        else:
            logger.info("no graph for operation %s (index %d)", operation, idx)
            if node.terminal and default_node.terminal:
                if node.terminal.type != default_node.terminal.type:
                    outfile.write("(%s %s)\n" % (node.terminal, operation))
                    outfile_xml.write("\t<operation name=\"%s\" action=\"%s\" />\n" % (operation, node.terminal))

    outfile.close()
    outfile_xml.write("</operations>\n")
    outfile_xml.close()

def get_ios_major_version(release):
    """
    Returns major version of release
    """
    return int(release.split('.')[0])

def is_ios_more_than_10_release(release):
    """
    Returns True if release is using newer (iOS >= 10) binary sandbox profile format.
    """
    major_version = get_ios_major_version(release)
    if major_version < 10:
        return False
    return True


def display_sandbox_profiles(f, re_table_offset, num_sb_ops, ios_version):
    logger.info("Printing sandbox profiles from bundle")
    if ios_version >= 13:
        f.seek(6)
    elif ios_version >= 12:
        f.seek(12)
    elif ios_version >= 10:
        f.seek(10)
    else:
        f.seek(6)
    num_profiles = struct.unpack("<H", f.read(2))[0]

    if ios_version >= 13:
        f.seek(2)
        num_operation_nodes = struct.unpack("<H", f.read(2))[0]
        print(hex(num_operation_nodes))
    else:
        # Place file pointer to start of operation nodes area.
        if ios_version >= 12:
            f.seek(14 + (num_sb_ops + 2) * 2 * num_profiles)
        elif ios_version >= 10:
            f.seek(12 + (num_sb_ops + 2) * 2 * num_profiles)
        else:
            f.seek(8 + (num_sb_ops + 2) * 2 * num_profiles)
        while True:
            word = struct.unpack("<H", f.read(2))[0]
            if word != 0:
                f.seek(-2, 1)
                break
        start = f.tell()
        end = re_table_offset * 8
        num_operation_nodes = (end - start) / 8

    logger.info("number of operation nodes: %u" % num_operation_nodes)

    for i in range(0, num_profiles):
        if ios_version >= 13:
            f.seek(8)
            regex_table_count = struct.unpack('<H', f.read(2))[0]
            f.seek(10)
            global_table_count = struct.unpack('<B', f.read(1))[0]
            f.seek(11)
            debug_table_count = struct.unpack('<B', f.read(1))[0]
            f.seek(12 + (regex_table_count + global_table_count + \
                    debug_table_count) * 2 + (num_sb_ops + 2) * 2 * i)
        elif ios_version >= 12:
            f.seek(14 + (num_sb_ops + 2) * 2 * i)
        elif ios_version >= 10:
            f.seek(12 + (num_sb_ops + 2) * 2 * i)
        else:
            f.seek(8 + (num_sb_ops + 2) * 2 * i)

        name_offset = struct.unpack("<H", f.read(2))[0]
        boundary = struct.unpack("<H", f.read(2))[0]
        name = extract_string_from_offset(f, name_offset, ios_version)

        print(name)

    logger.info("Found %d sandbox profiles." % num_profiles)


def get_global_vars(f, vars_offset, num_vars, base_offset):
    global_vars = []
    for i in range(0, num_vars):
        if base_offset > 0:
            f.seek(vars_offset + i*2)
        else:
            f.seek(vars_offset*8 + i*2)
        current_offset = struct.unpack("<H", f.read(2))[0]
        f.seek(base_offset + current_offset * 8)
        if base_offset > 0:
            len = struct.unpack("<H", f.read(2))[0]
        else:
            len = struct.unpack("<I", f.read(4))[0]
        s = f.read(len-1)
        global_vars.append(s)
    logger.info("global variables are {:s}".format(", ".join(s for s in global_vars)))
    return global_vars

def get_base_addr(f, ios_version):
    if ios_version >= 13:
        # extract operation node table count
        f.seek(2)
        op_nodes_count = struct.unpack('<H', f.read(2))[0]

        # extract sandbox operations count
        f.seek(4)
        sb_ops_count = struct.unpack('<H', f.read(2))[0]

        # extract sandbox profile count
        f.seek(6)
        sb_profiles_count = struct.unpack('<H', f.read(2))[0]

        # extract regular expressions count
        f.seek(8)
        regex_table_count = struct.unpack('<H', f.read(2))[0]

        # extract global table count
        f.seek(10)
        global_table_count = struct.unpack('<B', f.read(1))[0]

        # extract debug table count
        f.seek(11)
        debug_table_count = struct.unpack('<B', f.read(1))[0]

        return 12 + (regex_table_count + global_table_count + debug_table_count)*2 \
                + (2 + sb_ops_count) * 2 * sb_profiles_count + op_nodes_count * 8 + 4
    return 0


def main():
    """Reverse Apple binary sandbox file to SBPL (Sandbox Profile Language) format.

    Sample run:
        python reverse_sandbox.py -r 7.1.1 container.sb.bin
        python reverse_sandbox.py -r 7.1.1 -d out container.sb.bin
        python reverse_sandbox.py -r 7.1.1 -d out container.sb.bin -n network-inbound network-outbound
        python reverse_sandbox.py -r 9.0.2 -d out sandbox_bundle_iOS_9.0 -n network-inbound network-outbound -p container
    """

    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="path to the binary sandbox profile")
    parser.add_argument("-r", "--release", help="iOS release version for sandbox profile", required=True)
    parser.add_argument("-o", "--operations_file", help="file with list of operations", required=True)
    parser.add_argument("-p", "--profile", nargs='+', help="profile to reverse (for bundles) (default is to reverse all operations)")
    parser.add_argument("-n", "--operation", nargs='+', help="particular operation(s) to reverse (default is to reverse all operations)")
    parser.add_argument("-d", "--directory", help="directory where to write reversed profiles (default is current directory)")
    parser.add_argument("-psb", "--print_sandbox_profiles", action="store_true", help="print sandbox profiles of a given bundle (only for iOS versions 9+)")
    parser.add_argument("-kbf", "--keep_builtin_filters", help="keep builtin filters in output", action="store_true")

    args = parser.parse_args()

    if args.filename is None:
        parser.print_usage()
        print("no sandbox profile/bundle file to reverse")
        sys.exit(1)

    # Read sandbox operations.
    sb_ops = [l.strip() for l in open(args.operations_file)]
    num_sb_ops = len(sb_ops)
    logger.info("num_sb_ops: %d", num_sb_ops)

    ops_to_reverse = []
    if args.operation:
        for op in args.operation:
            if op not in sb_ops:
                parser.print_usage()
                print("unavailable operation: {}".format(op))
                sys.exit(1)
            ops_to_reverse.append(op)

    if args.directory:
        out_dir = args.directory
    else:
        out_dir = os.getcwd()

    f = open(args.filename, "rb")

    if get_ios_major_version(args.release) >= 6:
        header = struct.unpack("<H", f.read(2))[0]
        logger.debug("header: 0x%x", header)
    else:
        logger.debug("header: none for iOS <6; using 0")
        header = 0

    if get_ios_major_version(args.release) >= 13:
        re_table_offset = 12
    else:
        re_table_offset = struct.unpack("<H", f.read(2))[0]
    
    if get_ios_major_version(args.release) >= 12:
        f.seek(8)
    re_table_count = struct.unpack("<H", f.read(2))[0]

    logger.debug("re_table_offset: 0x%x", re_table_offset)
    logger.debug("re_table_count: 0x%x", re_table_count)

    logger.debug("\n\nregular expressions:\n")
    regex_list = []
    if re_table_count > 0:
        if get_ios_major_version(args.release) >= 13:
            f.seek(re_table_offset)
        else:
            f.seek(re_table_offset * 8)
        
        re_offsets_table = struct.unpack("<%dH" % re_table_count, f.read(2 * re_table_count))
        for offset in re_offsets_table:
            if get_ios_major_version(args.release) >= 13:
                f.seek(get_base_addr(f, get_ios_major_version(args.release)) + offset * 8)
                re_length = struct.unpack("<H", f.read(2))[0]
            else:
                f.seek(offset * 8)
                re_length = struct.unpack("<I", f.read(4))[0]
            
            re = struct.unpack("<%dB" % re_length, f.read(re_length))
            logger.debug("total_re_length: 0x%x", re_length)
            re_debug_str = "re: [", ", ".join([hex(i) for i in re]), "]"
            logger.debug(re_debug_str)
            regex_list.append(sandbox_regex.parse_regex(re))
    logger.debug(regex_list)

    if args.print_sandbox_profiles:
        if header == 0x8000:
            display_sandbox_profiles(f, re_table_offset, num_sb_ops, get_ios_major_version(args.release))
        else:
            print("cannot print sandbox profiles list; filename {} is not a sandbox bundle".format(args.filename))
        sys.exit(0)

    global_vars = None

    # In case of sandbox profile bundle, go through each profile.
    if header == 0x8000:
        logger.info("using profile bundle")
        if get_ios_major_version(args.release) >= 13:
            # get the regex table entries
            f.seek(8)
            regex_table_count = struct.unpack('<H', f.read(2))[0]
            vars_offset = 12 + regex_table_count * 2
            f.seek(10)
            num_vars = struct.unpack("<B", f.read(1))[0]
            logger.info("{:d} global vars at offset 0x{:0x}".format(num_vars, vars_offset))
            global_vars = get_global_vars(f, vars_offset, num_vars, get_base_addr(f, get_ios_major_version(args.release)))
            f.seek(6)
        elif get_ios_major_version(args.release) >= 12:
            f.seek(4)
            vars_offset = struct.unpack("<H", f.read(2))[0]
            f.seek(10)
            num_vars = struct.unpack("<B", f.read(1))[0]
            logger.info("{:d} global vars at offset 0x{:0x}".format(num_vars, vars_offset))
            global_vars = get_global_vars(f, vars_offset, num_vars, 0)
            f.seek(12)
        elif get_ios_major_version(args.release) >= 10:
            f.seek(6)
            vars_offset = struct.unpack("<H", f.read(2))[0]
            num_vars = struct.unpack("<H", f.read(2))[0]
            logger.info("{:d} global vars at offset 0x{:0x}".format(num_vars, vars_offset))
            global_vars = get_global_vars(f, vars_offset, num_vars, 0)
            f.seek(10)
        else:
            f.seek(6)
        num_profiles = struct.unpack("<H", f.read(2))[0]
        logger.info("number of profiles in bundle: %d", num_profiles)

        if get_ios_major_version(args.release) >= 13:
            f.seek(2)
            num_operation_nodes = struct.unpack("<H", f.read(2))[0]
            f.seek(get_base_addr(f, get_ios_major_version(args.release)) - num_operation_nodes*8)
        else:
            # Place file pointer to start of operation nodes area.
            if get_ios_major_version(args.release) >= 12:
                f.seek(14 + (num_sb_ops + 2) * 2 * num_profiles)
            elif get_ios_major_version(args.release) >= 10:
                f.seek(12 + (num_sb_ops + 2) * 2 * num_profiles)
            else:
                f.seek(8 + (num_sb_ops + 2) * 2 * num_profiles)
            while True:
                word = struct.unpack("<H", f.read(2))[0]
                if word != 0:
                    f.seek(-2, 1)
                    break
            start = f.tell()
            end = re_table_offset * 8
            num_operation_nodes = (end - start) / 8
        logger.info("number of operation nodes: %u" % num_operation_nodes)

        operation_nodes = create_operation_nodes(f, regex_list,
            num_operation_nodes, get_ios_major_version(args.release),
            args.keep_builtin_filters, global_vars)

        for i in range(0, num_profiles):
            if get_ios_major_version(args.release) >= 13:
                f.seek(8)
                regex_table_count = struct.unpack('<H', f.read(2))[0]
                f.seek(10)
                global_table_count = struct.unpack('<B', f.read(1))[0]
                f.seek(11)
                debug_table_count = struct.unpack('<B', f.read(1))[0]
                f.seek(12 + (regex_table_count + global_table_count + \
                        debug_table_count) * 2 + (num_sb_ops + 2) * 2 * i)
            elif get_ios_major_version(args.release) >= 12:
                f.seek(14 + (num_sb_ops + 2) * 2 * i)
            elif get_ios_major_version(args.release) >= 10:
                f.seek(12 + (num_sb_ops + 2) * 2 * i)
            else:
                f.seek(8 + (num_sb_ops + 2) * 2 * i)

            name_offset = struct.unpack("<H", f.read(2))[0]
            boundary = struct.unpack("<H", f.read(2))[0]
            name = extract_string_from_offset(f, name_offset,
                                get_ios_major_version(args.release))

            # Go past profiles not in list, in case list is defined.
            if args.profile:
                if name not in args.profile:
                    continue
            logger.info("profile name (offset 0x%x): %s" % (name_offset, name))

            if get_ios_major_version(args.release) >= 13:
                f.seek(8)
                regex_table_count = struct.unpack('<H', f.read(2))[0]
                f.seek(10)
                global_table_count = struct.unpack('<B', f.read(1))[0]
                f.seek(11)
                debug_table_count = struct.unpack('<B', f.read(1))[0]
                f.seek(12 + (regex_table_count + global_table_count + \
                        debug_table_count) * 2 + (num_sb_ops + 2) * 2 * i + 4)
            elif get_ios_major_version(args.release) >= 12:
                f.seek(14 + (num_sb_ops + 2) * 2 * i + 4)
            elif get_ios_major_version(args.release) >= 10:
                f.seek(12 + (num_sb_ops + 2) * 2 * i + 4)
            else:
                f.seek(8 + (num_sb_ops + 2) * 2 * i + 4)
            op_table = struct.unpack("<%dH" % num_sb_ops, f.read(2 * num_sb_ops))
            for idx in range(1, len(op_table)):
                offset = op_table[idx]
                operation = sb_ops[idx]
                logger.info("operation %s (index %u) starts at node offset %u (0x%x)", operation, idx, offset, offset)
            out_fname = os.path.join(out_dir, name + ".sb")
            process_profile(f, out_fname, sb_ops, ops_to_reverse, op_table, operation_nodes)

    else:
        if get_ios_major_version(args.release) >= 12:
            f.seek(4)
            vars_offset = struct.unpack("<H", f.read(2))[0]
            f.seek(10)
            num_vars = struct.unpack("<B", f.read(1))[0]
            logger.info("{:d} global vars at offset 0x{:0x}".format(num_vars, vars_offset))
            global_vars = get_global_vars(f, vars_offset, num_vars, 0)
            f.seek(12)
        elif get_ios_major_version(args.release) >= 10:
            f.seek(6)
            vars_offset = struct.unpack("<H", f.read(2))[0]
            num_vars = struct.unpack("<H", f.read(2))[0]
            logger.info("{:d} global vars at offset 0x{:0x}".format(num_vars, vars_offset))
            global_vars = get_global_vars(f, vars_offset, num_vars, 0)
            f.seek(10)
        elif get_ios_major_version(args.release) >= 6:
            f.seek(6)
        else:
            f.seek(4)
        op_table = struct.unpack("<%dH" % num_sb_ops, f.read(2 * num_sb_ops))
        for idx in range(1, len(op_table)):
            offset = op_table[idx]
            operation = sb_ops[idx]
            logger.info("operation %s (index %u) starts at node offset %u (0x%x)", operation, idx, offset, offset)

        # Place file pointer to start of operation nodes area.
        while True:
            word = struct.unpack("<H", f.read(2))[0]
            if word != 0:
                f.seek(-2, 1)
                break
        start = f.tell()
        end = re_table_offset * 8
        num_operation_nodes = (end - start) / 8
        logger.info("number of operation nodes: %d ; start: %#x" % (num_operation_nodes, start))

        operation_nodes = create_operation_nodes(f, regex_list,
            num_operation_nodes, get_ios_major_version(args.release),
            args.keep_builtin_filters, global_vars)
        out_fname = os.path.join(out_dir, os.path.splitext(os.path.basename(args.filename))[0])
        process_profile(f, out_fname, sb_ops, ops_to_reverse, op_table, operation_nodes)

    f.close()


if __name__ == "__main__":
    sys.exit(main())
