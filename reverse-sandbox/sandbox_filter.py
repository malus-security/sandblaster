#!/usr/bin/env python

import struct
import re
import logging
import logging.config
import reverse_sandbox
import reverse_string

from filters import Filters


logging.config.fileConfig("logger.config")
logger = logging.getLogger(__name__)

ios_major_version = 4
keep_builtin_filters = False
global_vars = []
base_addr = 0

def get_filter_arg_string_by_offset(f, offset):
    """Extract string (literal) from given offset."""
    f.seek(base_addr + offset * 8)
    if ios_major_version >= 13:
        len = struct.unpack("<H", f.read(2))[0]
        s = f.read(len)
        logger.info("binary string is " + s.encode("hex"))
        ss = reverse_string.SandboxString()
        myss = ss.parse_byte_string(s, global_vars)
        actual_string = ""
        for sss in myss:
            actual_string = actual_string + sss + " "
        actual_string = actual_string[:-1]
        logger.info("actual string is " + actual_string)
        return myss
    len = struct.unpack("<I", f.read(4))[0]
    if ios_major_version >= 10:
        f.seek(offset * 8)
        s = f.read(4+len)
        logger.info("binary string is " + s.encode("hex"))
        ss = reverse_string.SandboxString()
        myss = ss.parse_byte_string(s[4:], global_vars)
        actual_string = ""
        for sss in myss:
            actual_string = actual_string + sss + " "
        actual_string = actual_string[:-1]
        logger.info("actual string is " + actual_string)
        return myss
    type = struct.unpack("<B", f.read(1))[0]
    return '"%s"' % f.read(len)


def get_filter_arg_string_by_offset_with_type(f, offset):
    """Extract string from given offset and consider type byte."""
    global ios_major_version
    global keep_builtin_filters
    f.seek(base_addr + offset * 8)
    if ios_major_version >= 13:
        len = struct.unpack("<H", f.read(2))[0]
        s = f.read(len)
        logger.info("binary string is " + s.encode("hex"))
        ss = reverse_string.SandboxString()
        myss = ss.parse_byte_string(s, global_vars)
        append = "literal"
        actual_string = ""
        for sss in myss:
            actual_string = actual_string + sss + " "
        actual_string = actual_string[:-1]
        logger.info("actual string is " + actual_string)
        return (append, myss)
    len = struct.unpack("<I", f.read(4))[0]
    if ios_major_version >= 10:
        f.seek(base_addr + offset * 8)
        s = f.read(4+len)
        logger.info("binary string is " + s.encode("hex"))
        ss = reverse_string.SandboxString()
        myss = ss.parse_byte_string(s[4:], global_vars)
        append = "literal"
        actual_string = ""
        for sss in myss:
            actual_string = actual_string + sss + " "
        actual_string = actual_string[:-1]
        logger.info("actual string is " + actual_string)
        return (append, myss)
    type = struct.unpack("<B", f.read(1))[0]
    append = ""
    if type == 0x00 or type == 0x04 or type == 0x02:
        append += "literal"
    elif type == 0x01 or type == 0x05:
        append += "subpath"
    elif type == 0x0c or type == 0x0e or type == 0x14 or type == 0x16:
        append += "literal-prefix"
    elif type == 0x0d or type == 0x15:
        append += "subpath-prefix"
    elif type == 0x06 or type == 0x24:
        append += "prefix"
    else:
        logger.warn("Unknown type for string type: {} at offset {}".format(type, offset * 8))
    actual_string = f.read(len)
    if actual_string == "/private/var/tmp/launchd/sock" and keep_builtin_filters == False:
        return (append, "###$$$***")
    return (append, '"%s"' % actual_string)


def get_filter_arg_string_by_offset_no_skip(f, offset):
    """Extract string from given offset and ignore type byte."""
    f.seek(base_addr + offset * 8)
    if ios_major_version >= 13:
        len = struct.unpack("<H", f.read(2))[0]-1
    else:
        len = struct.unpack("<I", f.read(4))[0]-1
    return '"%s"' % f.read(len)


def get_filter_arg_network_address(f, offset):
    """Convert 4 bytes value to network address (host and port)."""
    f.seek(base_addr + offset * 8)

    host, port = struct.unpack("<HH", f.read(4))
    host_port_string = ""
    if host == 0x1:
        proto = "ip4"
        host_port_string += "*"
    elif host == 0x2:
        proto = "ip6"
        host_port_string += "*"
    elif host == 0x3:
        proto = "ip"
        host_port_string += "*"
    elif host == 0x5:
        proto = "tcp4"
        host_port_string += "*"
    elif host == 0x6:
        proto = "tcp6"
        host_port_string += "*"
    elif host == 0x7:
        proto = "tcp"
        host_port_string += "*"
    elif host == 0x9:
        proto = "udp4"
        host_port_string += "*"
    elif host == 0xa:
        proto = "udp6"
        host_port_string += "*"
    elif host == 0xb:
        proto = "udp"
        host_port_string += "*"
    elif host == 0x101:
        proto = "ip4"
        host_port_string += "localhost"
    elif host == 0x102:
        proto = "ip6"
        host_port_string += "localhost"
    elif host == 0x103:
        proto = "ip"
        host_port_string += "localhost"
    elif host == 0x105:
        proto = "tcp4"
        host_port_string += "localhost"
    elif host == 0x106:
        proto = "tcp6"
        host_port_string += "localhost"
    elif host == 0x107:
        proto = "tcp"
        host_port_string += "localhost"
    elif host == 0x109:
        proto = "udp4"
        host_port_string += "localhost"
    elif host == 0x10a:
        proto = "udp6"
        host_port_string += "localhost"
    elif host == 0x10b:
        proto = "udp"
        host_port_string += "localhost"
    else:
        proto = "unknown"
        host_port_string += "0x%x" % host

    if port == 0:
        host_port_string += ":*"
    else:
        host_port_string += ":%d" % (port)
    return '%s "%s"' % (proto, host_port_string)


def get_filter_arg_integer(f, arg):
    """Convert integer value to decimal string representation."""
    return '%d' % arg


def get_filter_arg_octal_integer(f, arg):
    """Convert integer value to octal string representation."""
    return '#o%04o' % arg


def get_filter_arg_boolean(f, arg):
    """Convert boolean value to scheme boolean string representation."""
    if arg == 1:
        return '#t'
    else:
        return '#f'


regex_list = []
def get_filter_arg_regex_by_id(f, regex_id):
    """Get regular expression by index."""
    global keep_builtin_filters
    return_string = ""
    global regex_list
    for regex in regex_list[regex_id]:
        if re.match("^/com\\\.apple\\\.sandbox\$", regex) and keep_builtin_filters == False:
            return "###$$$***"
        return_string += ' #"%s"' % (regex)
    return return_string[1:]


def get_filter_arg_ctl(f, arg):
    """Convert integer value to IO control string."""
    letter = chr(arg >> 8)
    number = arg & 0xff
    return '(_IO "%s" %d)' % (letter, number)


def get_filter_arg_vnode_type(f, arg):
    """Convert integer to file (vnode) type string."""
    arg_types = {
            0x01: "REGULAR-FILE",
            0x02: "DIRECTORY",
            0x03: "BLOCK-DEVICE",
            0x04: "CHARACTER-DEVICE",
            0x05: "SYMLINK",
            0x06: "SOCKET",
            0x07: "FIFO",
            0xffff: "TTY"
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_owner(f, arg):
    """Convert integer to process owner string."""
    arg_types = {
            0x01: "self",
            0x02: "pgrp",
            0x03: "others",
            0x04: "children",
            0x05: "same-sandbox"
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_socket_domain(f, arg):
    """Convert integer to socket domain string."""
    arg_types = {
            0: "AF_UNSPEC",
            1: "AF_UNIX",
            2: "AF_INET",
            3: "AF_IMPLINK",
            4: "AF_PUP",
            5: "AF_CHAOS",
            6: "AF_NS",
            7: "AF_ISO",
            8: "AF_ECMA",
            9: "AF_DATAKIT",
            10: "AF_CCITT",
            11: "AF_SNA",
            12: "AF_DECnet",
            13: "AF_DLI",
            14: "AF_LAT",
            15: "AF_HYLINK",
            16: "AF_APPLETALK",
            17: "AF_ROUTE",
            18: "AF_LINK",
            19: "pseudo_AF_XTP",
            20: "AF_COIP",
            21: "AF_CNT",
            22: "pseudo_AF_RTIP",
            23: "AF_IPX",
            24: "AF_SIP",
            25: "pseudo_AF_PIP",
            27: "AF_NDRV",
            28: "AF_ISDN",
            29: "pseudo_AF_KEY",
            30: "AF_INET6",
            31: "AF_NATM",
            32: "AF_SYSTEM",
            33: "AF_NETBIOS",
            34: "AF_PPP",
            35: "pseudo_AF_HDRCMPLT",
            36: "AF_RESERVED_36",
            37: "AF_IEEE80211",
            38: "AF_UTUN",
            40: "AF_MAX"
            }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_socket_type(f, arg):
    """Convert integer to socket type string."""
    arg_types = {
        0x01: "SOCK_STREAM",
        0x02: "SOCK_DGRAM",
        0x03: "SOCK_RAW",
        0x04: "SOCK_RDM",
        0x05: "SOCK_SEQPACKET"
        }
    if arg in arg_types.keys():
        return '"%s"' % (arg_types[arg])
    else:
        return '%d' % arg


def get_none(f, arg):
    """Dumb callback function"""
    return None


def get_filter_arg_privilege_id(f, arg):
    """Convert integer to privilege id string."""
    arg_types = {
            1000: "PRIV_ADJTIME",
            1001: "PRIV_PROC_UUID_POLICY",
            1002: "PRIV_GLOBAL_PROC_INFO",
            1003: "PRIV_SYSTEM_OVERRIDE",
            1004: "PRIV_HW_DEBUG_DATA",
            1005: "PRIV_SELECTIVE_FORCED_IDLE",
            1006: "PRIV_PROC_TRACE_INSPECT",
            1008: "PRIV_KERNEL_WORK_INTERNAL",
            6000: "PRIV_VM_PRESSURE",
            6001: "PRIV_VM_JETSAM",
            6002: "PRIV_VM_FOOTPRINT_LIMIT",
            10000: "PRIV_NET_PRIVILEGED_TRAFFIC_CLASS",
            10001: "PRIV_NET_PRIVILEGED_SOCKET_DELEGATE",
            10002: "PRIV_NET_INTERFACE_CONTROL",
            10003: "PRIV_NET_PRIVILEGED_NETWORK_STATISTICS",
            10004: "PRIV_NET_PRIVILEGED_NECP_POLICIES",
            10005: "PRIV_NET_RESTRICTED_AWDL",
            10006: "PRIV_NET_PRIVILEGED_NECP_MATCH",
            11000: "PRIV_NETINET_RESERVEDPORT",
            14000: "PRIV_VFS_OPEN_BY_ID",
        }
    if arg in arg_types.keys():
        return '"%s"' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_process_attribute(f, arg):
    """Convert integer to process attribute string."""
    arg_types = {
            0: 'is-plugin',
            1: 'is-installer',
            2: 'is-restricted',
            3: 'is-initproc',
        }
    if arg in arg_types.keys():
        return '%s' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_csr(f, arg):
    """Convert integer to csr string."""
    arg_types = {
            1: 'CSR_ALLOW_UNTRUSTED_KEXTS',
            2: 'CSR_ALLOW_UNRESTRICTED_FS',
            4: 'CSR_ALLOW_TASK_FOR_PID',
            8: 'CSR_ALLOW_KERNEL_DEBUGGER',
            16: 'CSR_ALLOW_APPLE_INTERNAL',
            32: 'CSR_ALLOW_UNRESTRICTED_DTRACE',
            64: 'CSR_ALLOW_UNRESTRICTED_NVRAM',
            128: 'CSR_ALLOW_DEVICE_CONFIGURATION',
        }
    if arg in arg_types.keys():
        return '"%s"' % (arg_types[arg])
    else:
        return '%d' % arg


def get_filter_arg_host_port(f, arg):
    """Convert integer to host special port string."""
    arg_types = {
            8: 'HOST_DYNAMIC_PAGER_PORT',
            9: 'HOST_AUDIT_CONTROL_PORT',
            10: 'HOST_USER_NOTIFICATION_PORT',
            11: 'HOST_AUTOMOUNTD_PORT',
            12: 'HOST_LOCKD_PORT',
            13: 'unknown: 13',
            14: 'HOST_SEATBELT_PORT',
            15: 'HOST_KEXTD_PORT',
            16: 'HOST_CHUD_PORT',
            17: 'HOST_UNFREED_PORT',
            18: 'HOST_AMFID_PORT',
            19: 'HOST_GSSD_PORT',
            20: 'HOST_TELEMETRY_PORT',
            21: 'HOST_ATM_NOTIFICATION_PORT',
            22: 'HOST_COALITION_PORT',
            23: 'HOST_SYSDIAGNOSE_PORT',
            24: 'HOST_XPC_EXCEPTION_PORT',
            25: 'HOST_CONTAINERD_PORT',
        }
    if arg in arg_types.keys():
        return '"%s"' % (arg_types[arg])
    else:
        return '%d' % arg


"""An array (dictionary) of filter converting items

A filter is identied by a filter id and a filter argument. They are
both stored in binary format (numbers) inside the binary sandbox
profile file.

Each item in the dictionary is identied by the filter id (used in
hexadecimal). The value of each item is the string form of the filter id
and the callback function used to convert the binary form the filter
argument to a string form.

While there is a one-to-one mapping between the binary form and the
string form of the filter id, that is not the case for the filter
argument. To convert the binary form of the filter argument to its
string form we use one of the callback functions above; almost all
callback function names start with get_filter_arg_.
"""

def convert_filter_callback(f, ios_major_version_arg, keep_builtin_filters_arg,
        global_vars_arg, re_list, filter_id, filter_arg, base_addr_arg):
    """Convert filter from binary form to string.

    Binary form consists of filter id and filter argument:
      * filter id is the index inside the filters array above
      * filter argument is an actual parameter (such as a port number),
        a file offset or a regular expression index

    The string form consists of the name of the filter (as extracted
    from the filters array above) and a string representation of the
    filter argument. The string form of the filter argument if obtained
    from the binary form through the use of the callback function (as
    extracted frm the filters array above).

    Function arguments are:
      f: the binary sandbox profile file
      regex_list: list of regular expressions
      filter_id: the binary form of the filter id
      filter_arg: the binary form of the filter argument
    """

    global regex_list
    global ios_major_version
    global keep_builtin_filters
    global global_vars
    global base_addr
    keep_builtin_filters = keep_builtin_filters_arg
    ios_major_version = ios_major_version_arg
    global_vars = global_vars_arg
    regex_list = re_list
    base_addr = base_addr_arg

    if not Filters.exists(ios_major_version, filter_id):
        logger.warn("filter_id {} not in keys".format(filter_id))
        return (None, None)
    filter = Filters.get(ios_major_version, filter_id)
    if not filter["arg_process_fn"]:
        logger.warn("no function for filter {}".format(filter_id))
        return (None, None)
    if filter["arg_process_fn"] == "get_filter_arg_string_by_offset_with_type":
        (append, result) = globals()[filter["arg_process_fn"]](f, filter_arg)
        if filter_id == 0x01 and append == "path":
            append = "subpath"
        if result == None and filter["name"] != "debug-mode":
            logger.warn("result of calling string offset for filter {} is none".format(filter_id))
            return (None, None)
        return (filter["name"] + append, result)
    result = globals()[filter["arg_process_fn"]](f, filter_arg)
    if result == None and not ((filter["name"] in ["debug-mode", "syscall-mask", "machtrap-mask", "kernel-mig-routine-mask"]) or
            (filter["name"] in ["extension", "mach-extension"]
                and ios_major_version <= 5)):
        logger.warn("result of calling arg_process_fn for filter {} is none".format(filter_id))
        return (None, None)
    return (filter["name"], result)
