#!/usr/bin/env python

import sys
import struct


def main():
    if len(sys.argv) != 2:
        print >> sys.stderr, "Usage: $0 <sandbox.kext>"
        sys.exit(1)

    offset = 0
    with open(sys.argv[1]) as f:
        while True:
            buf = f.read(16)
            if buf == "":
                break
            first_word, rest, pen_word, last_word = struct.unpack("<H10sHH", buf)
            if first_word == 0x8000 and pen_word == last_word:
                print offset
            else:
                first_word, r1, b1, r2, b2, r3, b3, last_word = struct.unpack("HBB3sB5sBH", buf)
                if first_word == 0x8000 and b2 == b3 and last_word == 0x0000:
                    print offset
            offset += 16


if __name__ == "__main__":
    sys.exit(main())
