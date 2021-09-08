#!/usr/bin/env python2
import os
import sys
import socket
import struct
import ctypes
import subprocess
import hexdump
from optparse import OptionParser

# Also see: https://github.com/cilium/cilium/blob/master/bpf/sockops/bpf_sockops.c

usage = "usage: %prog INTERFACE"

# Capture only TCP packets - 'ip proto \tcp'
# (000) ldh      [12]
# (001) jeq      #0x800           jt 2	jf 5
# (002) ldb      [23]
# (003) jeq      #0x6             jt 4	jf 5
# (004) ret      #262144
# (005) ret      #0

#  [struct.pack('HBBI', 0x6, 0, 0, 0x00040000)]

tcp_filter = \
    [struct.pack('HBBI', 0x28, 0, 0, 0x0000000c),
     struct.pack('HBBI', 0x15, 0, 3, 0x00000800),
     struct.pack('HBBI', 0x30, 0, 0, 0x00000017),
     struct.pack('HBBI', 0x15, 0, 1, 0x00000006),
     struct.pack('HBBI', 0x6, 0, 0, 0x00040000 ),
     struct.pack('HBBI', 0x6, 0, 0, 0x00000000 )]

# Defined in asm-generic/socket.h
SO_ATTACH_FILTER = 26

# Defined in linux/if_ether.h
ETH_P_ALL = 0x0003

class BPFSniffer(object):
    def __init__(self, iface, dry_run):
        self.iface = iface
        self.dry_run = dry_run
        self.nonces = []
        self.sock = self._create_socket()

    def _create_socket(self):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        bpf = ctypes.create_string_buffer(''.join(tcp_filter))
        prog = struct.pack('HL', len(tcp_filter), ctypes.addressof(bpf))
        sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, prog)
        sock.bind((self.iface, ETH_P_ALL))
        return sock

    def detect(self):
        while True:
            pkt, addr = self.sock.recvfrom(1024)
            print "Address:", addr
            print "Src IP:", ".".join([str(ord(c)) for c in pkt[26:30]])
            print "Dst IP:", ".".join([str(ord(c)) for c in pkt[30:34]])
            print "Packet:"
            hexdump.hexdump(pkt)
            print "========================================="

def main():
    parser = OptionParser(usage)
    parser.add_option("-n", "--dry-run", dest="dry_run",
                      action="store_true", help="Do not disconnect suspected devices")
    (options, args) = parser.parse_args()

    if len(args) != 1:
        parser.error("Incorrect number of arguments")

    if os.getuid() != 0:
        print "Please run as root"
        sys.exit(1)

    iface = args[0]
    dry_run = options.dry_run

    BPFSniffer(iface, dry_run).detect()


if __name__ == "__main__":
    main()
