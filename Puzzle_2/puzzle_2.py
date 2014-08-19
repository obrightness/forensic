#! /bin/python

import dpkt
import sys


if len(sys.argv) != 2:
    print 'Usage: puzzle_2.py [filename]'
    sys.exit(0)


for ts, pkt in dpkt.pcap.Reader( open( sys.argv[1], 'r' ) ):

    print ts, 'pkt'
