#! /usr/bin/env python

import sys

if ( len(sys.argv) != 2 ) :
    print " Usage : ./split infile "
    sys.exit(0)

infile = open(sys.argv[1], 'rb')

idx = 0
# read all bytes before valid oscar header
while True:
    word = infile.read(1)
    if hex(ord(word)) != '0x2a':
        continue
    if hex(ord(word)) == '0x2a':
        break
    if word == '':
        print "end of file " + sys.argv[1]
        sys.exit(0)


# open first stream
outfile = open(sys.argv[1]+str(idx), 'wb')
outfile.write(word)
# loop read oscar protocal
while True:
    word = infile.read(1)

    if word == '':
        print "end of file " + sys.argv[1]
        outfile.close()
        sys.exit(0)

    # start of another stream
    if hex(ord(word)) == '0x2a':
        outfile.close()
        idx += 1
        outfile = open(sys.argv[1]+str(idx), 'wb')
        outfile.write(word)
        continue

    outfile.write(word)




