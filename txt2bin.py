#!/usr/bin/python

import getopt
import sys
import string
import struct

def txt2bin(infn, outfn, offset=0):
    infile = sys.stdin
    outfile = sys.stdout

    if '-' != infn:
        infile = open(infn, 'r')

    if '-' != outfn:
        outfile = open(outfn, 'w')

    bytes = infile.read().replace("\n", ' ').strip().split(' ')
    for t in bytes[offset:]:
        if '' == t:
            continue
        outfile.write(struct.pack("B", string.atoi(t, 16)))

    infile.close()
    outfile.close()


if '__main__' == __name__:
    offset = 0
    optlist, args = getopt.getopt(sys.argv[1:], 'o:')
    if len(args) < 2:
        print "Usage: %s [-t offset] <infile> <outfile>" % sys.argv[0]
        sys.exit(1)
    
    for opt, arg in optlist:
        if '-o' == opt:
            offset = int(arg)
        else:
            print "Unrecognized option %s" % opt
            sys.exit(1)

    txt2bin(args[0], args[1], offset=offset)

    

    
