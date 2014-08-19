#! /usr/bin/python2.7


import sys
import os
import glob
from subprocess import call


if len(sys.argv) != 2:
    print 'usage: dumpall [filename]'
    sys.exit(1)

path = './flow'
filename = sys.argv[1]
gzfolder = './gz'
flowcount = 1

if not os.path.isdir(path):
    call( 'mkdir ' + path, shell=True)
if not os.path.isdir(gzfolder):
    call( 'mkdir ' + gzfolder, shell=True)


call( 'cd ' + path + ' && ' + ' tcpflow -r ../' + filename, shell=True)

for flows in glob.glob(path+'/*.*.*'):
    iFile = open( flows, 'rb' )
    word = iFile.read(1)
    while word != '':
        if hex( ord(word) ) == '0x1f':
            word = iFile.read(1)
            if hex( ord(word) ) == '0x8b':
                oFile = open( gzfolder + '/flow' + str(flowcount) + '.gz', 'wb' )
                oFile.write( '\x1f\x8b' )
                flowcount += 1
                while word != '':
                    word = iFile.read(1)
                    oFile.write(word)
                call( 'gunzip ' + gzfolder + '/flow' + str(flowcount) + '.gz', shell=True) 
                call( 'rm ' + gzfolder + '/flow' + str(flowcount) + '.gz', shell=True)
        word = iFile.read(1)

                
    
    


