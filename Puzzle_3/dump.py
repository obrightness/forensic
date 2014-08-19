#! /usr/bin/python2.7


filename = 'stream1'
ofilename = 'stream1.out'
File = open( filename, 'rb' )
oFile = open( ofilename, 'wb' )
while True:
    word = File.read(1)
    if hex( ord(word) ) == '0x1f':
        word = File.read(1)
        if hex( ord(word) ) == '0x8b':
            break

oFile.write('\x1f\x8b')
word = File.read(1)

while word != '':
    oFile.write(word)
    word = File.read(1)





