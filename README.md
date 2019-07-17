dump
====

Generic file / device hexdumping tool.
I use this tool in most of my reverse engineering projects as a first step, for investigating
the basic structure of unknown files.

 * you can specify an alternate offset for offset 0 of the file. ( `-b` )
 * you can select the dump section of the file by specify a starting offset + length, or a starting offset + end offset.
 * negative values for offsets or lengths are with respect to the end of file.
 * you can specify the number of elements printed on each line. ( `-w` )
 * you can specify a step size, when you want only one line for every `STEPSIZE` bytes. ( `-s` )
 * you can specify the element size printed ( -1, -2, -4, -8 ) for byte, word, dword, qword
 * you can calculate the hash, checksum or crc of a section of the file.
 * when combined with step + width ( `-s` and `-w` ) a hash is printed for each WIDTH bytes every of STEPSIZE chunk of the file.
 * repeating lines are summarized.
 * you can have a hexdump with either hexbytes, hex + ascii, only ascii. or a string dump. ( `-a`, `-x`, `-xx` )
 * you can read from files, block devices, stdin.
 * you can copy the selected file section to stdout or another file. ( `-c` or filename )


options
-------

 * -b BASEOFFSET   make listing appear at the specified offset
 * -h              print all known cryptographic hashes for the selection
 * -o START        start offset for selection, taking into account the base offset.
 * -e END          end offset for the selection
 * -l LENGTH       length starting at 'start', either specify '-e' or '-l'
 * -r CHUNKSIZE    in what chunks to read from the file/device.
 * -w DISPLAYWIDTH how many items to print on each line
 * -s STEPSIZE     amount to skip forward after each line.
 * -a              output as strings, one per line.
 * -c              output the raw bytes
 * -f              don't summarize identical lines
 * -S THRESHOLD    minimum number of identical lines to sumarize
 * -x              hexdump only, no ascii
 * -xx             ascii only, no hexdump
 * -1, -2, -4, -8  size of items to print ( byte, short, dword, qword )
 * -md5, -md160, -md2, -md5, -sha1, -sha256, -sha384, -sha512  various types o hashes.
 * -crc[:start:poly] what crc to calculate.
 * -sum            print various types of checksums.

 * an input file.
 * optionally a output file.



dump2
=====

Like dump, but uses mmap for opening files, and uses cpputils/hexdumper.h.
`dump2` does not have the hashing and summing options, but does do better with
handling summarizing, and also the -b (baseoffset) option works better.


mmdump
======

Hexdump memory mapped devices.
I used this tool to investigate disk devices on android phones.


mmedit
======

Edit memory mapped devices.
I use this tool to make patches to disk devices on android phones.

Author
======

Willem Hengeveld <itsme@xs4all.nl>

