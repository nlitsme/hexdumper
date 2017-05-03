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
 * you can not hexdump, but copy the selected file section to stdout or another file. ( `-c` or filename )


dump2
=====

Like dump, but uses mmap for opening files, and uses cpputils/hexdumper.h




Author
======

Willem Hengeveld <itsme@xs4all.nl>

