#include <stdint.h>
#include <iostream>
#include <fcntl.h>
#include "hexdumper.h"
#include "argparse.h"

#include "mmem.h"
#include "fhandle.h"

enum {
    DUMP_BOTH,
    DUMP_HEX,
    DUMP_ASCII,
};

void usage()
{
    printf("Usage: dump2 [opt] <infile>\n");
    // -b, -o, -e, -l, -w, -s, -f, -S, -x
}
int main(int argc, char**argv)
{
    int64_t llOffset=0;
    int64_t llEndOffset=0;
    int64_t llLength=0;
    int64_t llBaseOffset=0;
    std::string srcFilename;
    std::string dstFilename;
    int nDumpUnitSize=1;
    int nUnitsPerLine= 0;
    uint64_t llStepSize= 0;
    int dumpformat = DUMP_BOTH;
    bool bSummarize = true;
    int nSummarizeThreshold = 2;

    int argsfound=0; 
    for (auto& arg : ArgParser(argc, argv))
        switch(arg.option())
        {
            case 'b': llBaseOffset = arg.getint(); break;
                      // 'h' : dump hashes
            case 'o': llOffset = arg.getint(); break;
            case 'e': llEndOffset = arg.getint(); break;
            case 'l': llLength = arg.getint(); break;

                      // 'ripemd160'
                      // 'h' : chunksize
            case 'w': nUnitsPerLine = arg.getuint(); break;
            case 's': llStepSize = arg.getuint(); break;
                      // -sha1, -sha2, -sha3, -sha5, -sum
                      // -md5, -md2, -md4, -md160
                      // -a : strings
                      // -crc
                      // -c : raw
            case 'f': bSummarize = false; break;
            case 'S': nSummarizeThreshold = arg.getuint(); break;
            case 'x': if (arg.count()==2)
                          dumpformat= DUMP_ASCII; 
                      else
                          dumpformat= DUMP_HEX; 
                      break;
            case '1': case '2': case '4': case '8':
                nDumpUnitSize= arg.option()-'0';
                break;

            case -1:
                switch (argsfound++) {
                    case 0: srcFilename= arg.getstr(); break;
                    case 1: dstFilename= arg.getstr(); break;
                }
                break;

            default:
                usage();
                return 1;
        }

    if (argsfound==0 || argsfound>2)
    {
        usage();
        return 1;
    }
    if (nUnitsPerLine==0) {
        switch(nDumpUnitSize)
        {
            case 1: nUnitsPerLine = 32; break;
            case 2: nUnitsPerLine = 16; break;
            case 4: nUnitsPerLine = 8; break;
            case 8: nUnitsPerLine = 4; break;
        }
        switch(dumpformat)
        {
            case DUMP_BOTH:
                nUnitsPerLine /= 2;
                break;
            case DUMP_ASCII:
                nUnitsPerLine = 64;
                break;
        }
    }
    if (llLength==0)
    {
        if (llEndOffset)
            llLength = llEndOffset-llOffset;
        else
            llLength = 0x100;
    }

    filehandle f= open(srcFilename.c_str(), O_RDONLY);
    // todo: add choice of reading via stdio, or via mmap
    mappedmem m(f, llOffset, llOffset+llLength, PROT_READ);

    switch(dumpformat)
    {
        case DUMP_ASCII: std::cout << std::right; break;
        case DUMP_HEX: std::cout << std::left; break;
    }
    // todo: llBaseOffset
    // todo: dstFilename
    // todo: nSummarizeThreshold 
    std::cout << std::showpoint;
    std::cout << std::setw(nUnitsPerLine);
    std::cout << std::setprecision(nDumpUnitSize);
    std::cout << std::hex;
    std::cout << hex::step(llStepSize);
    if (bSummarize)
        std::cout << std::skipws;
    std::cout << hex::offset(llOffset);
    std::cout << hex::dumper(m.ptr(), m.ptr()+llLength);

}
