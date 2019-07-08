#include <stdint.h>
#include <iostream>
#include <fcntl.h>
#include <optional>
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
    printf(R"TEXT(Usage: dump2 [opt] <infile> [outfile]
        -b BASE    -- what offset to give the start of the file.
        -o START   -- where to start dumping
        -e END     -- where to end dumping
        -l SIZE    -- how many bytes to dump
        -w WIDTH   -- nr of items per line
        -s STEP    -- how many bytes to skip between lines
        -f         -- don't summarize, full dump
        -S THRESH  -- summarize threshold
        -x         -- only hex
        -xx        -- only ascii
        -1, -2, -4, -8  -- wordsize
)TEXT");
}
int main(int argc, char**argv)
{
    std::optional<int64_t> llOffset;
    std::optional<int64_t> llEndOffset;
    std::optional<int64_t> llLength;
    std::optional<int64_t> llBaseOffset;

    std::string srcFilename;
    std::string dstFilename;
    int nDumpUnitSize = 1;
    int nUnitsPerLine = 0;
    uint64_t llStepSize = 0;
    int dumpformat = DUMP_BOTH;
    bool bSummarize = true;
    std::optional<int> nSummarizeThreshold;

    int argsfound = 0; 
    for (auto& arg : ArgParser(argc, argv))
        switch(arg.option())
        {
          // options from 'dump', not yet implemented:
          //   -h  : dump hashes
          //   -ripemd160
          //   -sha1, -sha2, -sha3, -sha5, -sum
          //   -md5, -md2, -md4, -md160
          //   -a : strings
          //   -crc
          //   -c : raw selected data to stdout.
          //   -r SIZE  : specify readchunk
          //
          // todo: add choice of reading via stdio, or via mmap
          // todo: add choice of outputting a hexdump, rawdata, stringdump, to dstFilename

            case 'b': llBaseOffset = arg.getint(); break;
            case 'o': llOffset = arg.getint(); break;
            case 'e': llEndOffset = arg.getint(); break;
            case 'l': llLength = arg.getint(); break;

            case 'w': nUnitsPerLine = arg.getuint(); break;
            case 's': llStepSize = arg.getuint(); break;
            case 'f': bSummarize = false; break;
            case 'S': nSummarizeThreshold = arg.getuint(); break;
            case 'x': if (arg.count()==2)
                          dumpformat = DUMP_ASCII; 
                      else
                          dumpformat = DUMP_HEX; 
                      break;
            case '1': case '2': case '4': case '8':
                nDumpUnitSize = arg.option()-'0';
                break;

            case -1:
                switch (argsfound++) {
                    case 0: srcFilename = arg.getstr(); break;
                    case 1: dstFilename = arg.getstr(); break;
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
    filehandle f = open(srcFilename.c_str(), O_RDONLY);
    int64_t llFileSize = f.size();
    if (!llBaseOffset)
        llBaseOffset = 0;

    if (!llOffset)
        llOffset = llBaseOffset;
    else if (llOffset.value() < 0) {
        if (llFileSize < 0) {
            printf("Can't use negative offsets, when filesize is unknown\n");
            return 1;
        }
        llOffset = llOffset.value() + llFileSize;
    }

    if (!llLength && !llEndOffset)
    {
        if (llFileSize >= 0) {
            llEndOffset = llFileSize;
            llLength = llEndOffset.value() - llOffset.value();
        }
        // else: filesize, length unknown - until EOF.
    }
    else if (!llLength && llEndOffset) {
        if (llEndOffset < 0) {
            if (llFileSize < 0) {
                printf("Can't use negative offsets, when filesize is unknown\n");
                return 1;
            }
            llEndOffset = llEndOffset.value() + llFileSize;
        }
        llLength = llEndOffset.value() - llOffset.value();
    }
    else if (llLength && !llEndOffset) {
        if (llLength < 0) {
            printf("Can't use negative length\n");
            return 1;
        }
        llEndOffset = llOffset.value() + llLength.value();
    }
    else {
        if (llEndOffset != llOffset.value() + llLength.value()) {
            printf("inconsistent use of -l, -o and -e\n");
            return 1;
        }
    }

    if (llOffset.value() < llBaseOffset.value()) {
        printf("offset must be >= baseoffset\n");
        return 1;
    }

    mappedmem m(f, llOffset.value() - llBaseOffset.value(), llEndOffset.value() - llBaseOffset.value(), PROT_READ);

    switch(dumpformat)
    {
        case DUMP_ASCII: std::cout << std::right; break;
        case DUMP_HEX: std::cout << std::left; break;
    }
    if (nSummarizeThreshold)
        std::cout << Hex::summarize_threshold(nSummarizeThreshold.value());
    
    std::cout << std::showpoint;
    std::cout << std::setw(nUnitsPerLine);
    std::cout << std::setprecision(nDumpUnitSize);
    std::cout << std::hex;
    std::cout << Hex::step(llStepSize);
    if (bSummarize)
        std::cout << std::skipws;
    std::cout << Hex::offset(llOffset.value());
    std::cout << Hex::dumper(m.ptr(), m.ptr()+llLength.value());

}
