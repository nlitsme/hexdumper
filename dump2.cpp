#include <stdint.h>
#include <iostream>
#include <fcntl.h>
#include <optional>
#include <cpputils/hexdumper.h>
#include <cpputils/argparse.h>

#include <cpputils/mmem.h>
#include <cpputils/fhandle.h>
#ifdef __MACH__
#include "machmemory.h"
#endif

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
struct DumpParams {
    std::optional<int64_t> offset;
    std::optional<int64_t> endOffset;
    std::optional<int64_t> length;
    std::optional<int64_t> baseOffset;
    std::optional<int64_t> fileSize;

    int dumpUnitSize = 1;
    int unitsPerLine = 0;
    uint64_t stepSize = 0;
    int dumpformat = DUMP_BOTH;
    bool summarize = true;
    std::optional<int> summarizeThreshold;


    bool resolveSizes()
    {
        if (!baseOffset)
            baseOffset = 0;

        // determine start
        if (!offset)
            offset = baseOffset;
        else if (*offset < 0) {
            if (!fileSize) {
                printf("Can't use negative offsets, when filesize is unknown\n");
                return false;
            }
            offset = *baseOffset + *offset + *fileSize;
        }

        // determine end
        if (!length && !endOffset)
        {
            if (fileSize) {
                endOffset = *baseOffset + *fileSize;
                length = *endOffset - *offset;
            }
            // else: filesize, length unknown - until EOF.
        }
        else if (!length && endOffset) {
            if (endOffset < 0) {
                if (!fileSize) {
                    printf("Can't use negative offsets, when filesize is unknown\n");
                    return false;
                }
                endOffset = *endOffset + *fileSize;
            }
            length = *endOffset - *offset;
        }
        else if (length && !endOffset) {
            if (length < 0) {
                printf("Can't use negative length\n");
                return false;
            }
            endOffset = *offset + *length;
        }
        else {
            if (endOffset != *offset + *length) {
                printf("inconsistent use of -l, -o and -e\n");
                return false;
            }
        }

        if (*offset < *baseOffset) {
            printf("offset must be >= baseoffset\n");
            return false;
        }
        return true;
    }

    void resolveLineFormat()
    {
        if (unitsPerLine==0) {
            switch(dumpUnitSize)
            {
                case 1: unitsPerLine = 32; break;
                case 2: unitsPerLine = 16; break;
                case 4: unitsPerLine = 8; break;
                case 8: unitsPerLine = 4; break;
            }
            switch(dumpformat)
            {
                case DUMP_BOTH:
                    unitsPerLine /= 2;
                    break;
                case DUMP_ASCII:
                    unitsPerLine = 64;
                    break;
            }
        }

    }

    void applyFormat(std::ostream& os)
    {
        switch(dumpformat)
        {
            case DUMP_ASCII: os << std::right; break;
            case DUMP_HEX: os << std::left; break;
        }
        if (summarizeThreshold)
            os << Hex::summarize_threshold(*summarizeThreshold);
        
        os << std::showpoint;
        os << std::setw(unitsPerLine);
        os << std::setprecision(dumpUnitSize);
        os << std::hex;
        os << Hex::step(stepSize);
        if (summarize)
            os << std::skipws;
        else
            os << std::noskipws;
        os << Hex::offset(*offset);
    }
};
int main(int argc, char**argv)
{
    std::string srcFilename;
    std::string dstFilename;
    DumpParams params;
    int processId = 0;

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

            case 'b': params.baseOffset = arg.getint(); break;  // the offset at file pos 0
            case 'o': params.offset = arg.getint(); break;
            case 'e': params.endOffset = arg.getint(); break;
            case 'l': params.length = arg.getint(); break;
            case 'p': processId = arg.getint(); break;

            case 'w': params.unitsPerLine = arg.getuint(); break;
            case 's': params.stepSize = arg.getuint(); break;
            case 'f': params.summarize = false; break;
            case 'S': params.summarizeThreshold = arg.getuint(); break;
            case 'x': if (arg.count()==2)
                          params.dumpformat = DUMP_ASCII; 
                      else
                          params.dumpformat = DUMP_HEX; 
                      break;
            case '1': case '2': case '4': case '8':
                params.dumpUnitSize = arg.option()-'0';
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

    if (processId==0 && (argsfound==0 || argsfound>2))
    {
        usage();
        return 1;
    }

    params.resolveLineFormat();

    filehandle f;
#ifdef __MACH__
    std::shared_ptr<MachVirtualMemory> vmem;
#endif
    std::shared_ptr<mappedmem> mmem;

    if (!srcFilename.empty()) {
        f = open(srcFilename.c_str(), O_RDONLY);
        params.fileSize = f.size();

        if (!params.resolveSizes())
            return 1;
        mmem = std::make_shared<mappedmem>(f, *params.offset - *params.baseOffset, *params.endOffset - *params.baseOffset, PROT_READ);
    }
#ifdef __MACH__
    else if (processId) {
        try {
        task_t task = MachOpenProcessByPid(processId);
        vmem = std::make_shared<MachVirtualMemory>(task, *params.offset, *params.length);
        }
        catch(std::exception& e)
        {
            std::cout << "ERROR " << e.what() << "\n";
        }
    }
#endif

    params.applyFormat(std::cout);

    if (mmem)
        std::cout << Hex::dumper(mmem->ptr(), mmem->ptr()+*params.length);
#ifdef __MACH__
    else if (vmem)
        std::cout << Hex::dumper(vmem->begin(), vmem->end());
#endif
    else {
        printf("Nothing to do\n");
        return 1;
    }
    return 0;
}
