#include <stdint.h>
#include <string.h>
#include <algorithm>
#include <vector>
#include "argparse.h"
#include "formatter.h"
#include <sys/mman.h>
#include <sys/errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "mmem.h"
#include "fhandle.h"

void copydata(uint8_t *dst, const uint8_t *src, int size, int access)
{
    switch(access)
    {
        case 1: std::copy_n((const uint8_t *)src, size/1, (uint8_t *)dst); break;
        case 2: std::copy_n((const uint16_t*)src, size/2, (uint16_t*)dst); break;
        case 4: std::copy_n((const uint32_t*)src, size/4, (uint32_t*)dst); break;
        case 8: std::copy_n((const uint64_t*)src, size/8, (uint64_t*)dst); break;
    }
}

void mmdump(int f, uint64_t offset, uint64_t length, uint64_t step, uint64_t width, int access, int mmapmode)
{
    mappedmem m(f, offset, offset+length, mmapmode);

    std::vector<uint8_t> data(width);
    for (uint8_t *p= m.ptr() ; p<m.ptr()+length ; p+=step)
    {
        uint64_t want= std::min((uint64_t)(m.ptr()+length-p), width);
        copydata(&data[0], p, want, access);
        if (want<width)
            std::fill(&data[want], &data[width], 0);
        switch(access)
        {
        case 1: print("%08llx: %b", offset, std::vector<uint8_t>(&data[0], &data[0]+width/access));
        case 2: print("%08llx: %b", offset, std::vector<uint16_t>(&data[0], &data[0]+width/access));
        case 4: print("%08llx: %b", offset, std::vector<uint32_t>(&data[0], &data[0]+width/access));
        case 8: print("%08llx: %b", offset, std::vector<uint64_t>(&data[0], &data[0]+width/access));
        }

        offset += step;
    }
}
void mmsave(int f, int of, uint64_t offset, uint64_t length, int mmapmode)
{
    mappedmem m(f, offset, offset+length, mmapmode);

    write(of, m.ptr(), length);
}

void usage()
{
    printf("Usage: mmfile [options] file [outfile]\n");
    printf("   -o OFFSET     start offset\n");
    printf("   -l LENGTH     nr of bytes\n");
    printf("   -s STEP       after each line, skip STEP bytes\n");
    printf("   -m            call mmap for each step\n");
    printf("                 default: call mmap once for entire range\n");
    printf("   -w WIDTH      nr of items per line\n");
    printf("   -W            open in read/write mode\n");
    printf("   -1,-2,-4      size of items to display\n");
    printf("note: pagesize= %08x\n", getpagesize());
}
int main(int argc, char**argv)
{
    uint64_t offset= 0;  bool offset_specified= false;
    uint64_t length= 0x1000;  bool length_specified= false;
    uint64_t step= 0;  bool step_specified= false;
    uint64_t width= 0;  bool width_specified= false;

    std::string filename;
    std::string outname;
    int access= 0;
    int openmode= O_RDONLY;
    int mmapmode= PROT_READ;

    bool devicestep= false;

    try {
    for (auto& arg : ArgParser(argc, argv))
        switch (arg.option())
        {
            case 'o': offset= arg.getint(); offset_specified= true; break;
            case 'l': length= arg.getint(); length_specified= true; break;
            case 's': step= arg.getint(); step_specified= true; break;
            case 'w': width= arg.getint(); width_specified= true; break;
            case '1': access= 1; break;
            case '2': access= 2; break;
            case '4': access= 4; break;
            case 'W': openmode= O_RDWR; mmapmode= PROT_READ|PROT_WRITE; break;
            case 'm': devicestep= true; break;
            case -1:
                if (filename.empty())
                    filename= arg.getstr();
                else if (outname.empty())
                    outname= arg.getstr();
                break;     
            default:
                      usage();
                      return 1;
        }
    if (access==0)
        access= 1;
    if (!width_specified)
        width= 16;
    if (!step_specified)
        step= width;

    if (filename.empty()) {
        usage();
        return 1;
    }
    //printf("mm(%08llx, %08llx): s=%llx, w=%llx\n", offset, length, step, width);
    filehandle f= open(filename.c_str(), openmode);
    if (f==-1) {
        perror(filename.c_str());
        return 1;
    }
    if (outname.empty()) {
        if (!devicestep) {
            mmdump(f, offset, length, step, width, access, mmapmode);
        }
        else {
            for (uint64_t o= offset ; o<offset+length ; o+=step)
                mmdump(f, o, width, width, width, access, mmapmode);
        }
    }
    else {
        int of= open(outname.c_str(), O_RDWR|O_CREAT, 0666);
        if (of==-1) {
            perror ("saving");
            return 1;
        }
        if (!devicestep) {
            mmsave(f, of, offset, length, mmapmode);
        }
        else {
            for (uint64_t o= offset ; o<offset+length ; o+=step)
                mmsave(f, of, o, width, mmapmode);
        }
    }

    }
    catch (const char*msg)
    {
        printf("E: %s\n", msg);
        return 1;
    }

    return 0;
}
