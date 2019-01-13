/* (C) 2003-2007 Willem Jan Hengeveld <itsme@xs4all.nl>
 * Web: http://www.xs4all.nl/~itsme/
 *      http://wiki.xda-developers.com/
 *
 * $Id$
 *
 * this program provides various ways of (hex) dumping sections of binary files
 *
 */
// DONE:
// ? dump 8000.mem -o 0x02400000 -s 0x400 -xx
// ? does not work as it should, .. offsets seem to be double from their real value.
//   ... bug seems to have disappeared
//
// DONE:
//   dump of a very large file ( >2M ) with all 0s
//   the summary lines are not printed.

// todo:
//    * DONE think of way to make winxp support sha256: now using openssl
//    * DONE add simple add-checksum , and xor-checksum support
//    * DONE make '*' summary only print '*' when more than X lines are the same
//    * bug: "dump -s 16 -w 8 -4 -x x.nb"  should not print ascii part in line.
//        problem is incompatible interface to bighexdump and hexdump
//        other problem is that the hexdumper has no state.
//    * improved hexdumper
//    * check for identical lines -before- converting to string
//    * use MmapReader/FileReader/BlockDevice where appropriate
//    * bug: dump -o 0x14 -f -4 -w 22 -s 0x56  file
//        -> crash
//    * bug: "dump - -o 11 -e 0x20d"  should give the same output as "dump - -o 11 -l 0x202" -> it does not!
//
// done:
//    * dump -s STEP {-md5|-sum}
//       should print hash/sum of each step block. ( and default to blocksize=stepsize )
//
//
//note: you can use dump also to read block devices, 
//  dump \\.\PhysicalDrive0 -xx -o 0  -l 0xa00000000 -s 0x100000000
// will dump 64 ascii chars every 4G of your 40G disk.
//
// 
#define __STDC_LIMIT_MACROS
#ifndef NOMINMAX
#define NOMINMAX
#endif
//#include <util/wintypes.h>
#include <stdio.h>
#ifdef _WIN32
#include <io.h>
#endif
#ifndef _WIN32
#include <sys/stat.h>

#ifdef __MACH__
#include <sys/disk.h>
#endif
#ifdef __linux__
#include <linux/fs.h>
#endif

#include <sys/ioctl.h>
#include <unistd.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif

#include <fcntl.h>

#ifdef _USE_WINCRYPTAPI
#include "dump_hash.h"
#elif defined(_USE_OPENSSL)
#include "dump_ossl_hash.h"
#elif defined(__ANDROID__)
#include "dump_android_hash.h"
#else
#include "dump_dummy_hash.h"
#endif

#include "dump_crc32.h"
#include "dump_sum.h"
#include "bighexdump.h"
#include "bigascdump.h"
#include "formatter.h"
#include "stringlibrary.h"
#include "argparse.h"
#include <stdint.h>
#include <string.h>
#include <algorithm>
#include "hexdumper.h"

#define vectorptr(v)  ((v).empty()?NULL:&(v)[0])

namespace std {
size_t min(int64_t a, size_t b)
{
#ifdef _WIN32
    return (a<b) ? a : b;
#else
    return b>=__INTMAX_MAX__ ? a : (a<b) ? a : b;
#endif
}
}
DumpUnitType g_dumpunit=DUMPUNIT_BYTE;
DumpFormat g_dumpformat= DUMP_HEX_ASCII;
int g_hashtype= 0;
uint64_t g_crc_initval= 0;
uint64_t g_crc_poly= 0xEDB88320;
uint64_t g_crc_bits= 32;

int g_nMaxUnitsPerLine=-1;
int64_t g_llStepSize= 0;

bool g_fulldump= false;
int g_summarizeThreshold=-1;

uint32_t g_chunksize= 1024*1024;

std::string hexstring(const std::vector<uint8_t>& bv)
{
    return stringformat("%-b", bv);
}
std::string hexdump(uint64_t ofs, const uint8_t *p, size_t n, int type, int width)
{
    std::stringstream buf;
    buf << Hex::offset(ofs) << std::hex << std::setw(width) << std::left;
    switch(type)
    {
        case 1: buf << Hex::dumper((const uint8_t*)p, n); break;
        case 2: buf << Hex::dumper((const uint16_t*)p, n); break;
        case 4: buf << Hex::dumper((const uint32_t*)p, n); break;
        case 8: buf << Hex::dumper((const uint64_t*)p, n); break;
    }
    return buf.str();
}
uint64_t invmask(int bits)
{
    return (uint64_t(1)<<bits)-1;
}


// skipbytes is used for non-seekable files ( like stdin )
void skipbytes(FILE *f, int64_t skip)
{
    std::vector<uint8_t> buf;
    buf.resize(std::min(skip,g_chunksize));

    while (skip) {
        size_t want= std::min(skip,buf.size());
        fread(vectorptr(buf), 1, want, f);
        skip-=want;
    }
}

// seek > 4G when only 32 bit api is available.
int longseek(FILE *f, int64_t delta, int type)
{
    // todo: lseek64(fileno(f), delta, type);
#if defined(_ANDROID) || defined(ANDROID)
    if (type!=SEEK_CUR) {
        if (delta<0x40000000) {
            return fseek(f, delta, type);
        }
        return fseek(f, 0, type);
    }
    if (delta>0) {
        while (delta>=0x40000000) {
            fseek(f, 0x40000000, SEEK_CUR);
            delta -= 0x40000000;
        }
        return fseek(f, delta, SEEK_CUR);
    }
    else {
        while (delta<=-0x40000000) {
            fseek(f, -0x40000000, SEEK_CUR);
            delta += 0x40000000;
        }
        return fseek(f, delta, SEEK_CUR);
    }
#elif defined(_WIN32)
    return _fseeki64(f, delta, type);
#else
    return fseeko(f, delta, type);
#endif
}

// hexdump stepped chunks of the file.
bool StepFile(const std::string& srcFilename, int64_t llBaseOffset, int64_t llOffset, int64_t llLength)
{
    std::vector<uint8_t> buffer;
    std::string prevline;
    int nSameCount= 0;

    bool fromStdin= srcFilename=="-";

    FILE *f= NULL;
    if (fromStdin) {
        f= stdin;
#ifdef WIN32
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            print("ERROR: _setmode(stdin, rb)");
            return false;
        }
#endif
    }
    else {
        f= fopen(srcFilename.c_str(), "rb");
    }

    if (f==NULL) {
        perror(srcFilename.c_str());
        return false;
    }

    if (f==stdin) {
        skipbytes(f, llOffset-llBaseOffset);
    }
    else if (longseek(f, llOffset-llBaseOffset, SEEK_SET))
    {
        fclose(f);
    }


#ifdef _USE_WINCRYPTAPI
    CryptProvider cprov;
#endif
    while (llLength>0)
    {
        buffer.resize(DumpUnitSize(g_dumpunit)*g_nMaxUnitsPerLine);

        uint32_t dwBytesWanted= std::min(llLength,buffer.size());
        std::string line;
        uint32_t dwNumberOfBytesRead= fread(vectorptr(buffer), 1, dwBytesWanted, f);
        if (dwNumberOfBytesRead==0)
            break;
        if (g_dumpformat==DUMP_RAW) {
            line.clear();
        }
        else if (g_dumpformat==DUMP_HASH) {
#ifdef _USE_WINCRYPTAPI
            CryptHash hashcalc(cprov);
#define HASHTYPEOFFSET (ALG_CLASS_HASH | ALG_TYPE_ANY)
#else
            CryptHash hashcalc;
#define HASHTYPEOFFSET 0
#endif
            hashcalc.InitHash(g_hashtype);
            hashcalc.AddData(buffer);

            std::vector<uint8_t> hash = hashcalc.GetHash();
            line= hexstring(hash);
        }
        else if (g_dumpformat==DUMP_HASHES) {
typedef std::vector<CryptHash*> CryptHashList;
            CryptHashList hashes;

#define VALIDALGS 0x701e
            for (int ihash=0 ; ihash<CryptHash::HASHTYPECOUNT ; ihash++) {
#ifdef _USE_WINCRYPTAPI
                if (((1<<ihash)&VALIDALGS)==0)
                    continue;
                hashes.push_back(new CryptHash(cprov));
#else
                hashes.push_back(new CryptHash);
#endif
                try {
                hashes.back()->InitHash(ihash+HASHTYPEOFFSET);
                }
                catch(...) {
                    delete hashes.back();
                    hashes.resize(hashes.size()-1);
                }
            }
            for (CryptHashList::iterator ih= hashes.begin() ; ih!=hashes.end() ; ih++)
            {
                (*ih)->AddData(buffer);
            }
            line.clear();
            for (CryptHashList::iterator ih= hashes.begin() ; ih!=hashes.end() ; ih++)
            {
                std::vector<uint8_t> hash = (*ih)->GetHash();
                if (!line.empty())
                    line += " ";
                line += hexstring(hash);
            }
        }
        else if (g_dumpformat==DUMP_CRC32) {
            CRC32 crc(g_crc_initval, g_crc_poly, g_crc_bits);
            crc.add_data(vectorptr(buffer), buffer.size());
            line= stringformat("%08lx~%08lx", crc.crc, crc.crc^invmask(g_crc_bits));
        }
        else if (g_dumpformat==DUMP_SUM) {
            DATASUM sum;
            CRC32 crc(g_crc_initval, g_crc_poly, g_crc_bits);
            CRC32 crc1(~g_crc_initval, g_crc_poly, g_crc_bits);
            sum.add_data(vectorptr(buffer), buffer.size());
            crc.add_data(vectorptr(buffer), buffer.size());
            crc1.add_data(vectorptr(buffer), buffer.size());

            line= stringformat("%08llx~%08llx  %08llx~%08llx +%02llx LE:%04llx %08llx %16llx BE:%04llx %08llx %16llx ^%02x %04x %08lx %016llx", 
                crc.crc, crc.crc^invmask(g_crc_bits), crc1.crc, crc1.crc^invmask(g_crc_bits), 
                sum.sum1, sum.sum2_le, sum.sum4_le, sum.sum8_le, sum.sum2_be, sum.sum4_be, sum.sum8_be,
                sum.sumxor1, sum.sumxor2, sum.sumxor4, sum.sumxor8);
        }
        else if (g_dumpformat==DUMP_STRINGS)
            line= bigascdump(buffer);
        else if (g_dumpformat==DUMP_ASCII)
            line= asciidump(vectorptr(buffer), dwNumberOfBytesRead);
        else {
            line= hexdump(llOffset, vectorptr(buffer), dwNumberOfBytesRead, DumpUnitSize(g_dumpunit), g_nMaxUnitsPerLine);
            line.erase(0, line.find_first_of(' ')+1);
        }
        if (*line.rbegin()=='\n')
            line.resize(line.size()-1);

        if (g_dumpformat==DUMP_RAW)
            fwrite(&buffer[0], 1, buffer.size(), stdout);
        else if (!g_fulldump && line == prevline) {
            nSameCount++;
        }
        else {
            if (nSameCount>0 && (g_summarizeThreshold==-1 || nSameCount<=g_summarizeThreshold)) {
                for (int i=0 ; i<nSameCount ; i++)
                    writedumpline(llOffset+g_llStepSize*(signed(i)-nSameCount), prevline);
            }
            else if (nSameCount>0 && g_summarizeThreshold>0 && nSameCount>g_summarizeThreshold)
                print("*  [ 0x%x lines ]\n", nSameCount);
            nSameCount= 0;
            writedumpline(llOffset, line);
        }
        prevline= line;
        int64_t llStep= std::min(llLength, g_llStepSize);
        if (f==stdin) {
            skipbytes(f, llStep-dwNumberOfBytesRead);
        }
        else if (longseek(f, llStep-dwNumberOfBytesRead, SEEK_CUR))
        {
            fclose(f);
        }
        llLength -= llStep;
        llOffset += llStep;
    }
    fclose(f);

    if (g_dumpformat!=DUMP_RAW) {
        if (nSameCount==1)
            writedumpline(llOffset-g_llStepSize, prevline);
        else if (nSameCount>1)
            print("*  [ 0x%x lines ]\n", nSameCount);
        writedumpline(llOffset, "");
    }

    return true;
}

// normal hexdump of file
bool Dumpfile(const std::string& srcFilename, int64_t llBaseOffset, int64_t llOffset, int64_t llLength)
{
    if (g_nMaxUnitsPerLine>=MAXUNITSPERLINE) {
        printf("WARNING: -w 0x%x too large\n", g_nMaxUnitsPerLine);
        return false;
    }
    uint32_t flags= hexdumpflags(g_dumpunit, g_nMaxUnitsPerLine, g_dumpformat)
        | (g_fulldump?0:HEXDUMP_SUMMARIZE) | (g_dumpformat==DUMP_RAW?0:HEXDUMP_WITH_OFFSET);

    bool fromStdin= srcFilename=="-";

    FILE *f= NULL;
    if (fromStdin) {
        f= stdin;
#ifdef WIN32
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            print("ERROR: _setmode(stdin, rb)");
            return false;
        }
#endif
    }
    else {
        f= fopen(srcFilename.c_str(), "rb");
    }
    if (f==NULL) {
        perror(srcFilename.c_str());
        return false;
    }

    if (f==stdin) {
        skipbytes(f, llOffset-llBaseOffset);
    }
    else if (longseek(f, llOffset-llBaseOffset, SEEK_SET))
    {
        fclose(f);
    }

#ifdef _USE_WINCRYPTAPI
    CryptProvider cprov;
    CryptHash hashcalc(cprov);
#define HASHTYPEOFFSET (ALG_CLASS_HASH | ALG_TYPE_ANY)
#else
    CryptHash hashcalc;
#define HASHTYPEOFFSET 0
#endif
    if (g_dumpformat==DUMP_HASH)
        hashcalc.InitHash(g_hashtype);

typedef std::vector<CryptHash*> CryptHashList;
    CryptHashList hashes;
    if (g_dumpformat==DUMP_HASHES) {

        for (int ihash=0 ; ihash<CryptHash::HASHTYPECOUNT ; ihash++) {
#ifdef _USE_WINCRYPTAPI
            hashes.push_back(new CryptHash(cprov));
#else
            hashes.push_back(new CryptHash);
#endif
            try {
            hashes.back()->InitHash(ihash+HASHTYPEOFFSET);
            }
            catch(...) {
                delete hashes.back();
                hashes.resize(hashes.size()-1);
            }
        }
    }

    DATASUM sum;
    CRC32 crc(g_crc_initval, g_crc_poly, g_crc_bits);
    CRC32 crc1(~g_crc_initval, g_crc_poly, g_crc_bits);

    std::vector<uint8_t> buf;
    while (llLength>0)
    {
        buf.resize(g_chunksize);
        uint32_t dwBytesWanted= std::min(llLength,buf.size());
        uint32_t nRead= fread(vectorptr(buf), 1, dwBytesWanted, f);

        if (nRead==0)
            break;

        buf.resize(nRead);

        if (g_dumpformat==DUMP_HASH) {
            hashcalc.AddData(buf);
        }
        else if (g_dumpformat==DUMP_HASHES) {
            for (CryptHashList::iterator ih= hashes.begin() ; ih!=hashes.end() ; ih++)
                (*ih)->AddData(buf);
        }
        else if (g_dumpformat==DUMP_CRC32) {
            crc.add_data(vectorptr(buf), buf.size());
        }
        else if (g_dumpformat==DUMP_SUM) {
            sum.add_data(vectorptr(buf), buf.size());
            crc.add_data(vectorptr(buf), buf.size());
            crc1.add_data(vectorptr(buf), buf.size());
        }
        else if (g_dumpformat==DUMP_RAW)
            fwrite(&buf[0], 1, buf.size(), stdout);
        else
            bighexdump(llOffset, buf, flags | (llLength!=nRead ? HEXDUMP_MOREFOLLOWS : 0) );

        llLength -= nRead;
        llOffset += nRead;
    }
    fclose(f);
    if (g_dumpformat==DUMP_HASH) {
        std::vector<uint8_t> hash = hashcalc.GetHash();
        print("%s\n", hexstring(hash));
    }
    else if (g_dumpformat==DUMP_HASHES) {
        for (CryptHashList::iterator ih= hashes.begin() ; ih!=hashes.end() ; ih++)
        {
            std::vector<uint8_t> hash = (*ih)->GetHash();
            print("%-10s: %s\n", (*ih)->hashname(), hexstring(hash));
        }
    }
    else if (g_dumpformat==DUMP_CRC32) {
        print("crc=%08llx invcrc=%08llx\n", crc.crc, crc.crc^invmask(g_crc_bits));
    }
    else if (g_dumpformat==DUMP_SUM) {
        print("crc0=%08llx invcrc=%08llx\n", crc.crc, crc.crc^invmask(g_crc_bits));
        print("crc-1=%08llx invcrc=%08llx\n", crc1.crc, crc1.crc^invmask(g_crc_bits));
        print("addsum=%02llx LE:%04llx %08llx %16llx BE:%04llx %08llx %16llx sumxor=%02x %04x %08lx %016llx\n", 
                sum.sum1, sum.sum2_le, sum.sum4_le, sum.sum8_le,
                sum.sum2_be, sum.sum4_be, sum.sum8_be,
                sum.sumxor1, sum.sumxor2, sum.sumxor4, sum.sumxor8);
    }
    return true;
}

// copy multiple chunks of srcfile to dstfile
bool CopyFileSteps(const std::string& srcFilename, const std::string& dstFilename, int64_t llBaseOffset, int64_t llOffset, int64_t llLength)
{
    std::vector<uint8_t> buffer;

    bool fromStdin= srcFilename=="-";

    FILE *f= NULL;
    if (fromStdin) {
        f= stdin;
#ifdef WIN32
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            print("ERROR: _setmode(stdin, rb)");
            return false;
        }
#endif
    }
    else {
        f= fopen(srcFilename.c_str(), "rb");
    }
    if (f==NULL) {
        perror(srcFilename.c_str());
        return false;
    }

    if (f==stdin) {
        skipbytes(f, llOffset-llBaseOffset);
    }
    else if (longseek(f, llOffset-llBaseOffset, SEEK_SET))
    {
        fclose(f);
    }
    FILE *g= fopen(dstFilename.c_str(), "w+b");
    if (g==NULL) {
        perror(dstFilename.c_str());
        return false;
    }


    while (llLength>0)
    {
        buffer.resize(DumpUnitSize(g_dumpunit)*g_nMaxUnitsPerLine);

        uint32_t dwBytesWanted= std::min(llLength,buffer.size());
        uint32_t dwNumberOfBytesRead= fread(vectorptr(buffer), 1, dwBytesWanted, f);
        if (dwNumberOfBytesRead==0)
            break;

        fwrite(&buffer[0], 1, buffer.size(), g);

        int64_t llStep= std::min(llLength, g_llStepSize);
        if (f==stdin) {
            skipbytes(f, llStep-dwNumberOfBytesRead);
        }
        else if (longseek(f, llStep-dwNumberOfBytesRead, SEEK_CUR))
        {
            fclose(f);
        }

        llLength -= llStep;
        llOffset += llStep;
    }
    fclose(g);
    fclose(f);
    return true;
}

// copy section of srcfile to dstfile
bool Copyfile(const std::string& srcFilename, const std::string& dstFilename, int64_t llBaseOffset, int64_t llOffset, int64_t llLength)
{
    FILE *f= NULL;

    bool fromStdin= srcFilename=="-";

    if (fromStdin) {
        f= stdin;
#ifdef WIN32
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            print("ERROR: _setmode(stdin, rb)");
            return false;
        }
#endif
    }
    else {
        f= fopen(srcFilename.c_str(), "rb");
    }
    if (f==NULL) {
        perror(srcFilename.c_str());
        return false;
    }

    if (f==stdin) {
        skipbytes(f, llOffset-llBaseOffset);
    }
    else if (longseek(f, llOffset-llBaseOffset, SEEK_SET))
    {
        fclose(f);
    }
    FILE *g= fopen(dstFilename.c_str(), "w+b");
    if (g==NULL) {
        perror(dstFilename.c_str());
        return false;
    }

    std::vector<uint8_t> buf;
    while (llLength>0)
    {
        buf.resize(g_chunksize);
        uint32_t dwBytesWanted= std::min(llLength,buf.size());
        uint32_t nRead= fread(vectorptr(buf), 1, dwBytesWanted, f);

        if (nRead==0)
            break;

        buf.resize(nRead);

        fwrite(&buf[0], 1, buf.size(), g);

        llLength -= nRead;
        llOffset += nRead;
    }

    fclose(g);
    fclose(f);
    return true;
}

// filesize for various platforms, files, blockdevice.
int64_t GetFileSize(const std::string& filename)
{
#ifdef WIN32
    HANDLE hSrc = CreateFile(filename.c_str(), GENERIC_READ, FILE_SHARE_WRITE|FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hSrc)
    {
        print("ERROR: Unable to open file %s", filename.c_str());
        return 0;
    }

    DWORD dwSizeH;
    DWORD dwSizeL= GetFileSize(hSrc, &dwSizeH);

    CloseHandle(hSrc);

    return ((int64_t)dwSizeH<<32)+dwSizeL;
#else
    struct stat st;
    if (lstat(filename.c_str(), &st)) {
        print("ERROR: lstat");
        return 0;
    }
    if (st.st_mode&S_IFREG)
        return st.st_size;
    else if (st.st_mode&S_IFBLK) {
        int h= open(filename.c_str(), O_RDONLY);
        uint64_t devsize;
#ifdef DKIOCGETBLOCKCOUNT
        uint64_t bkcount;
        uint32_t bksize;
        if (-1==ioctl(h, DKIOCGETBLOCKCOUNT, &bkcount)) {
            close(h);
            print("ERROR: ioctl(DKIOCGETBLOCKCOUNT)");
            return 0;
        }
        if (-1==ioctl(h, DKIOCGETBLOCKSIZE, &bksize)) {
            close(h);
            print("ERROR: ioctl(DKIOCGETBLOCKSIZE)");
            return 0;
        }
        devsize = bkcount*bksize;
#endif
#ifdef BLKGETSIZE64
        if (-1==ioctl(h, BLKGETSIZE64, &devsize)) {
            close(h);
            print("ERROR: ioctl(BLKGETSIZE64)");
            return 0;
        }
#endif
        close(h);
        return devsize;
    }
    else {
        printf("could not get size for device\n");
        return -1;
    }
#endif
}
void usage()
{
    printf("(C) 2003-2008 Willem jan Hengeveld  itsme@xs4all.nl\n");
    printf("Usage: dump [options] FILENAME  [OUTFILENAME]\n");
    printf("   when outfilename is specified, the binary data is writen to it.\n");
    printf("    -b BASE   : specify base offset - what offset has first byte of the file\n");
    printf("    -o OFS    : what offset to display\n");
    printf("    -l LEN    : length to dump\n");
    printf("    -e OFS    : end offset ( alternative for -l )\n");
    printf("    -w N      : how many words to print on each line\n");
    printf("    -s SIZE   : step with SIZE through memory\n");
    printf("    -r SIZE   : read chunk size, default 1M\n");
    printf("    -1,2,4    : what to print: byte, word, dword\n");
    printf("    -a     : ascdump iso hexdump\n");
#ifdef MD5_DIGEST_LENGTH
    printf("    -md5   : print md5sum of selected memory range\n");
#endif
#ifdef SHA1_DIGEST_LENGTH
    printf("    -sha1  : print sha1 of selected memory range\n");
#endif
#ifdef SHA256_DIGEST_LENGTH
    printf("    -sha256: print sha256 of selected memory range\n");
#endif
    printf("    -crc   : print crc32 of selected memory range\n");
    printf("    -crc:INIT:POLY:bits  default: -crc:0:0xEDB88320:32\n");
    printf("    -sum   : print checksums of selected memory range\n");
    printf("    -h     : calc all known hash types\n");
    printf("    -f     : full - do not summarize identical lines\n");
    printf("    -S N   : summarize threshold\n");
    printf("    -c     : print raw memory to stdout\n");
    printf("    -x     : print only hex\n");
    printf("    -xx    : print only fixed length ascii dumps\n");

}
int main(int argc, char **argv)
{
    int64_t llOffset=0;     bool haveOffset = false;
    int64_t llEndOffset=0;
    int64_t llLength=0;
    int64_t llBaseOffset=0;
    std::string srcFilename;
    std::string dstFilename;
    int nDumpUnitSize=1;
    std::string crcspec;

    int argsfound=0; 
    for (auto& arg : ArgParser(argc, argv))
        switch(arg.option())
        {
            case 'b': llBaseOffset = arg.getint(); break;
            case 'h': g_dumpformat= DUMP_HASHES; break;
            case 'o': llOffset = arg.getint(); haveOffset = true; break;
            case 'e': llEndOffset = arg.getint(); break;
            case 'l': llLength = arg.getint(); break;

            case 'r': 
#if !defined(__ANDROID__)
#ifdef RIPEMD160_DIGEST_LENGTH
                      if (arg.match("-ripemd160")) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::RIPEMD160;
                      }
                      else
#endif
#endif
 
                      g_chunksize = arg.getuint(); break;

            case 'w': g_nMaxUnitsPerLine = arg.getint(); break;
            case 's': if (0)
                          ;
#ifdef SHA1_DIGEST_LENGTH
                      else if (arg.match("-sha1")) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA1;
                      }
#endif
#if !defined(__ANDROID__)
#ifdef SHA256_DIGEST_LENGTH
                      else if (arg.match("-sha256")) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA256;
                      }
#endif
#ifdef SHA384_DIGEST_LENGTH
                      else if (arg.match("-sha384")) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA384;
                      }
#endif
#ifdef SHA512_DIGEST_LENGTH
                      else if (arg.match("-sha512")) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA512;
                      }
#endif
#endif

                      else if (arg.match("-sum"))
                          g_dumpformat= DUMP_SUM;
                      else
                          g_llStepSize = arg.getint();
                      break;
            case 'm': if (0)
                          ;
#ifdef MD5_DIGEST_LENGTH
                      else if (arg.match("-md5")) {
                          g_dumpformat= DUMP_HASH; 
                          g_hashtype= CryptHash::MD5;
                      }
#endif
#ifdef MD2_DIGEST_LENGTH
                      else if (arg.match("-md2")) {
                          g_dumpformat= DUMP_HASH; 
                          g_hashtype= CryptHash::MD2;
                      }
#endif
#ifdef MD4_DIGEST_LENGTH
                      else if (arg.match("-md4")) {
                          g_dumpformat= DUMP_HASH; 
                          g_hashtype= CryptHash::MD4;
                      }
#endif
#if !defined(__ANDROID__)
#ifdef RIPEMD160_DIGEST_LENGTH
                      else if (arg.match("-md160")) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::RIPEMD160;
                      }
#endif
#endif

                      break;
            case 'a': g_dumpformat= DUMP_STRINGS; break;
            case 'c': if (arg.match("-crc")) {
                          g_dumpformat= DUMP_CRC32; 
                          crcspec = arg.getstr();
                      }
                      else
                          g_dumpformat= DUMP_RAW; 
                      break;
            case 'f': g_fulldump= true; break;
            case 'S': g_summarizeThreshold = arg.getuint(); break;
            case 'x': if (arg.count()==2)
                          g_dumpformat= DUMP_ASCII; 
                      else
                          g_dumpformat= DUMP_HEX; 
                      break;
            case '1': case '2': case '4': case '8':
                nDumpUnitSize= arg.option()-'0';
                break;
            case 0: // single '-'
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

    if (!crcspec.empty()) {
        auto res1 = parsesigned(crcspec.begin(), crcspec.end(), 0);
        g_crc_initval= res1.first;
        if (res1.second!=crcspec.end()) {
            auto res2 = parseunsigned(res1.second+1, crcspec.end(), 0);
            g_crc_poly= res2.first;
            if (res2.second!=crcspec.end()) {
                auto res3 = parseunsigned(res2.second+1, crcspec.end(), 0);
                g_crc_bits= res3.first;

            }
        }
    }

    // 64 = highest 2^n, such that addrsize + 2^n <= screenwidth
    // 32 = highest 2^n, such that addrsize + 3*2^n <= screenwidth+25 ...
    // 16 = highest 2^n, such that addrsize + 4*2^n <= screenwidth
    if (g_nMaxUnitsPerLine<0) {
        if (g_dumpformat==DUMP_ASCII) 
            g_nMaxUnitsPerLine= 64/nDumpUnitSize;
        else if (g_dumpformat==DUMP_HEX) 
            g_nMaxUnitsPerLine= 32/nDumpUnitSize;
        else if (g_dumpformat>=DUMP_HASH)
            g_nMaxUnitsPerLine= g_llStepSize;
        else
            g_nMaxUnitsPerLine= 16/nDumpUnitSize;
    }

    g_dumpunit= 
        nDumpUnitSize==1?DUMPUNIT_BYTE:
        nDumpUnitSize==2?DUMPUNIT_WORD:
        nDumpUnitSize==4?DUMPUNIT_DWORD:
        nDumpUnitSize==8?DUMPUNIT_QWORD:DUMPUNIT_BYTE;

    if (g_dumpformat==DUMP_RAW) {
#ifdef WIN32
        if (-1==_setmode( _fileno( stdout ), _O_BINARY )) {
            print("ERROR: _setmode(stdout, rb)");
            return 1;
        }
#endif
    }

    bool fromStdin= srcFilename=="-";

    uint64_t llFileSize= fromStdin ? 0 : GetFileSize(srcFilename);
    if (llOffset<0) {
        if (fromStdin) {
            printf("dumping end of stdin stream not yet implemented\n");
            return 1;
        }
        llOffset += llFileSize;
    }
    if (llLength<0) {
        if (fromStdin) {
            printf("dumping end of stdin stream not yet implemented\n");
            return 1;
        }
        llLength += llFileSize;
    }


    if (llLength==0 && fromStdin)
        llLength= INT64_MAX;

    if (llLength==0 && llEndOffset)
        llLength= llEndOffset-llOffset;  // NOTE: this will not work for stdin!

    if (llLength==0)
        llLength= llFileSize;

    if (!dstFilename.empty()) {
        if (g_llStepSize)
            CopyFileSteps(srcFilename, dstFilename, llBaseOffset, llOffset, llLength);
        else
            Copyfile(srcFilename, dstFilename, llBaseOffset, llOffset, llLength);
    }
    else {
        if (g_llStepSize)
            StepFile(srcFilename, llBaseOffset, llOffset, llLength);
        else
            Dumpfile(srcFilename, llBaseOffset, llOffset, llLength);
    }

    return 0;
}
