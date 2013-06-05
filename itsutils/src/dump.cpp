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
#include <util/wintypes.h>
#include <stdio.h>
#ifdef _WIN32
#include <io.h>
#endif
#ifndef _WIN32
#include <sys/stat.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif
#include <fcntl.h>
#ifdef _USE_WINCRYPTAPI
#include "dump_hash.h"
#endif
#ifdef _USE_OPENSSL
#include "dump_ossl_hash.h"
#endif
#include "dump_crc32.h"
#include "dump_sum.h"
#include "debug.h"
#include "stringutils.h"
#include "args.h"
#include <stdint.h>
#include <string.h>
#include <algorithm>

#ifdef WIN32
#define fseeko _fseeki64
#endif

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
unsigned long g_crc_initval= 0;
unsigned long g_crc_poly= 0xEDB88320;
unsigned long g_crc_bits= 32;

int g_nMaxUnitsPerLine=-1;
int64_t g_llStepSize= 0;

bool g_fulldump= false;
int g_summarizeThreshold=-1;

uint32_t g_chunksize= 1024*1024;

// skipbytes is used for non-seekable files ( like stdin )
void skipbytes(FILE *f, int64_t skip)
{
    ByteVector buf;
    buf.resize(std::min(skip,g_chunksize));

    while (skip) {
        size_t want= std::min(skip,buf.size());
        fread(vectorptr(buf), 1, want, f);
        skip-=want;
    }
}

bool StepFile(const std::string& srcFilename, int64_t llBaseOffset, int64_t llOffset, int64_t llLength)
{
    ByteVector buffer;
    std::string prevline;
    int nSameCount= 0;

    bool fromStdin= srcFilename=="-";

    FILE *f= NULL;
    if (fromStdin) {
        f= stdin;
#ifdef WIN32
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            error("_setmode(stdin, rb)");
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
    else if (fseeko(f, llOffset-llBaseOffset, SEEK_SET))
    {
        error("fseeko");
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
            if (!hashcalc.InitHash(g_hashtype)) {
                error("CryptHash.init");
                return false;
            }
            if (!hashcalc.AddData(buffer)) {
                error("CryptHash.add");
                break;
            }
            ByteVector hash;
            if (!hashcalc.GetHash(hash)) {
                error("CryptHash.final");
                return false;
            }
            line= hash_as_string(hash);
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
                if (!hashes.back()->InitHash(ihash+HASHTYPEOFFSET)) {
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
                ByteVector hash;
                if (!(*ih)->GetHash(hash)) {
                    error("Gethash(%08lx - %s)", (*ih)->hashtype(), (*ih)->hashname().c_str());
                }
                else {
                    if (!line.empty())
                        line += " ";
                    line += hash_as_string(hash);
                }
            }
        }
        else if (g_dumpformat==DUMP_CRC32) {
            CRC32 crc(g_crc_initval, g_crc_poly);
            crc.add_data(vectorptr(buffer), buffer.size());
            line= stringformat("%08lx~%08lx", crc.crc, ~crc.crc);
        }
        else if (g_dumpformat==DUMP_SUM) {
            DATASUM sum;
            CRC32 crc(g_crc_initval, g_crc_poly);
            CRC32 crc1(~g_crc_initval, g_crc_poly);
            sum.add_data(vectorptr(buffer), buffer.size());
            crc.add_data(vectorptr(buffer), buffer.size());
            crc1.add_data(vectorptr(buffer), buffer.size());

            line= stringformat("%08lx~%08lx  %08lx~%08lx +%02llx LE:%04llx %08llx %16llx BE:%04llx %08llx %16llx ^%02x %04x %08lx %016llx", 
                crc.crc, ~crc.crc, crc1.crc, ~crc1.crc, 
                sum.sum1, sum.sum2_le, sum.sum4_le, sum.sum8_le, sum.sum2_be, sum.sum4_be, sum.sum8_be,
                sum.sumxor1, sum.sumxor2, sum.sumxor4, sum.sumxor8);
        }
        else if (g_dumpformat==DUMP_STRINGS)
            line= ascdump(buffer);
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
                debug("*  [ 0x%x lines ]\n", nSameCount);
            nSameCount= 0;
            writedumpline(llOffset, line);
        }
        prevline= line;
        int64_t llStep= std::min(llLength, g_llStepSize);
        if (f==stdin) {
            skipbytes(f, llStep-dwNumberOfBytesRead);
        }
        else if (fseeko(f, llStep-dwNumberOfBytesRead, SEEK_CUR))
        {
            error("fseeko");
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
            debug("*  [ 0x%x lines ]\n", nSameCount);
        writedumpline(llOffset, "");
    }

    return true;
}

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
            error("_setmode(stdin, rb)");
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
    else if (fseeko(f, llOffset-llBaseOffset, SEEK_SET))
    {
        error("fseeko");
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
    if (g_dumpformat==DUMP_HASH && !hashcalc.InitHash(g_hashtype)) {
        error("CryptHash.init");
        return false;
    }
typedef std::vector<CryptHash*> CryptHashList;
    CryptHashList hashes;
    if (g_dumpformat==DUMP_HASHES) {

#define VALIDALGS 0x701e
        for (int ihash=0 ; ihash<CryptHash::HASHTYPECOUNT ; ihash++) {
#ifdef _USE_WINCRYPTAPI
            if (((1<<ihash)&VALIDALGS)==0)
                continue;
            hashes.push_back(new CryptHash(cprov));
#else
            hashes.push_back(new CryptHash);
#endif
			if (!hashes.back()->InitHash(ihash+HASHTYPEOFFSET)) {
				delete hashes.back();
                hashes.resize(hashes.size()-1);
			}
        }
    }

    DATASUM sum;
    CRC32 crc(g_crc_initval, g_crc_poly);
    CRC32 crc1(~g_crc_initval, g_crc_poly);

    ByteVector buf;
    while (llLength>0)
    {
        buf.resize(g_chunksize);
        uint32_t dwBytesWanted= std::min(llLength,buf.size());
        uint32_t nRead= fread(vectorptr(buf), 1, dwBytesWanted, f);

        if (nRead==0)
            break;

        buf.resize(nRead);

        if (g_dumpformat==DUMP_HASH) {
            if (!hashcalc.AddData(buf)) {
                error("CryptHash.add");
                break;
            }
        }
        else if (g_dumpformat==DUMP_HASHES) {
            for (CryptHashList::iterator ih= hashes.begin() ; ih!=hashes.end() ; ih++)
            {
                (*ih)->AddData(buf);
            }
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
        ByteVector hash;
        if (!hashcalc.GetHash(hash)) {
            error("CryptHash.final");
            return false;
        }
        debug("%s\n", hash_as_string(hash).c_str());
    }
    else if (g_dumpformat==DUMP_HASHES) {
        for (CryptHashList::iterator ih= hashes.begin() ; ih!=hashes.end() ; ih++)
        {
            ByteVector hash;
            if (!(*ih)->GetHash(hash)) {
                error("Gethash(%08lx - %s)", (*ih)->hashtype(), (*ih)->hashname().c_str());
            }
            else {
                debug("%-10s: %s\n", (*ih)->hashname().c_str(), hash_as_string(hash).c_str());
            }
        }
    }
    else if (g_dumpformat==DUMP_CRC32) {
        debug("crc=%08lx invcrc=%08lx\n", crc.crc, ~crc.crc);
    }
    else if (g_dumpformat==DUMP_SUM) {
        debug("crc0=%08lx invcrc=%08lx\n", crc.crc, ~crc.crc);
        debug("crc-1=%08lx invcrc=%08lx\n", crc1.crc, ~crc1.crc);
        debug("addsum=%02llx LE:%04llx %08llx %16llx BE:%04llx %08llx %16llx sumxor=%02x %04x %08lx %016llx\n", 
                sum.sum1, sum.sum2_le, sum.sum4_le, sum.sum8_le,
                sum.sum2_be, sum.sum4_be, sum.sum8_be,
                sum.sumxor1, sum.sumxor2, sum.sumxor4, sum.sumxor8);
    }
    return true;
}

bool CopyFileSteps(const std::string& srcFilename, const std::string& dstFilename, int64_t llBaseOffset, int64_t llOffset, int64_t llLength)
{
    ByteVector buffer;

    bool fromStdin= srcFilename=="-";

    FILE *f= NULL;
    if (fromStdin) {
        f= stdin;
#ifdef WIN32
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            error("_setmode(stdin, rb)");
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
    else if (fseeko(f, llOffset-llBaseOffset, SEEK_SET))
    {
        error("fseeko");
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
        else if (fseeko(f, llStep-dwNumberOfBytesRead, SEEK_CUR))
        {
            error("fseeko");
            fclose(f);
        }

        llLength -= llStep;
        llOffset += llStep;
    }
    fclose(g);
    fclose(f);
    return true;
}
bool Copyfile(const std::string& srcFilename, const std::string& dstFilename, int64_t llBaseOffset, int64_t llOffset, int64_t llLength)
{
    FILE *f= NULL;

    bool fromStdin= srcFilename=="-";

    if (fromStdin) {
        f= stdin;
#ifdef WIN32
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            error("_setmode(stdin, rb)");
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
    else if (fseeko(f, llOffset-llBaseOffset, SEEK_SET))
    {
        error("fseeko");
        fclose(f);
    }
    FILE *g= fopen(dstFilename.c_str(), "w+b");
    if (g==NULL) {
        perror(dstFilename.c_str());
        return false;
    }

    ByteVector buf;
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
int64_t GetFileSize(const std::string& filename)
{
#ifdef WIN32
    HANDLE hSrc = CreateFile(filename.c_str(), GENERIC_READ, FILE_SHARE_WRITE|FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hSrc)
    {
        error("Unable to open file %s", filename.c_str());
        return 0;
    }

    DWORD dwSizeH;
    DWORD dwSizeL= GetFileSize(hSrc, &dwSizeH);

    CloseHandle(hSrc);

    return ((int64_t)dwSizeH<<32)+dwSizeL;
#else
    struct stat st;
    if (lstat(filename.c_str(), &st)) {
        error("lstat");
        return 0;
    }
    if (st.st_mode&S_IFREG)
        return st.st_size;
    else if (st.st_mode&S_IFBLK) {
#ifdef __MACH__
        int h= open(filename.c_str(), O_RDONLY);
        uint64_t bkcount;
        uint32_t bksize;
        if (-1==ioctl(h, DKIOCGETBLOCKCOUNT, &bkcount)) {
            error("ioctl(DKIOCGETBLOCKCOUNT)");
            return 0;
        }
        if (-1==ioctl(h, DKIOCGETBLOCKSIZE, &bksize)) {
            error("ioctl(DKIOCGETBLOCKSIZE)");
            return 0;
        }
        close(h);
        return bkcount*bksize;
#else
        int h= open(filename.c_str(), O_RDONLY);
        uint64_t devsize;
        if (-1==ioctl(h, BLKGETSIZE64, &devsize)) {
            error("ioctl(BLKGETSIZE64)");
            return 0;
        }
        close(h);
        return devsize;
#endif
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
    printf("    -md5   : print md5sum of selected memory range\n");
    printf("    -sha1  : print sha1 of selected memory range\n");
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
    int64_t llOffset=0;
    int64_t llEndOffset=0;
    int64_t llLength=0;
    int64_t llBaseOffset=0;
    std::string srcFilename;
    std::string dstFilename;
    int nDumpUnitSize=1;

    DebugStdOut();

    int argsfound=0; 
    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-' && argv[i][1]) switch (argv[i][1])
        {
            case 'b': HANDLELLOPTION(llBaseOffset, int64_t); break;
            case 'h': g_dumpformat= DUMP_HASHES; break;
            case 'o': HANDLELLOPTION(llOffset, int64_t); break;
            case 'e': HANDLELLOPTION(llEndOffset, int64_t); break;
            case 'l': HANDLELLOPTION(llLength, int64_t); break;

            case 'r': HANDLEULOPTION(g_chunksize, uint32_t); break;

            case 'w': HANDLEULOPTION(g_nMaxUnitsPerLine, int); break;
            case 's': if (stringcompare(argv[i]+1, "sha1")==0) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA1;
                      }
#ifdef SHA256_DIGEST_LENGTH
                      else if (stringcompare(argv[i]+1, "sha256")==0) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA256;
                      }
#endif
#ifdef SHA384_DIGEST_LENGTH
                      else if (stringcompare(argv[i]+1, "sha384")==0) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA384;
                      }
#endif
#ifdef SHA512_DIGEST_LENGTH
                      else if (stringcompare(argv[i]+1, "sha512")==0) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA512;
                      }
#endif
                      else if (stringcompare(argv[i]+1, "sum")==0)
                          g_dumpformat= DUMP_SUM;
                      else
                          HANDLELLOPTION(g_llStepSize, int64_t);
                      break;
            case 'm': if (stringcompare(argv[i]+1, "md5")==0) {
                          g_dumpformat= DUMP_HASH; 
                          g_hashtype= CryptHash::MD5;
                      }
#ifdef MD2_DIGEST_LENGTH
                      else if (stringcompare(argv[i]+1, "md2")==0) {
                          g_dumpformat= DUMP_HASH; 
                          g_hashtype= CryptHash::MD2;
                      }
#endif
                      else if (stringcompare(argv[i]+1, "md4")==0) {
                          g_dumpformat= DUMP_HASH; 
                          g_hashtype= CryptHash::MD4;
                      }
                      break;
            case 'a': g_dumpformat= DUMP_STRINGS; break;
            case 'c': if (std::string(argv[i]+1, 3)=="crc") {
                          g_dumpformat= DUMP_CRC32; 
                          if (argv[i][4]) {
                              char *colon= strchr(argv[i], ':');
                              if (colon) {
                                  g_crc_initval= strtoul(colon+1, NULL, 0);
                                  colon = strchr(colon+1, ':');
                                  if (colon) {
                                      g_crc_poly= strtoul(colon+1, NULL, 0);
                                      colon = strchr(colon+1, ':');
                                      if (colon) {
                                          g_crc_bits= strtoul(colon+1, NULL, 0);
                                      }
                                  }
                              }
                          }
                      }
                      else
                          g_dumpformat= DUMP_RAW; 
                      break;
            case 'f': g_fulldump= true; break;
            case 'S': HANDLEULOPTION(g_summarizeThreshold, unsigned); break;
            case 'x': if (argv[i][2]=='x')
                          g_dumpformat= DUMP_ASCII; 
                      else
                          g_dumpformat= DUMP_HEX; 
                      break;
            case '1': case '2': case '4': case '8':
                nDumpUnitSize= argv[i][1]-'0';
                break;
            default:
                usage();
                return 1;
        }
        else switch (argsfound++) {
            case 0: srcFilename= argv[i]; break;
            case 1: dstFilename= argv[i]; break;
        }
    }
    if (argsfound==0 || argsfound>2)
    {
        usage();
        return 1;
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
            error("_setmode(stdout, rb)");
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

    if (llLength==0 && fromStdin)
        llLength= INT64_MAX;
    if (llLength==0 && llEndOffset)
        llLength= llEndOffset-llOffset;

    if (llLength==0)
        llLength= llFileSize;

    // todo: i think i meant something different here - need to fix.
    if (llOffset < llBaseOffset && llOffset+0x80000000 > llBaseOffset)
        llOffset= llBaseOffset;

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
