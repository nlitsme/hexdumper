/* (C) 2003-2007 Willem Jan Hengeveld <itsme@xs4all.nl>
 * Web: http://www.xs4all.nl/~itsme/
 *      http://wiki.xda-developers.com/
 *
 * $Id$
 *
 * this program provides various ways of (hex) dumping sections of binary files
 *
 */

// todo: fix bug:
//   dump 8000.mem -o 0x02400000 -s 0x400 -xx
//   does not work as it should, .. offsets seem to be double from their real value.
//
// todo:
//    * DONE think of way to make winxp support sha256: now using openssl
//    * DONE add simple add-checksum , and xor-checksum support
//    * make '*' summary only print '*' when more than X lines are the same
//
//note: you can use dump also to read block devices, 
//  dump \\.\PhysicalDrive0 -xx -o 0  -l 0xa00000000 -s 0x100000000
// will dump 64 ascii chars every 4G of your 40G disk.
//
// 
#define __STDC_LIMIT_MACROS
#define NOMINMAX
#include <windows.h>
#include <stdio.h>
#include <io.h>
#ifndef WIN32
#include <sys/stat.h>
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
#include <algorithm>

#ifdef WIN32
#define fseeko _fseeki64
#endif

namespace std {
size_t min(int64_t a, size_t b)
{
    return (a<b) ? a : b;
}
}
DumpUnitType g_dumpunit=DUMPUNIT_BYTE;
DumpFormat g_dumpformat= DUMP_HEX_ASCII;
int g_hashtype= 0;
unsigned long g_crc_initval= 0;
unsigned long g_crc_poly= 0xEDB88320;

int g_nMaxUnitsPerLine=-1;
int64_t g_llStepSize= 0;

bool g_fulldump= false;
unsigned g_summarizeThreshold=-1;

DWORD g_chunksize= 1024*1024;

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

bool StepFile(char *szFilename, int64_t llBaseOffset, int64_t llOffset, int64_t llLength)
{
    ByteVector buffer;
    std::string prevline;
    int nSameCount= 0;

    FILE *f= NULL;
    if (strcmp(szFilename, "-")==0) {
        f= stdin;
#ifdef WIN32
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            error("_setmode(stdin, rb)");
            return false;
        }
#endif
    }
    else {
        f= fopen(szFilename, "rb");
    }

    if (f==NULL) {
        perror(szFilename);
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

    while (llLength>0)
    {
        buffer.resize(DumpUnitSize(g_dumpunit)*g_nMaxUnitsPerLine);

        DWORD dwBytesWanted= std::min(llLength,buffer.size());
        std::string line;
        DWORD dwNumberOfBytesRead= fread(vectorptr(buffer), 1, dwBytesWanted, f);
        if (dwNumberOfBytesRead==0)
            break;
        if (g_dumpformat==DUMP_RAW) {
            line.clear();
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
            fwrite(vectorptr(buffer), 1, buffer.size(), stdout);
        else if (!g_fulldump && line == prevline) {
            nSameCount++;
        }
        else {
            if (nSameCount>0 && nSameCount<=g_summarizeThreshold) {
                for (unsigned i=0 ; i<nSameCount ; i++)
                    writedumpline(llOffset+(i-nSameCount)*g_llStepSize, prevline);
            }
            else if (nSameCount>g_summarizeThreshold)
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
    if (nSameCount==1)
        writedumpline(llOffset-g_llStepSize, prevline);
    else if (nSameCount>1)
        debug("*  [ 0x%x lines ]\n", nSameCount);
    writedumpline(llOffset, "");

    return true;
}

bool Dumpfile(char *szFilename, int64_t llBaseOffset, int64_t llOffset, int64_t llLength)
{
    DWORD flags= hexdumpflags(g_dumpunit, g_nMaxUnitsPerLine, g_dumpformat)
        | (g_fulldump?0:HEXDUMP_SUMMARIZE) | (g_dumpformat==DUMP_RAW?0:HEXDUMP_WITH_OFFSET);


    FILE *f= NULL;
    if (strcmp(szFilename, "-")==0) {
        f= stdin;
#ifdef WIN32
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            error("_setmode(stdin, rb)");
            return false;
        }
#endif
    }
    else {
        f= fopen(szFilename, "rb");
    }
    if (f==NULL) {
        perror(szFilename);
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
    CRC32 crc1(~0, g_crc_poly);

    ByteVector buf;
    while (llLength>0)
    {
        buf.resize(g_chunksize);
        DWORD dwBytesWanted= std::min(llLength,buf.size());
        DWORD nRead= fread(vectorptr(buf), 1, dwBytesWanted, f);

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
            fwrite(vectorptr(buf), 1, buf.size(), stdout);
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
        debug("addsum=%02x LE:%04x %08lx  BE:%04x %08lx  sumxor=%02x %04x %08lx\n", 
                sum.sum1, sum.sum2_le, sum.sum4_le, sum.sum2_be, sum.sum4_be, sum.sumxor1, sum.sumxor2, sum.sumxor4);
    }
    return true;
}

bool CopyFileSteps(char *szFilename, char *szDstFilename, int64_t llBaseOffset, int64_t llOffset, int64_t llLength)
{
    ByteVector buffer;

    FILE *f= NULL;
    if (strcmp(szFilename, "-")==0) {
        f= stdin;
#ifdef WIN32
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            error("_setmode(stdin, rb)");
            return false;
        }
#endif
    }
    else {
        f= fopen(szFilename, "rb");
    }
    if (f==NULL) {
        perror(szFilename);
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
    FILE *g= fopen(szDstFilename, "w+b");
    if (g==NULL) {
        perror(szDstFilename);
        return false;
    }


    while (llLength>0)
    {
        buffer.resize(DumpUnitSize(g_dumpunit)*g_nMaxUnitsPerLine);

        DWORD dwBytesWanted= std::min(llLength,buffer.size());
        DWORD dwNumberOfBytesRead= fread(vectorptr(buffer), 1, dwBytesWanted, f);
        if (dwNumberOfBytesRead==0)
            break;

        fwrite(vectorptr(buffer), 1, buffer.size(), g);

        int64_t llStep= std::min(llLength, g_llStepSize);
        llLength -= llStep;
        llOffset += llStep;
    }
    fclose(g);
    fclose(f);
    return true;
}
bool Copyfile(char *szFilename, char *szDstFilename, int64_t llBaseOffset, int64_t llOffset, int64_t llLength)
{
    FILE *f= NULL;
    if (strcmp(szFilename, "-")==0) {
        f= stdin;
#ifdef WIN32
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            error("_setmode(stdin, rb)");
            return false;
        }
#endif
    }
    else {
        f= fopen(szFilename, "rb");
    }
    if (f==NULL) {
        perror(szFilename);
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
    FILE *g= fopen(szDstFilename, "w+b");
    if (g==NULL) {
        perror(szDstFilename);
        return false;
    }

    ByteVector buf;
    while (llLength>0)
    {
        buf.resize(g_chunksize);
        DWORD dwBytesWanted= std::min(llLength,buf.size());
        DWORD nRead= fread(vectorptr(buf), 1, dwBytesWanted, f);

        if (nRead==0)
            break;

        buf.resize(nRead);

        fwrite(vectorptr(buf), 1, buf.size(), g);

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
    return st.st_size;
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
    char *szFilename=NULL;
    char *szDstFilename=NULL;
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

            case 'r': HANDLEULOPTION(g_chunksize, DWORD); break;

            case 'w': HANDLEULOPTION(g_nMaxUnitsPerLine, DWORD); break;
            case 's': if (strcmp(argv[i]+1, "sha1")==0) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA1;
                      }
#ifdef SHA256_DIGEST_LENGTH
                      else if (strcmp(argv[i]+1, "sha256")==0) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA256;
                      }
#endif
#ifdef SHA384_DIGEST_LENGTH
                      else if (strcmp(argv[i]+1, "sha384")==0) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA384;
                      }
#endif
#ifdef SHA512_DIGEST_LENGTH
                      else if (strcmp(argv[i]+1, "sha512")==0) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA512;
                      }
#endif
                      else if (strcmp(argv[i]+1, "sum")==0)
                          g_dumpformat= DUMP_SUM;
                      else
                          HANDLELLOPTION(g_llStepSize, int64_t);
                      break;
            case 'm': if (strcmp(argv[i]+1, "md5")==0) {
                          g_dumpformat= DUMP_HASH; 
                          g_hashtype= CryptHash::MD5;
                      }
                      else if (strcmp(argv[i]+1, "md2")==0) {
                          g_dumpformat= DUMP_HASH; 
                          g_hashtype= CryptHash::MD2;
                      }
                      else if (strcmp(argv[i]+1, "md4")==0) {
                          g_dumpformat= DUMP_HASH; 
                          g_hashtype= CryptHash::MD4;
                      }
                      break;
            case 'a': g_dumpformat= DUMP_STRINGS; break;
            case 'c': if (strncmp(argv[i]+1, "crc", 3)==0) {
                          g_dumpformat= DUMP_CRC32; 
                          if (argv[i][4]) {
                              char *colon= strchr(argv[i], ':');
                              if (colon) {
                                  g_crc_initval= strtoul(colon+1, NULL, 0);
                                  colon = strchr(colon+1, ':');
                                  if (colon) {
                                      g_crc_poly= strtoul(colon+1, NULL, 0);
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
            case '1': case '2': case '4':
                nDumpUnitSize= argv[i][1]-'0';
                break;
            default:
                usage();
                return 1;
        }
        else switch (argsfound++) {
            case 0: szFilename= argv[i]; break;
            case 1: szDstFilename= argv[i]; break;
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
        else
            g_nMaxUnitsPerLine= 16/nDumpUnitSize;
    }

    g_dumpunit= 
        nDumpUnitSize==1?DUMPUNIT_BYTE:
        nDumpUnitSize==2?DUMPUNIT_WORD:
        nDumpUnitSize==4?DUMPUNIT_DWORD:DUMPUNIT_BYTE;

    if (g_dumpformat==DUMP_RAW) {
#ifdef WIN32
        if (-1==_setmode( _fileno( stdout ), _O_BINARY )) {
            error("_setmode(stdout, rb)");
            return false;
        }
#endif
    }

    if (llLength==0 && strcmp(szFilename, "-")==0)
        llLength= INT64_MAX;
    if (llLength==0 && llEndOffset)
        llLength= llEndOffset-llOffset;

    if (llLength==0)
        llLength= GetFileSize(szFilename);

    // todo: i think i meant something different here - need to fix.
    if (llOffset < llBaseOffset && llOffset+0x80000000 > llBaseOffset)
        llOffset= llBaseOffset;

    if (szDstFilename) {
        if (g_llStepSize)
            CopyFileSteps(szFilename, szDstFilename, llBaseOffset, llOffset, llLength);
        else
            Copyfile(szFilename, szDstFilename, llBaseOffset, llOffset, llLength);
    }
    else {
        if (g_llStepSize)
            StepFile(szFilename, llBaseOffset, llOffset, llLength);
        else
            Dumpfile(szFilename, llBaseOffset, llOffset, llLength);
    }

    return 0;
}
