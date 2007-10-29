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
//    * think of way to make winxp support sha256
//    * DONE add simple add-checksum , and xor-checksum support
//    * make '*' summary only print '*' when more than X lines are the same
//
// 
#include <windows.h>
#include <stdio.h>
#include <io.h>
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

DumpUnitType g_dumpunit=DUMPUNIT_BYTE;
DumpFormat g_dumpformat= DUMP_HEX_ASCII;
int g_hashtype= 0;
unsigned long g_crc_initval= 0;
unsigned long g_crc_poly= 0xEDB88320;

int g_nMaxUnitsPerLine=-1;
DWORD g_nStepSize= 0;
bool g_fulldump= false;
DWORD g_chunksize= 1024*1024;

bool StepFile(char *szFilename, DWORD dwBaseOffset, DWORD dwOffset, DWORD dwLength)
{
    ByteVector buffer;
    std::string prevline;
    bool bSamePrinted= false;

    FILE *f= NULL;
    if (strcmp(szFilename, "-")==0) {
        f= stdin;
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            error("_setmode(stdin, rb)");
            return false;
        }
    }
    else {
        f= fopen(szFilename, "rb");
    }

    if (f==NULL) {
        perror(szFilename);
        return false;
    }

    if (fseek(f, dwOffset-dwBaseOffset, SEEK_SET))
    {
        error("fseek");
        fclose(f);
    }

    while (dwLength>0)
    {
        buffer.resize(DumpUnitSize(g_dumpunit)*g_nMaxUnitsPerLine);

        DWORD dwBytesWanted= min(dwLength, buffer.size());
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
            line= asciidump(vectorptr(buffer), dwNumberOfBytesRead)+"\n";
        else
            line= hexdump(dwOffset, vectorptr(buffer), dwNumberOfBytesRead, DumpUnitSize(g_dumpunit), g_nMaxUnitsPerLine).substr(9);

        if (g_dumpformat==DUMP_RAW)
            fwrite(vectorptr(buffer), 1, buffer.size(), stdout);
        else if (!g_fulldump && line == prevline) {
            if (!bSamePrinted && line != " * * * * * *\n")
                printf("*\n");
            bSamePrinted= true;
        }
        else {
            bSamePrinted= false;

            printf("%08lx: %hs", dwOffset, line.c_str());
        }
        prevline= line;
        DWORD dwStep= min(dwLength, g_nStepSize);
        if (fseek(f, dwStep-dwNumberOfBytesRead, SEEK_CUR))
        {
            error("fseek");
            fclose(f);
        }
        dwLength -= dwStep;
        dwOffset += dwStep;
    }
    fclose(f);
    return true;
}

bool Dumpfile(char *szFilename, DWORD dwBaseOffset, DWORD dwOffset, DWORD dwLength)
{
    DWORD flags= hexdumpflags(g_dumpunit, g_nMaxUnitsPerLine, g_dumpformat)
        | (g_fulldump?0:HEXDUMP_SUMMARIZE) | (g_dumpformat==DUMP_RAW?0:HEXDUMP_WITH_OFFSET);


    FILE *f= NULL;
    if (strcmp(szFilename, "-")==0) {
        f= stdin;
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            error("_setmode(stdin, rb)");
            return false;
        }
    }
    else {
        f= fopen(szFilename, "rb");
    }
    if (f==NULL) {
        perror(szFilename);
        return false;
    }

    if (fseek(f, dwOffset-dwBaseOffset, SEEK_SET))
    {
        error("fseek");
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
        for (int ihash=0 ; ihash<15  ; ihash++) {
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
    CRC32 crc1(-1, g_crc_poly);

    ByteVector buf;
    while (dwLength>0)
    {
        buf.resize(g_chunksize);
        DWORD dwBytesWanted= min(buf.size(), dwLength);
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
            bighexdump(dwOffset, buf, flags | (dwLength!=nRead ? HEXDUMP_MOREFOLLOWS : 0) );

        dwLength -= nRead;
        dwOffset += nRead;
    }
    fclose(f);
    if (g_dumpformat==DUMP_HASH) {
        ByteVector hash;
        if (!hashcalc.GetHash(hash)) {
            error("CryptHash.final");
            return false;
        }
        debug("%hs\n", hash_as_string(hash).c_str());
    }
    else if (g_dumpformat==DUMP_HASHES) {
        for (CryptHashList::iterator ih= hashes.begin() ; ih!=hashes.end() ; ih++)
        {
            ByteVector hash;
            if (!(*ih)->GetHash(hash)) {
                error("Gethash(%08lx - %s)", (*ih)->hashtype(), (*ih)->hashname().c_str());
            }
            else {
                debug("%-10s: %hs\n", (*ih)->hashname().c_str(), hash_as_string(hash).c_str());
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

bool CopyFileSteps(char *szFilename, char *szDstFilename, DWORD dwBaseOffset, DWORD dwOffset, DWORD dwLength)
{
    ByteVector buffer;

    FILE *f= NULL;
    if (strcmp(szFilename, "-")==0) {
        f= stdin;
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            error("_setmode(stdin, rb)");
            return false;
        }
    }
    else {
        f= fopen(szFilename, "rb");
    }
    if (f==NULL) {
        perror(szFilename);
        return false;
    }

    if (fseek(f, dwOffset-dwBaseOffset, SEEK_SET))
    {
        error("fseek");
        fclose(f);
    }
    FILE *g= fopen(szDstFilename, "w+b");
    if (g==NULL) {
        perror(szDstFilename);
        return false;
    }


    while (dwLength>0)
    {
        buffer.resize(DumpUnitSize(g_dumpunit)*g_nMaxUnitsPerLine);

        DWORD dwBytesWanted= min(dwLength, buffer.size());
        DWORD dwNumberOfBytesRead= fread(vectorptr(buffer), 1, dwBytesWanted, f);
        if (dwNumberOfBytesRead==0)
            break;

        fwrite(vectorptr(buffer), 1, buffer.size(), g);

        DWORD dwStep= min(dwLength, g_nStepSize);
        dwLength -= dwStep;
        dwOffset += dwStep;
    }
    fclose(g);
    fclose(f);
    return true;
}
bool Copyfile(char *szFilename, char *szDstFilename, DWORD dwBaseOffset, DWORD dwOffset, DWORD dwLength)
{
    FILE *f= NULL;
    if (strcmp(szFilename, "-")==0) {
        f= stdin;
        if (-1==_setmode( _fileno( stdin ), _O_BINARY )) {
            error("_setmode(stdin, rb)");
            return false;
        }
    }
    else {
        f= fopen(szFilename, "rb");
    }
    if (f==NULL) {
        perror(szFilename);
        return false;
    }

    if (fseek(f, dwOffset-dwBaseOffset, SEEK_SET))
    {
        error("fseek");
        fclose(f);
    }
    FILE *g= fopen(szDstFilename, "w+b");
    if (g==NULL) {
        perror(szDstFilename);
        return false;
    }

    ByteVector buf;
    while (dwLength>0)
    {
        buf.resize(g_chunksize);
        DWORD dwBytesWanted= min(buf.size(), dwLength);
        DWORD nRead= fread(vectorptr(buf), 1, dwBytesWanted, f);

        if (nRead==0)
            break;

        buf.resize(nRead);

        fwrite(vectorptr(buf), 1, buf.size(), g);

        dwLength -= nRead;
        dwOffset += nRead;
    }

    fclose(g);
    fclose(f);
    return true;
}
DWORD GetFileSize(const std::string& filename)
{
    HANDLE hSrc = CreateFile(filename.c_str(), GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hSrc)
    {
        error("Unable to open file %hs", filename.c_str());
        return 0;
    }

    DWORD dwSize= GetFileSize(hSrc, NULL);

    CloseHandle(hSrc);

    return dwSize;
}

void usage()
{
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
    printf("    -sha256: print sha256 of selected memory range\n");
    printf("    -crc   : print crc32 of selected memory range\n");
    printf("    -h     : calc all known hash types\n");
    printf("    -f     : full - do not summarize identical lines\n");
    printf("    -c     : print raw memory to stdout\n");
    printf("    -x     : print only hex\n");
    printf("    -xx    : print only fixed length ascii dumps\n");

}
int main(int argc, char **argv)
{
    DWORD dwOffset=0;
    DWORD dwEndOffset=0;
    DWORD dwLength=0;
    DWORD dwBaseOffset=0;
    char *szFilename=NULL;
    char *szDstFilename=NULL;
    int nDumpUnitSize=1;

    DebugStdOut();

    int argsfound=0; 
    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-' && argv[i][1]) switch (argv[i][1])
        {
            case 'b': HANDLEULOPTION(dwBaseOffset, DWORD); break;
            case 'h': g_dumpformat= DUMP_HASHES; break;
            case 'o': HANDLEULOPTION(dwOffset, DWORD); break;
            case 'e': HANDLEULOPTION(dwEndOffset, DWORD); break;
            case 'l': HANDLEULOPTION(dwLength, DWORD); break;

            case 'r': HANDLEULOPTION(g_chunksize, DWORD); break;

            case 'w': HANDLEULOPTION(g_nMaxUnitsPerLine, DWORD); break;
            case 's': if (strcmp(argv[i]+1, "sha1")==0) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA1;
                      }
                      else if (strcmp(argv[i]+1, "sha256")==0) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA256;
                      }
                      else if (strcmp(argv[i]+1, "sha384")==0) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA384;
                      }
                      else if (strcmp(argv[i]+1, "sha512")==0) {
                          g_dumpformat= DUMP_HASH;
                          g_hashtype= CryptHash::SHA512;
                      }
                      else if (strcmp(argv[i]+1, "sum")==0)
                          g_dumpformat= DUMP_SUM;
                      else
                          HANDLEULOPTION(g_nStepSize, DWORD);
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
        if (-1==_setmode( _fileno( stdout ), _O_BINARY )) {
            error("_setmode(stdout, rb)");
            return false;
        }
    }

    if (dwLength==0 && strcmp(szFilename, "-")==0)
        dwLength= MAXDWORD;
    if (dwLength==0 && dwEndOffset)
        dwLength= dwEndOffset-dwOffset;

    if (dwLength==0)
        dwLength= GetFileSize(szFilename);

    if (dwOffset < dwBaseOffset && dwOffset+0x80000000 > dwBaseOffset)
        dwOffset= dwBaseOffset;

    if (szDstFilename) {
        if (g_nStepSize)
            CopyFileSteps(szFilename, szDstFilename, dwBaseOffset, dwOffset, dwLength);
        else
            Copyfile(szFilename, szDstFilename, dwBaseOffset, dwOffset, dwLength);
    }
    else {
        if (g_nStepSize)
            StepFile(szFilename, dwBaseOffset, dwOffset, dwLength);
        else
            Dumpfile(szFilename, dwBaseOffset, dwOffset, dwLength);
    }

    return 0;
}
