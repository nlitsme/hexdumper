/* (C) 2003 XDA Developers  itsme@xs4all.nl
 *
 * $Header$
 */
#include <windows.h>
#include <stdio.h>
#include "debug.h"
#include "stringutils.h"
#include "args.h"

DumpUnitType g_dumpunit=DUMPUNIT_BYTE;
DumpFormat g_dumpformat= DUMP_HEX_ASCII;
int g_nMaxUnitsPerLine=-1;
DWORD g_nStepSize= 0;
bool g_fulldump= false;


void StepFile(char *szFilename, DWORD dwBaseOffset, DWORD dwOffset, DWORD dwLength)
{
    ByteVector buffer;
    std::string prevline;
    bool bSamePrinted= false;

    FILE *f= fopen(szFilename, "rb");
    if (f==NULL) {
        perror(szFilename);
        return;
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
                printf("*\n", dwOffset);
            bSamePrinted= true;
        }
        else {
            bSamePrinted= false;

            printf("%08lx: %hs", dwOffset, line.c_str());
        }
        prevline= line;
        DWORD dwStep= min(dwLength, g_nStepSize);
        dwLength -= dwStep;
        dwOffset += dwStep;
    }
}

void Dumpfile(char *szFilename, DWORD dwBaseOffset, DWORD dwOffset, DWORD dwLength)
{
    DWORD flags= hexdumpflags(g_dumpunit, g_nMaxUnitsPerLine, g_dumpformat)
        | (g_fulldump?0:HEXDUMP_SUMMARIZE) | (g_dumpformat==DUMP_RAW?0:HEXDUMP_WITH_OFFSET);


    FILE *f= fopen(szFilename, "rb");
    if (f==NULL) {
        perror(szFilename);
        return;
    }

    if (fseek(f, dwOffset-dwBaseOffset, SEEK_SET))
    {
        error("fseek");
        fclose(f);
    }

    ByteVector buf;
    while (dwLength>0)
    {
        buf.resize(65536);
        DWORD dwBytesWanted= min(buf.size(), dwLength);
        DWORD nRead= fread(vectorptr(buf), 1, dwBytesWanted, f);

        if (nRead==0)
            break;

        buf.resize(nRead);

        bighexdump(dwOffset, buf, flags | (dwLength!=nRead ? HEXDUMP_MOREFOLLOWS : 0) );

        dwLength -= nRead;
        dwOffset += nRead;
    }
    fclose(f);
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
    printf("Usage: dump [options] FILENAME\n");
    printf("    -b BASE   : specify base offset - what offset has first byte of the file\n");
    printf("    -o OFS    : what offset to display\n");
    printf("    -l LEN    : length to dump\n");
    printf("    -w N      : how many words to print on each line\n");
    printf("    -s SIZE   : step with SIZE through memory\n");
    printf("    -1,2,4    : what to print: byte, word, dword\n");
    printf("    -a     : ascdump iso hexdump\n");
    printf("    -f     : full - do not summarize identical lines\n");
    printf("    -c     : print raw memory to stdout\n");
    printf("    -x     : print only hex\n");
    printf("    -xx    : print only fixed length ascii dumps\n");

}
int main(int argc, char **argv)
{
    DWORD dwOffset=0;
    DWORD dwLength=0;
    DWORD dwBaseOffset=0;
    char *szFilename=NULL;
    int nDumpUnitSize=1;

    DebugStdOut();

    int argsfound=0; 
    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-') switch (argv[i][1])
        {
            case 'b': HANDLEULOPTION(dwBaseOffset, DWORD); break;
            case 'o': HANDLEULOPTION(dwOffset, DWORD); break;
            case 'l': HANDLEULOPTION(dwLength, DWORD); break;

            case 'w': HANDLEULOPTION(g_nMaxUnitsPerLine, DWORD); break;
            case 's': HANDLEULOPTION(g_nStepSize, DWORD); break;
            case 'a': g_dumpformat= DUMP_STRINGS; break;
            case 'c': g_dumpformat= DUMP_RAW; break;
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
        else if (argsfound++==0)
            szFilename= argv[i];
    }
    if (argsfound!=1)
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

    if (dwLength==0)
        dwLength= GetFileSize(szFilename);

    if (dwOffset < dwBaseOffset && dwOffset+0x80000000 > dwBaseOffset)
        dwOffset= dwBaseOffset;

    if (g_nStepSize)
        StepFile(szFilename, dwBaseOffset, dwOffset, dwLength);
    else
        Dumpfile(szFilename, dwBaseOffset, dwOffset, dwLength);

    return 0;
}
