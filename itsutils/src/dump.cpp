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
bool g_fulldump= false;

void Dumpfile(char *szFilename, DWORD dwBaseOffset, DWORD dwOffset, int nLength)
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
    while (nLength>0)
    {
        buf.resize(65536);
        DWORD nRead= fread(vectorptr(buf), 1, min(buf.size(), nLength), f);

        if (nRead==0)
            break;

        buf.resize(nRead);

        bighexdump(dwOffset, buf, flags | (nLength!=nRead ? HEXDUMP_MOREFOLLOWS : 0) );

        nLength -= nRead;
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

    Dumpfile(szFilename, dwBaseOffset, dwOffset, dwLength);

    return 0;
}
