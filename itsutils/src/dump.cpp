/* (C) 2003 Willem Jan Hengeveld  itsme@xs4all.nl */
#include <windows.h>
#include <stdio.h>
#include "debug.h"
#include "args.h"

void Dumpfile(char *szFilename, DWORD dwBaseOffset, DWORD dwOffset, int nLength)
{
    FILE *f= fopen(szFilename, "rb");
    if (f==NULL)
        return;

    if (fseek(f, dwOffset-dwBaseOffset, SEEK_SET))
    {
        error("fseek");
        fclose(f);
    }

    while (nLength>0)
    {
        BYTE buf[4096];
        DWORD nRead= fread(buf, 1, min(4096, nLength), f);

        if (nRead==0)
            break;

        hexdump(dwOffset, buf, nRead, g_nDumpUnitSize, g_nMaxWordsPerLine);

        nLength -= nRead;
        dwOffset += nRead;
    }
    fclose(f);
}

void usage()
{
    printf("Usage: dump [options]\n");
    printf("    -b BASE   : specify base offset - what offset has first byte of the file\n");
    printf("    -o OFS    : what offset to display\n");
    printf("    -l LEN    : length to dump\n");
    printf("    -f NAME   : file to dump\n");
    printf("    -w N      : how many words to print on each line\n");
    printf("    -1,2,4    : what to print: byte, word, dword\n");
}
int main(int argc, char **argv)
{
    DWORD dwOffset=0;
    int nLength=0;
    DWORD dwBaseOffset=0;
    char *szFilename=NULL;

    int argsfound=0; 
    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-') switch (argv[i][1])
        {
            case 'b': HANDLEULOPTION(dwBaseOffset, DWORD); break;
            case 'o': HANDLEULOPTION(dwOffset, DWORD); break;
            case 'l': HANDLEULOPTION(nLength, DWORD); break;
            case 'f': HANDLESTROPTION(szFilename); break;
            case 'w': HANDLEULOPTION(g_nMaxWordsPerLine, DWORD); break;

            case '1': case '2': case '4':
                g_nDumpUnitSize= argv[i][1]-'0';
                break;
            default:
                usage();
                return 1;
        }
        else 
            argsfound++;
    }
    if (argsfound>0)
    {
        usage();
        return 1;
    }

    if (g_nMaxWordsPerLine<0)
        g_nMaxWordsPerLine= 16/g_nDumpUnitSize;

    Dumpfile(szFilename, dwBaseOffset, dwOffset, nLength);

    return 0;
}
