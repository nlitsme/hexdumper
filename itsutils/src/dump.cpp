#include <windows.h>
#include <stdio.h>
#include "debug.h"

void hexdumpbytes(BYTE *buf, int nLength)
{
    while(nLength--)
        printf(" %02x", *buf++);
}
void dumpascii(BYTE *buf, int nLength)
{
    while(nLength--)
    {
        BYTE c= *buf++;
        putchar((c>=' ' && c<='~')?c:'.');
    }
}
void writespaces(int n)
{
    while(n--)
        putchar(' ');
}

#define HEXDUMP_WIDTH 16
void hexdump(DWORD dwOffset, BYTE *buf, int nLength)
{
    while(nLength)
    {
        int nLineLength= min(nLength, HEXDUMP_WIDTH);
        printf("%08lx: ", dwOffset);

        hexdumpbytes(buf, nLineLength);
        if (nLineLength<HEXDUMP_WIDTH)
            writespaces((HEXDUMP_WIDTH-nLineLength)*3);

        printf("  ");

        dumpascii(buf, nLineLength);
        if (nLineLength<HEXDUMP_WIDTH)
            writespaces(HEXDUMP_WIDTH-nLineLength);

        printf("\n");

        nLength -= nLineLength;
        dwOffset += nLineLength;
        buf += nLineLength;
    }
}

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

        hexdump(dwOffset, buf, nRead);

        nLength -= nRead;
        dwOffset += nRead;
    }
    fclose(f);
}

int main(int argc, char **argv)
{
    DWORD dwOffset=0;
    int nLength=0;
    DWORD dwBaseOffset=0;
    char *szFilename=NULL;

    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-')
            switch (argv[i][1])
            {
                case 'b': dwBaseOffset= strtoul(argv[i]+2, 0, 0); break;
                case 'o': dwOffset= strtoul(argv[i]+2, 0, 0); break;
                case 'l': nLength= strtol(argv[i]+2, 0, 0); break;
                case 'f': szFilename= argv[i]+2; break;
            }
    }

    Dumpfile(szFilename, dwBaseOffset, dwOffset, nLength);

    return 0;
}
