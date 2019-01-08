#include <stdint.h>
#include <string.h>
#include <algorithm>

#define _DISABLE_DEBUG
#include "argparse.h"
#include <sys/mman.h>
#include <sys/errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>

#include "mmem.h"
#include "fhandle.h"


int parsehexnyble(char c)
{
    if ('0'<=c && c<='9')
        return c-'0';
    if ('a'<=c && c<='f')
        return c-'a'+10;
    if ('A'<=c && c<='F')
        return c-'A'+10;
    return -1;
}
uint64_t parsehexnumber(const char *first, const char *last)
{
    uint64_t num= 0;
    const char *p= first;
    while (p<last) {
        int x= parsehexnyble(*p++);
        if (x==-1)
            throw "invalid hex digit";
        num *= 16;
        num += x;
    }
    return num;
}
const char *findnonhex(const char *first, const char *last)
{
    const char* p= first;
    while (p<last && parsehexnyble(*p)!=-1)
        p++;
    return p;
}
const char *findhex(const char *first, const char *last)
{
    const char* p= first;
    while (p<last && parsehexnyble(*p)==-1)
        p++;
    return p;
}

template<typename BYTEITER> inline void set8(BYTEITER p, uint8_t v) { *p= v; }
template<typename BYTEITER> inline void set16le(BYTEITER p, uint16_t v) { set8(p, v);      set8(p+1, v>>8); }
template<typename BYTEITER> inline void set32le(BYTEITER p, uint32_t v) { set16le(p, v);   set16le(p+2, v>>16); }
template<typename BYTEITER> inline void set64le(BYTEITER p, uint64_t v) { set32le(p, (uint32_t)v);   set32le(p+4, (uint32_t)(v>>32)); }


//   represents one edit
struct edit {
    uint64_t ofs;
    std::vector<uint8_t> data;
    edit(uint64_t ofs, std::vector<uint8_t> data)
        : ofs(ofs), data(data)
    {
    }

    static edit parse(const std::string& str)
    {
        size_t icolon= str.find(':');
        if (icolon==str.npos)
            throw "edit must have ':'";
        uint64_t ofs= parsehexnumber(&str[0], &str[icolon]);
        if (icolon+1==str.size())
            throw "no data after colon";

        // handle string constant
        if (str[icolon+1]=='"')
        {
            if (str[str.size()-1]!='"')
                throw "string not terminated";
            return edit(ofs, parsestring(&str[icolon+2], &str[str.size()-1]));
        }

        // handle data from file
        if (str[icolon+1]=='@')
        {
            return edit(ofs, parsefile(str.substr(icolon+2)));
        }

        // otherwise hex data
        return edit(ofs, parsedata(&str[icolon+1], &str[0]+str.size()));
    }
    static std::vector<uint8_t> parsedata(const char *first, const char *last)
    {
        std::vector<uint8_t> data;
        int width= 0;
        const char *p= first;
        while (p<last)
        {
            const char *q= findnonhex(p, last);
            if (width && q-p!=width)
                throw "inconsistent data width";
            if (width==0) {
                width= q-p;
                if (width&1)
                    throw "must be even nr of hex digits";
                if (width!=2 && width!=4 && width!=8 && width!=16)
                    throw "data width must be 1,2,4 or 8 bytes";
            }
            uint64_t val= parsehexnumber(p, q);
            append_to_data(data, width/2, val);

            p = findhex(q, last);
        }
        return data;
    }
    static std::vector<uint8_t> parsefile(const std::string& filename)
    {
        std::vector<uint8_t> v;
        filehandle f= open(filename.c_str(), O_RDONLY);
        struct stat st;
        if (-1==fstat(f, &st))
            throw "fstat error";
        v.resize(st.st_size);

        if (-1==read(f, &v[0], v.size()))
            throw "read error";
        
        return v;
    }
    static void append_to_data(std::vector<uint8_t>&data, int width, uint64_t value)
    {
        data.resize(data.size()+width);
        uint8_t *p= &data[data.size()-width];
        switch(width)
        {
            case 1: *p= value; break;
            case 2: set16le(p, value); break;
            case 4: set32le(p, value); break;
            case 8: set64le(p, value); break;
        }
    }
    static std::vector<uint8_t> parsestring(const char *first, const char *last)
    {
        return std::vector<uint8_t>((const uint8_t*)first, (const uint8_t*)last);
    }
};


void mmapply(int f, uint64_t ofs, const std::vector<uint8_t>& data)
{
    mappedmem  m(f, ofs, ofs+data.size(), PROT_READ|PROT_WRITE);

    memcpy(m.ptr(), &data[0], data.size());
}

void usage()
{
    printf("Usage: mmedit <device> [edits...]\n");
    printf("   edits are formatted like: <hexoffset>:<data>\n");
    printf("   data is formated as:\n");
    printf("     * 2,4,8 or 16 hex digits -> byte, short, dword, qword\n");
    printf("     * \"...\"  -> a double quoted string\n");
    printf("     * @filename  -> read from file\n");
}
int main(int argc, char**argv)
{
    std::vector<edit> edits;
    std::string filename;
    try {

    for (auto& arg : ArgParser(argc, argv))
        switch (arg.option())
        {
            case 'h': usage(); return 0;
            case -1:
                if (filename.empty())
                    filename= arg.getstr();
                else 
                    edits.push_back(edit::parse(arg.getstr()));
        }
    if (filename.empty() || edits.empty()) {
        usage();
        return 1;
    }

    filehandle f= open(filename.c_str(), O_RDWR);
    if (f==-1) {
        perror(filename.c_str());
        return 1;
    }
    for (auto &e : edits)
        mmapply(f, e.ofs, e.data);

    }
    catch (const char*msg)
    {
        printf("E: %s\n", msg);
        return 1;
    }
    return 0;
}
