#include <string>
#include <cpputils/formatter.h>
#include "bighexdump.h"

std::string asciidump(const uint8_t *p, size_t n)
{
    std::stringstream buf;
    buf << Hex::ascstring << Hex::dumper(p, n);
    return buf.str();

}

std::string dumponeunit(const uint8_t *p, size_t len, int unittype)
{
    switch(unittype) {
        case DUMPUNIT_BYTE: return stringformat("%02x", *p);
        case DUMPUNIT_WORD:
                if (len==1)
                    return stringformat("__%02x", *p);
                else
                    return stringformat("%04x", *(uint16_t*)p);
                break;
        case DUMPUNIT_DWORD:
                --unittype;
                if (len<=2)
                    return "____"+dumponeunit(p, len, unittype);
                else
                    return dumponeunit(p+2, len-2, unittype)+dumponeunit(p, 2, unittype);
                break;
        case DUMPUNIT_QWORD:
                --unittype;
                if (len<=4)
                    return "________"+dumponeunit(p, len, unittype);
                else
                    return dumponeunit(p+4, len-4, unittype)+dumponeunit(p, 4, unittype);
                break;

    }
    return "";
}
std::string hexdumpunit(const uint8_t *buf, size_t bytelen, DumpUnitType unittype)
{
    std::string str;

    str.reserve(bytelen*3);
    for (size_t i=0 ; i<bytelen ; i+=DumpUnitSize(unittype)) {
        if (!str.empty())
            str += " ";
        str += dumponeunit(buf+i, bytelen-i, unittype);
    }

    return str;
}


std::string dumpraw(const uint8_t *buf, size_t len, size_t &usedlen)
{
    std::string str((const char*)buf, len);
    str.resize(strlen(str.c_str()));
    size_t i= str.size();
    while (i<len && buf[i]==0) i++;

    usedlen= i;

    return str;
}
// todo: add 'summarize' option, to generate 'dup' constructs.
//       [DONE]make strings more readable, by breaking on NUL.
std::string dumpstrings(const uint8_t *buf, size_t len, size_t &usedlen)
{
    std::string result;
    bool bQuoted= false;
    bool bThisIsEolChar= false;
    std::string escaped= "\n\r\t";

    size_t i;
    for (i=0 ; i<len ; i++)
    {
        bool bNeedsEscape= escaped.find((char)buf[i])!=escaped.npos 
            || buf[i]=='\"' 
            || buf[i]=='\\';

        if (isprint(buf[i]) || bNeedsEscape) {
            if (!bQuoted) {
                if (!result.empty())
                    result += ",";
                result += "\"";
                bQuoted= true;
            }
            if (bNeedsEscape) {
                std::string escapecode;
                switch(buf[i]) {
                    case '\n': escapecode= "\\n"; break;
                    case '\r': escapecode= "\\r"; break;
                    case '\t': escapecode= "\\t"; break;
                    case '\"': escapecode= "\\\""; break;
                    case '\\': escapecode= "\\\\"; break;
                    default:
                       escapecode= stringformat("\\x%02x", buf[i]);
                }
                result += escapecode;
            }
            else {
                result += (char) buf[i];
            }
        }
        else {
            if (bQuoted) {
                result += "\"";
                bQuoted= false;
            }
            if (!result.empty())
                result += ",";
            result += stringformat("%02x", buf[i]);
        }
        if (i+1<len) {
            if (i==0)
                bThisIsEolChar = (buf[i]==0x0a || buf[i]==0x0d || buf[i]==0);

            bool bNextIsEolChar= (buf[i+1]==0x0a || buf[i+1]==0x0d || buf[i+1]==0);
            if (bThisIsEolChar && !bNextIsEolChar) {
                i++;
                break;
            }
            bThisIsEolChar= bNextIsEolChar;
        }
    }

    if (bQuoted) {
        result += "\"";
        bQuoted= false;
    }

    usedlen= i;

    return result;
}
void writedumpline(int64_t llOffset, const std::string& line)
{
    if (llOffset>>32) {
        // using extra variable to work around apparent compiler bug:
        // 'low' is passed to debug in eax:edx,  with xor eax,eax  to clear high part.
        // then in debug, the low value is read from 'rdx',  but the upper part of rdx
        // was _NOT_cleared.
        uint32_t low = static_cast<uint32_t>(llOffset);
        print("%x%08x: %s\n", static_cast<uint32_t>(llOffset>>32), low, line.c_str());
    }
    else
        print("%08x: %s\n", static_cast<uint32_t>(llOffset), line.c_str());
}
void bighexdump(int64_t llOffset, const uint8_t *data, size_t size, uint32_t flags/*=hexdumpflags(DUMPUNIT_BYTE, 16, DUMP_HEX_ASCII)*/)
{
    DumpUnitType dumpunittype= dumpunit_from_flags(flags);
    DumpFormat dumpformat= dumpformat_from_flags(flags);
    int unitsperline= unitsperline_from_flags(flags);
    bool bWithOffset= (flags&HEXDUMP_WITH_OFFSET)!=0;
    bool bSummarize= (flags&HEXDUMP_SUMMARIZE)!=0;

    bool bLastBlock= (flags&HEXDUMP_MOREFOLLOWS)==0;

    if (unitsperline==0)
        unitsperline= 0x1000;
    size_t bytesperline= unitsperline*DumpUnitSize(dumpunittype);

    if (dumpformat==DUMP_STRINGS || dumpformat==DUMP_RAW) {
        bytesperline= size;
    }

    std::string prevline;
    int nSameCount=0;

    for (size_t i=0 ; i<size ; i+=bytesperline) {
        // not using 'min' since msvc's header files are broken, and make it
        // quite hard to include them in an order as not to redefine 'min' in
        // an inconvenient way.

        size_t len= bytesperline; if (len > size-i) len= size-i;

        std::string line;
        if (dumpformat==DUMP_STRINGS) {
            line= dumpstrings(data+i, size-i, bytesperline);
        }
        if (dumpformat==DUMP_RAW) {
            line= dumpraw(data+i, size-i, bytesperline);
        }
        if (dumpformat==DUMP_HEX_ASCII || dumpformat==DUMP_HEX) {
            line= hexdumpunit(data+i, len, dumpunittype);
            if (len < bytesperline) {
                int charsinfullline= (2*DumpUnitSize(dumpunittype)+1)*unitsperline-1;
                line.append(charsinfullline-line.size(), ' ');
            }
        }
        if (dumpformat==DUMP_HEX_ASCII || dumpformat==DUMP_ASCII)  {
            if (!line.empty())
                line += "  ";
            line += asciidump(data+i, len);
            if (len < bytesperline) {
                line.append(bytesperline-len, ' ');
            }
        }

        if (dumpformat!=DUMP_RAW && bSummarize && line == prevline) {
            nSameCount++;
        }
        else {
            if (nSameCount==1)
                writedumpline(llOffset+i-bytesperline, prevline);
            else if (nSameCount>1) {
                print("*  [ 0x%x lines ]\n", nSameCount);
            }
            nSameCount= 0;

            if (bWithOffset)
                writedumpline(llOffset+i, line);
            else if (dumpformat==DUMP_RAW)
                print("%s", line.c_str());
            else
                print("%s\n", line.c_str());
        }

        prevline= line;
    }
    if (nSameCount==1)
        writedumpline(llOffset+size-bytesperline, prevline);
    else if (nSameCount>1)
        print("*  [ 0x%x lines ]\n", nSameCount);
    if (bLastBlock && nSameCount>0)
        writedumpline(llOffset+size, "");
}

