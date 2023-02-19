#include <cpputils/formatter.h>
#include "bigascdump.h"

// todo: also recognize unicode strings
std::string bigascdump(const uint8_t *first, size_t size, const std::string& escaped, bool bBreakOnEol/*= false*/)
{
    std::string result;
    bool bQuoted= false;
    bool bLastWasEolChar= false;

    bool bWarnedLarge= false;
    const uint8_t *p= first;
    const uint8_t *last= first+size;
    while (p<last)
    {
        if (result.size()>0x1000000 && !bWarnedLarge) {
            throw "ascdump error";
        }

        bool bNeedsEscape= escaped.find((char)*p)!=escaped.npos 
            || *p=='\"' 
            || *p=='\\';

        bool bThisIsEolChar= (*p==0x0a || *p==0x0d || *p==0);

        if ((p>first+1) && p[-2]==*p && p[-1]==*p && (*p==0 || *p==0xff)) {
            const uint8_t *seqstart= p-2;
            while (p<last && *p==*seqstart)
                p++;
            result += stringformat(" [x%d]", p-seqstart);
            p--;
        }
        if (bLastWasEolChar && !bThisIsEolChar && bBreakOnEol) {
            if (bQuoted)
                result += "\"";
            bQuoted= false;
            result += "\n";
        }

        if (isprint(*p) || bNeedsEscape) {
            if (!bQuoted) {
                if (!result.empty() && *result.rbegin()!='\n')
                    result += ",";
                result += "\"";
                bQuoted= true;
            }
            if (bNeedsEscape) {
                std::string escapecode;
                switch(*p) {
                    case '\n': escapecode= "\\n"; break;
                    case '\r': escapecode= "\\r"; break;
                    case '\t': escapecode= "\\t"; break;
                    case '\"': escapecode= "\\\""; break;
                    case '\\': escapecode= "\\\\"; break;
                    default:
                       escapecode= stringformat("\\x%02x", *p);
                }
                result += escapecode;
            }
            else {
                result += (char) *p;
            }
        }
        else {
            if (bQuoted) {
                result += "\"";
                bQuoted= false;
            }
            if (!result.empty())
                result += ",";
            result += stringformat("%02x", *p);
        }
        bLastWasEolChar= bThisIsEolChar;

        p++;
    }

    if (bQuoted) {
        result += "\"";
        bQuoted= false;
    }

    return result;
}
