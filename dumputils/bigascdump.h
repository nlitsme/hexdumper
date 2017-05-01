#pragma once
#include <string>

std::string bigascdump(const uint8_t *first, size_t size, const std::string& escaped, bool bBreakOnEol/*= false*/);

template<typename V>
inline std::string bigascdump(const V& buf, const std::string& escaped= "", bool bBreakOnEol= false)
{
    return bigascdump((const uint8_t*)&buf[0], buf.size(), escaped, bBreakOnEol);
}


