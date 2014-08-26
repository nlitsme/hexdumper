#ifndef __DUMP_CRC32_H__
#define __DUMP_CRC32_H__

#include "crc32.h"

class CRC32 {
    CRCCalc<uint32_t> _calc;
public:
    uint32_t crc;
    CRC32(uint32_t crc=0, uint32_t poly= 0xEDB88320, int bits=32)
        : _calc(poly, bits), crc(crc)
    {
    }

    void add_byte(unsigned char byte)
    {
        crc= _calc.crc(crc, byte);
    }

    void add_data(const unsigned char *data, int length)
    {
        while (length--) add_byte(*data++);
    }
};

#endif
