#pragma once
// some basic crc calculations with the crc32 polynomial.

#include "crc32.h"

class CRC32 {
    CRCCalc<uint64_t> _calc;
public:
    uint64_t crc;
    CRC32(uint64_t crc=0, uint64_t poly= 0xEDB88320, int bits=32)
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

