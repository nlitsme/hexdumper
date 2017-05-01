/* (C) 2003 XDA Developers  itsme@xs4all.nl
 *
 * $Header$
 */
#ifndef __CRC32_H__

#include <stdint.h>

// teststring: "123456789"
//              result        poly     reversepoly
//   CRC16:     0xBB3D            8005  a001
//   CRC-CCITT: 0x29B1            1021  8408
//   XMODEM:    0x31C3        
//   CRC-32:    0xCBF43926    04c11db7  edb88320

//  printf 123456789 | dump -crc:0:0xa001 -
//  printf 123456789 | dump -crc:-1:0xedb88320 -

// CCITT-32:   0x04C11DB7  =  x^32 + x^26 +  x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
// CRC-16:     0x8005      =  x^16 + x^15 + x^2 + 1
// CRC-CCITT:  0x1021      =  x^16 + x^12 + x^5 + 1
// CRC-XMODEM: 0x8408      =  x^16 + x^15 + x^10 + x^3
// 12bit-CRC:  0x80f       =  x^12 + x^11 + x^3 + x^2 + x + 1
// 10bit-CRC:  0x233       =  x^10 + x^9  + x^5  + x^4  + x  + 1
// 8bit-CRC:   0x07        =  x^8  + x^2  + x + 1

// 30bit-CRC: poly=0x6030B9C7 rev= 0xe39d0c06  ( used in qualcomm roms )
//   or 0x38E74301


template<typename T>
class CRCCalc {
public:
    CRCCalc(T poly, int bits)
    {
        _mask8=(1<<(bits-8))-1;
        _mask1=(1<<(bits-1))-1;
        initcrc(poly);

    }

    T crc(T prev, uint8_t c) const
    {
       return ((prev>>8)&_mask8) ^ crctab[(int)((prev&0xff)^c)];
    }

private:
        T crctab[256];
        T _mask8;
        T _mask1;
 
    T calccrctab(uint8_t c, T poly)
    {  
        T val = c;
        int i;
        for (i=0 ; i<8 ; i++)
        {
            val = ((val>>1)&_mask1) ^ ( (val&1) ? poly : 0);
        }
        return val;
    }

    void initcrc(T poly)
    {
       int i;
       for (i=0 ; i<256 ; i++)
          crctab[i]= calccrctab(i, poly);
    }
};


uint32_t add_to_crc32(uint32_t prev, uint8_t c);
uint32_t calccrc32(const uint8_t*buf, uint32_t len);

#define __CRC32_H__
#endif
