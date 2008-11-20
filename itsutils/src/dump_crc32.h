#ifndef __DUMP_CRC32_H__
#define __DUMP_CRC32_H__

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
class CRC32 {
public:
    unsigned long crc;
    unsigned long crc32tab[256];
    CRC32(unsigned long crc=0, unsigned long poly= 0xEDB88320) : crc(crc) 
    {
        for (unsigned long i=0 ; i<256 ; i++)
            crc32tab[i]= calccrc32tab(i, poly);
    }
    static unsigned long calccrc32tab(unsigned long c, unsigned long poly)
    {
        unsigned long value= c;
        for (int i=0 ; i<8 ; i++)
        {
            value = ((value>>1)&0x7fffffff) ^ ( (value&1) ? poly : 0 );
        }
        return value;
    }
    void add_byte(unsigned char byte)
    {
        crc= (crc>>8) ^ crc32tab[(crc^byte)&0xff];
    }

    void add_data(const unsigned char *data, int length)
    {
        while (length--) add_byte(*data++);
    }
};

#endif
