#ifndef __CRC_H__
#define __CRC_H__

// todo: resolve confusion with ../common/crc32.h, ../common/crc32.cpp
//
class CRC32 {
public:
    unsigned long crc;
    unsigned long crc32tab[256];
    CRC32(unsigned long crc=0, unsigned long poly= 0xEDB88320) : crc(crc) 
    {
        for (int i=0 ; i<256 ; i++)
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
