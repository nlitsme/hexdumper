
#ifndef __DUMP_SUM_H__
#define __DUMP_SUM_H__

class DATASUM {
public:
    unsigned long sumxor4;
    unsigned long sumxor2;
    unsigned long sumxor1;
    unsigned long sum4;
    unsigned long sum2;
    unsigned long sum1;
    int idx;
    union {
        unsigned long l;
        unsigned short w[2];
        unsigned char b[4];
    } data;
    DATASUM() : sumxor4(0), sumxor2(0), sumxor1(0), sum4(0), sum2(0), sum1(0), idx(0)
    {
        data.l= 0;
    }
    void add_byte(unsigned char byte)
    {
        data.b[idx & 3]= byte;
        
        sum1 += byte;
        sumxor1 ^= byte;

        if (idx&1) {
            sum2 += data.w[(idx/2)&1];
            sumxor2 ^= data.w[(idx/2)&1];

            if ((idx&3)==3) {
                sum4 += data.l;
                sumxor4 ^= data.l;
            }
        }
        idx++;
    }

    void add_data(const unsigned char *data, int length)
    {
        while (length--) add_byte(*data++);
    }
};

#endif

