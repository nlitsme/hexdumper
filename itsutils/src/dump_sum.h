
#ifndef __DUMP_SUM_H__
#define __DUMP_SUM_H__

class DATASUM {
public:
    unsigned long sumxor4;
    unsigned long sumxor2;
    unsigned long sumxor1;

    unsigned long sum4_le;
    unsigned long sum2_le;
    unsigned long sum4_be;
    unsigned long sum2_be;
    unsigned long sum1;
    int idx;
    union {
        unsigned long l;
        unsigned short w[2];
        unsigned char b[4];
    } data;
    DATASUM() : sumxor4(0), sumxor2(0), sumxor1(0), sum4_le(0), sum2_le(0), sum4_be(0), sum2_be(0), sum1(0), idx(0)
    {
        data.l= 0;
    }
    void add_byte(unsigned char byte)
    {
        data.b[idx & 3]= byte;
        
        sum1 += byte;
        sumxor1 ^= byte;

        if (idx&1) {
            unsigned char *p= &(data.b[(idx&3)-1]);
            sum2_be += (p[0]<<8)|p[1];
            sum2_le += (p[1]<<8)|p[0];
            sumxor2 ^= data.w[(idx/2)&1];

            if ((idx&3)==3) {
                sum4_be += (data.b[0]<<24)|(data.b[1]<<16)|(data.b[2]<<8)|data.b[3];
                sum4_le += (data.b[3]<<24)|(data.b[2]<<16)|(data.b[1]<<8)|data.b[0];
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

