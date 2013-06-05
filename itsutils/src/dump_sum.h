
#ifndef __DUMP_SUM_H__
#define __DUMP_SUM_H__

class DATASUM {
public:
    uint64_t sumxor8;
    uint32_t sumxor4;
    uint16_t sumxor2;
    uint8_t sumxor1;

    uint64_t sum8_le;
    uint64_t sum4_le;
    uint64_t sum2_le;
    uint64_t sum8_be;
    uint64_t sum4_be;
    uint64_t sum2_be;
    uint64_t sum1;

    int idx;

    uint8_t data[8];

    DATASUM() : sumxor8(0), sumxor4(0), sumxor2(0), sumxor1(0), sum8_le(0), sum4_le(0), sum2_le(0), sum8_be(0), sum4_be(0), sum2_be(0), sum1(0), idx(0)
    {
        memset(data, 0, 8);
    }
    void add_byte(unsigned char byte)
    {
        data[idx & 7]= byte;
        
        sum1 += byte;
        sumxor1 ^= byte;

        if (idx&1) {
            unsigned char *p= &data[(idx&7)-1];
            sum2_be += get16be(p);
            sum2_le += get16le(p);
            sumxor2 ^= get16le(p);

            if ((idx&3)==3) {
                unsigned char *p= &data[(idx&7)-3];
                sum4_be += get32be(p);
                sum4_le += get32le(p);
                sumxor4 ^= get32le(p);

                if ((idx&7)==7) {
                    unsigned char *p= &data[0];
                    sum8_be += get64be(p);
                    sum8_le += get64le(p);
                    sumxor8 ^= get64le(p);
                }
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

