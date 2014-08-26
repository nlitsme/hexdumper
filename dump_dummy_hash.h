#include "vectorutils.h"
class CryptHash {
public:
    enum { 
            MD4,
            MD5,
            SHA1,
            HASHTYPECOUNT 
    }; 

    bool InitHash(int type)
    {
        return true;
    }
    bool AddData(const ByteVector& data)
    {
        return true;
    }
    bool GetHash(ByteVector& hash)
    {
        return true;
    }
    bool CalcHash(const ByteVector& data, ByteVector& hash, int type)
    {
        return true;
    }
    int hashtype() const { return 0; }
    std::string hashname() const
    {
        return "unknown";
    }
};

