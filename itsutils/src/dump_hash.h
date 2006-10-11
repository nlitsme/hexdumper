
#include <wincrypt.h>
#include "vectorutils.h"
#include "debug.h"

class CryptHash {
private:
        HCRYPTPROV m_hProv;
        HCRYPTHASH m_hHash;
public:
    enum { MD5, SHA1, SHA256};

    CryptHash() : m_hProv(0), m_hHash(0) { }
    ~CryptHash() { Close(); }
    bool Open()
    {
        if (!CryptAcquireContext(&m_hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        {
            error("CryptAcquireContext");
            m_hProv= NULL;
            return false;
        }
        return true;
    }
    bool Close()
    {
        CloseHash();
        if (m_hProv) {
            CryptReleaseContext(m_hProv, 0);
            m_hProv= NULL;
        }
        return true;
    }

    bool InitHash(int type)
    {
        if (m_hProv==NULL && !Open())
            return false;

        if (m_hHash!=NULL)
            CloseHash();
        if (!CryptCreateHash(m_hProv, 
                    type==MD5?  CALG_MD5
                    :type==SHA1? CALG_SHA1
                    :type==SHA256? CALG_SHA_256
                    :0 , 0, 0, &m_hHash))
        {
            error("CryptCreateHash");
            return false;
        }
        return true;
    }
    bool CloseHash()
    {
        if (m_hHash) {
            CryptDestroyHash(m_hHash);
            m_hHash= NULL;
        }
        return true;
    }

    bool AddData(const ByteVector& data)
    {
        if (m_hHash==NULL)
            return false;
        if (!CryptHashData(m_hHash, vectorptr(data), data.size(), 0))
        {
            error("CryptHashData");
            return false;
        }
        return true;
    }
    bool GetHash(ByteVector& hash)
    {
        if (m_hHash==NULL)
            return false;
        DWORD dwSize;
        if (!CryptGetHashParam(m_hHash, HP_HASHVAL, NULL, &dwSize, 0))
        {
            error("CryptGetHashParam");
            return false;
        }

        hash.resize(dwSize);
        if (!CryptGetHashParam(m_hHash, HP_HASHVAL, vectorptr(hash), &dwSize, 0))
        {
            error("CryptGetHashParam");
            return false;
        }
        CloseHash();

        return true;
    }

    bool CalcHash(const ByteVector& data, ByteVector& hash, int type)
    {
        if (!InitHash(type))
            return false;
        if (!AddData(data))
            return false;

        if (!GetHash(hash))
            return false;
        return true;
    }
};
