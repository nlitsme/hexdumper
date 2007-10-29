
#include <wincrypt.h>
#include "vectorutils.h"
#include "stringutils.h"
#include "debug.h"

class CryptProvider {
private:
        HCRYPTPROV m_hProv;
public:
	CryptProvider() : m_hProv(0) { }
	~CryptProvider() { Close(); }

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
        if (m_hProv) {
            CryptReleaseContext(m_hProv, 0);
            m_hProv= NULL;
        }
        return true;
    }
	bool GetHandle(HCRYPTPROV &hProv)
	{
		if (m_hProv==NULL && !Open())
			return false;
		hProv= m_hProv;
		return true;
	}
};
class CryptHash {
private:
	    CryptProvider &m_prov;
        HCRYPTHASH m_hHash;
        int m_type;
public:
    enum { MD2, MD4, MD5, SHA1, SHA256, SHA384, SHA512 }; 

    CryptHash(CryptProvider &provider) : m_prov(provider), m_hHash(0), m_type(0) { }

    ~CryptHash() { Close(); }
    bool Close()
    {
        if (m_hHash!=NULL)
            CloseHash();
        return true;
    }

    bool InitHash(int type)
    {
        HCRYPTPROV hProv;
		if (!m_prov.GetHandle(hProv))
			return false;

        if (m_hHash!=NULL)
            CloseHash();
        m_type= type==MD2   ? CALG_MD2
                :type==MD4   ? CALG_MD4
                :type==MD5   ? CALG_MD5
                :type==SHA1  ? CALG_SHA1
                :type==SHA256? CALG_SHA_256
                :type==SHA384? CALG_SHA_384
                :type==SHA512? CALG_SHA_512
                : type;
        bool silent= (m_type==type);

        if (!CryptCreateHash(hProv, (ALG_ID)m_type, 0, 0, &m_hHash))
        {
            if (!silent)
                error("CryptCreateHash(%08lx)", m_type);
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
            error("CryptHashData(%08lx)", m_type);
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
            error("CryptGetHashParam(%08lx, HASHVAL-size)", m_type);
            return false;
        }

        hash.resize(dwSize);
        if (!CryptGetHashParam(m_hHash, HP_HASHVAL, vectorptr(hash), &dwSize, 0))
        {
            error("CryptGetHashParam(%08lx, HASHVAL-data)", m_type);
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
    int hashtype() const { return m_type; }
    std::string hashname() const
    { 
        switch(GET_ALG_SID(m_type))
        {
            case ALG_SID_MD2               : return "MD2";
            case ALG_SID_MD4               : return "MD4";
            case ALG_SID_MD5               : return "MD5";
            case ALG_SID_SHA1              : return "SHA1";
            case ALG_SID_MAC               : return "MAC";
            case ALG_SID_RIPEMD            : return "RIPEMD";
            case ALG_SID_RIPEMD160         : return "RIPEMD160";
            case ALG_SID_SSL3SHAMD5        : return "SSL3SHAMD5";
            case ALG_SID_HMAC              : return "HMAC";
            case ALG_SID_TLS1PRF           : return "TLS1PRF";
            case ALG_SID_HASH_REPLACE_OWF  : return "OWF";
            case ALG_SID_SHA_256           : return "SHA_256";
            case ALG_SID_SHA_384           : return "SHA_384";
            case ALG_SID_SHA_512           : return "SHA_512";
            default: return stringformat("a_%08x", m_type);
        }
    }
};
