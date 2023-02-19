// hash functions for microsoft platforms.
#include <cassert>
#include <exception>
#include <cpputils/formatter.h>
#include <string>
#include <wincrypt.h>

class winerror : std::exception {
    DWORD _code;
    std::string _msg;
public:
    winerror(const std::string& msg) : _code(GetLastError()), _msg(msg) { }
    virtual const char* what() const noexcept
    {
        return stringformat("[%08x] %s", _code, _msg).c_str();
    }
};
class CryptProvider {
private:
        HCRYPTPROV m_hProv;
public:
    CryptProvider() : m_hProv(0) { }
    ~CryptProvider() { Close(); }

    void Open()
    {
        if (!CryptAcquireContext(&m_hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        {
            m_hProv= NULL;
            throw winerror("CryptAcquireContext");
        }
    }
    void Close()
    {
        if (m_hProv) {
            CryptReleaseContext(m_hProv, 0);
            m_hProv= NULL;
        }
    }
    HCRYPTPROV GetHandle()
    {
            if (m_hProv==NULL)
                Open();
            return m_hProv;
    }
};
class CryptHash {
private:
        CryptProvider &m_prov;
        HCRYPTHASH m_hHash;
        int m_type;
public:
    enum { MD2, MD4, MD5, SHA1, SHA256, SHA384, SHA512, HASHTYPECOUNT }; 

    CryptHash(CryptProvider &provider) : m_prov(provider), m_hHash(0), m_type(0) { }

    ~CryptHash() { Close(); }
    void Close()
    {
        if (m_hHash!=NULL)
            CloseHash();
    }

    void InitHash(int type)
    {
        HCRYPTPROV hProv = m_prov.GetHandle();

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
                throw winerror(stringformat("CryptCreateHash(%08lx)", m_type));
        }
    }
    void CloseHash()
    {
        if (m_hHash) {
            CryptDestroyHash(m_hHash);
            m_hHash= NULL;
        }
    }

    void AddData(const std::vector<uint8_t>& data)
    {
        assert(m_hHash!=NULL);
        if (!CryptHashData(m_hHash, &data[0], data.size(), 0))
            throw winerror(stringformat("CryptHashData(%08lx)", m_type));
    }
    std::vector<uint8_t> GetHash()
    {
        assert(m_hHash!=NULL);

        DWORD dwSize;
        if (!CryptGetHashParam(m_hHash, HP_HASHVAL, NULL, &dwSize, 0))
            throw winerror(stringformat("CryptGetHashParam(%08lx, HASHVAL-size)", m_type));

        std::vector<uint8_t> hash(dwSize);

        if (!CryptGetHashParam(m_hHash, HP_HASHVAL, &hash[0], &dwSize, 0))
            throw winerror(stringformat("CryptGetHashParam(%08lx, HASHVAL-data)", m_type));
        CloseHash();

        return hash;
    }

    std::vector<uint8_t> CalcHash(const std::vector<uint8_t>& data, int type)
    {
        InitHash(type);
        AddData(data);

        return GetHash();
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
