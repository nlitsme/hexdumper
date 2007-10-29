#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include "debug.h"
#include "vectorutils.h"
#include "stringutils.h"

typedef int (*PFN_Init)(void *state);
typedef int (*PFN_Update)(void *state, const unsigned char *data, size_t len);
typedef int (*PFN_Final)(unsigned char *hash, void *state);
struct hashdefinition {
    const char *name;
    int statesize;
    int hashsize;
    int (*init)(void *state);
    int (*update)(void *state, const unsigned char *data, size_t len);
    int (*final)(unsigned char *hash, void *state);
    unsigned char *(*calc)(const unsigned char *data, size_t len, unsigned char *hash);
};

typedef SHA512_CTX SHA384_CTX;

struct hashdefinition hashdefs[]= {
{"MD2",   sizeof(MD2_CTX), MD2_DIGEST_LENGTH, (PFN_Init)MD2_Init, (PFN_Update)MD2_Update, (PFN_Final)MD2_Final, MD2},
{"MD4",   sizeof(MD4_CTX), MD4_DIGEST_LENGTH, (PFN_Init)MD4_Init, (PFN_Update)MD4_Update, (PFN_Final)MD4_Final, MD4},
{"MD5",   sizeof(MD5_CTX), MD5_DIGEST_LENGTH, (PFN_Init)MD5_Init, (PFN_Update)MD5_Update, (PFN_Final)MD5_Final, MD5},
{"SHA",   sizeof(SHA_CTX), SHA_DIGEST_LENGTH, (PFN_Init)SHA_Init, (PFN_Update)SHA_Update, (PFN_Final)SHA_Final, SHA},
{"SHA256",   sizeof(SHA256_CTX), SHA256_DIGEST_LENGTH, (PFN_Init)SHA256_Init, (PFN_Update)SHA256_Update, (PFN_Final)SHA256_Final, SHA256 },
{"SHA384",   sizeof(SHA384_CTX), SHA384_DIGEST_LENGTH, (PFN_Init)SHA384_Init, (PFN_Update)SHA384_Update, (PFN_Final)SHA384_Final, SHA384 },
{"SHA512",   sizeof(SHA512_CTX), SHA512_DIGEST_LENGTH, (PFN_Init)SHA512_Init, (PFN_Update)SHA512_Update, (PFN_Final)SHA512_Final, SHA512 },
{"RIPEMD160",   sizeof(RIPEMD160_CTX), RIPEMD160_DIGEST_LENGTH, (PFN_Init)RIPEMD160_Init, (PFN_Update)RIPEMD160_Update, (PFN_Final)RIPEMD160_Final, RIPEMD160 },
};
#define NRHASHTYPES (sizeof(hashdefs)/sizeof(*hashdefs))
class CryptHash {
private:
    int m_type;
    ByteVector m_state;
public:
    enum { MD2, MD4, MD5, SHA1, SHA256, SHA384, SHA512, RIPEMD160 }; 

    CryptHash() : m_type(-1) { }
    bool Close() { return true; }
    bool InitHash(int type)
    {
        if (type<0 || type>=NRHASHTYPES)
            return false;
        m_type= type;
        m_state.resize(hashdefs[m_type].statesize);
        return 0!=hashdefs[m_type].init(vectorptr(m_state));
    }
    bool AddData(const ByteVector& data)
    {
        if (m_type<0) return false;
        return 0!=hashdefs[m_type].update(vectorptr(m_state), vectorptr(data), data.size());
    }
    bool GetHash(ByteVector& hash)
    {
        if (m_type<0) return false;
        hash.resize(hashdefs[m_type].hashsize);
        return 0!=hashdefs[m_type].final(vectorptr(hash), vectorptr(m_state));
    }
    bool CalcHash(const ByteVector& data, ByteVector& hash, int type)
    {
        if (type<0 || type>=NRHASHTYPES) return false;
        hash.resize(hashdefs[type].hashsize);
        return NULL!=hashdefs[type].calc(vectorptr(data), data.size(), vectorptr(hash));
    }
    int hashtype() const { return m_type; }
    std::string hashname() const
    {
        if (m_type<0) return "unknown";
        return hashdefs[m_type].name;
    }
};
