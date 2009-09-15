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

// some defs to make the openssl interface more consistent
#ifdef SHA512_DIGEST_LENGTH
typedef SHA512_CTX SHA384_CTX;
#endif
#ifdef SHA256_DIGEST_LENGTH
typedef SHA256_CTX SHA224_CTX;
#endif
#ifndef OPENSSL_NO_SHA1
#define SHA1_DIGEST_LENGTH SHA_DIGEST_LENGTH
typedef SHA_CTX SHA1_CTX;
#endif

struct hashdefinition hashdefs[]= {
#ifdef MD2_DIGEST_LENGTH
{"MD2",   sizeof(MD2_CTX), MD2_DIGEST_LENGTH, (PFN_Init)MD2_Init, (PFN_Update)MD2_Update, (PFN_Final)MD2_Final, MD2},
#endif
#ifdef MD4_DIGEST_LENGTH
{"MD4",   sizeof(MD4_CTX), MD4_DIGEST_LENGTH, (PFN_Init)MD4_Init, (PFN_Update)MD4_Update, (PFN_Final)MD4_Final, MD4},
#endif
#ifdef MD5_DIGEST_LENGTH
{"MD5",   sizeof(MD5_CTX), MD5_DIGEST_LENGTH, (PFN_Init)MD5_Init, (PFN_Update)MD5_Update, (PFN_Final)MD5_Final, MD5},
#endif
#ifdef SHA_DIGEST_LENGTH
{"SHA",   sizeof(SHA_CTX), SHA_DIGEST_LENGTH, (PFN_Init)SHA_Init, (PFN_Update)SHA_Update, (PFN_Final)SHA_Final, SHA},
#endif
#ifdef SHA1_DIGEST_LENGTH
{"SHA1",   sizeof(SHA1_CTX), SHA1_DIGEST_LENGTH, (PFN_Init)SHA1_Init, (PFN_Update)SHA1_Update, (PFN_Final)SHA1_Final, SHA},
#endif
#ifdef SHA224_DIGEST_LENGTH
{"SHA224",   sizeof(SHA224_CTX), SHA224_DIGEST_LENGTH, (PFN_Init)SHA224_Init, (PFN_Update)SHA224_Update, (PFN_Final)SHA224_Final, SHA224 },
#endif
#ifdef SHA256_DIGEST_LENGTH
{"SHA256",   sizeof(SHA256_CTX), SHA256_DIGEST_LENGTH, (PFN_Init)SHA256_Init, (PFN_Update)SHA256_Update, (PFN_Final)SHA256_Final, SHA256 },
#endif
#ifdef SHA384_DIGEST_LENGTH
{"SHA384",   sizeof(SHA384_CTX), SHA384_DIGEST_LENGTH, (PFN_Init)SHA384_Init, (PFN_Update)SHA384_Update, (PFN_Final)SHA384_Final, SHA384 },
#endif
#ifdef SHA512_DIGEST_LENGTH
{"SHA512",   sizeof(SHA512_CTX), SHA512_DIGEST_LENGTH, (PFN_Init)SHA512_Init, (PFN_Update)SHA512_Update, (PFN_Final)SHA512_Final, SHA512 },
#endif
#ifdef RIPEMD160_DIGEST_LENGTH
{"RIPEMD160",   sizeof(RIPEMD160_CTX), RIPEMD160_DIGEST_LENGTH, (PFN_Init)RIPEMD160_Init, (PFN_Update)RIPEMD160_Update, (PFN_Final)RIPEMD160_Final, RIPEMD160 },
#endif

    // todo: add whirlpool
    // ripemd128, ripemd256, ripemd320  http://homes.esat.kuleuven.be/~bosselae/ripemd160.html
    // haval
    // ripemd
    // tiger-1
    // panama
    // gost
    // ghash-32-3
    // ghash-32-5
    // radiogatun
    // unix passwd crypt ( des, md5, ...)
    // various hmac's, with user supplied key
};
#define NRHASHTYPES (sizeof(hashdefs)/sizeof(*hashdefs))
class CryptHash {
private:
    int m_type;
    ByteVector m_state;
public:
    enum { 
#ifdef MD2_DIGEST_LENGTH
	    MD2,
#endif
#ifdef MD4_DIGEST_LENGTH
            MD4,
#endif
#ifdef MD5_DIGEST_LENGTH
            MD5,
#endif
#ifdef SHA_DIGEST_LENGTH
            SHA,
#endif
#ifdef SHA1_DIGEST_LENGTH
            SHA1,
#endif
#ifdef SHA224_DIGEST_LENGTH
            SHA224,
#endif
#ifdef SHA256_DIGEST_LENGTH
            SHA256,
#endif
#ifdef SHA384_DIGEST_LENGTH
            SHA384,
#endif
#ifdef SHA512_DIGEST_LENGTH
            SHA512,
#endif
#ifdef RIPEMD160_DIGEST_LENGTH
            RIPEMD160,
#endif
            HASHTYPECOUNT 
    }; 

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
