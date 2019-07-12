// hash functions based on openssl

//#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include <vector>
#include <cassert>
#include <stdexcept>
#include <stdint.h>

//#include "debug.h"
//#include "vectorutils.h"
//#include "stringutils.h"



/*  --  hash("")  for various algorithms
md2            8350e5a3e24c153df2275c9f80692773
md4            31d6cfe0d16ae931b73c59d7e0c089c0
md5            d41d8cd98f00b204e9800998ecf8427e
sha1           da39a3ee5e6b4b0d3255bfef95601890afd80709
sha224         d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f
sha256         e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
sha384         38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
sha512         cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
ripemd160      9c1185a5c5e9fc54612808977ee8f548b2258d31

-- not yet implemented: ripem, whirlpool, tiger, snefru, salsa, haval
ripemd128      cdf26213a150dc3ecb610f18f6b38b46
ripemd256      02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d
ripemd320      22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8
whirlpool      19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3
tiger-192      3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3


-- note these forgot to reverse the output bytes
tiger128,3     24f0130c63ac933216166e76b1bb925f
tiger160,3     24f0130c63ac933216166e76b1bb925ff373de2d
tiger192,3     24f0130c63ac933216166e76b1bb925ff373de2d49584e7a
tiger128,4     4635fff6a778cc243da15c69594e98e7
tiger160,4     4635fff6a778cc243da15c69594e98e79451256e
tiger192,4     4635fff6a778cc243da15c69594e98e79451256e680b4e80
snefru         8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881
snefru256      8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881
gost           ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d
adler32        00000001
crc32          00000000
crc32b         00000000
salsa10        00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
salsa20        00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
haval128,3     c68f39913f901f3ddf44c707357a7d70
haval160,3     d353c3ae22a25401d257643836d7231a9a95f953
haval192,3     e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e
haval224,3     c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d
haval256,3     4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17
haval128,4     ee6bbf4d6a46a679b3a856c88538bb98
haval160,4     1d33aae1be4146dbaaca0b6e70d7a11f10801525
haval192,4     4a8372945afa55c7dead800311272523ca19d42ea47b72da
haval224,4     3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e
haval256,4     c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b
haval128,5     184b8482a0c050dca54b59c7f05bf5dd
haval160,5     255158cfc1eed1a7be7c55ddd64d9790415b933b
haval192,5     4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85
haval224,5     4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e
haval256,5     be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330
*/
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
#ifdef SHA1_DIGEST_LENGTH
{"SHA",   sizeof(SHA1_CTX), SHA1_DIGEST_LENGTH, (PFN_Init)SHA1_Init, (PFN_Update)SHA1_Update, (PFN_Final)SHA1_Final, SHA},
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
#if !defined(__ANDROID__)
#ifdef RIPEMD160_DIGEST_LENGTH
{"RIPEMD160",   sizeof(RIPEMD160_CTX), RIPEMD160_DIGEST_LENGTH, (PFN_Init)RIPEMD160_Init, (PFN_Update)RIPEMD160_Update, (PFN_Final)RIPEMD160_Final, RIPEMD160 },
#endif
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

#define vectorptr(v)  ((v).empty()?NULL:&(v)[0])

#define NRHASHTYPES (sizeof(hashdefs)/sizeof(*hashdefs))
class CryptHash {
private:
    int m_type;
    std::vector<uint8_t>  m_state;
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
#ifdef SHA1_DIGEST_LENGTH
            SHA1,
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
#if !defined(__ANDROID__)
#ifdef RIPEMD160_DIGEST_LENGTH
            RIPEMD160,
#endif
#endif
            HASHTYPECOUNT 
    }; 

    CryptHash() : m_type(-1) { }
    bool Close() { return true; }
    void InitHash(int type)
    {
        assert(type>=0 && type<(int)NRHASHTYPES);

        m_type= type;
        m_state.resize(hashdefs[m_type].statesize);
        if (!hashdefs[m_type].init(vectorptr(m_state)))
            throw std::runtime_error("hash-init");
    }
    void AddData(const std::vector<uint8_t> & data)
    {
        assert(m_type>=0);
        if (!hashdefs[m_type].update(vectorptr(m_state), vectorptr(data), data.size()))
            throw std::runtime_error("hash-add");
    }
    std::vector<uint8_t> GetHash()
    {
        assert(m_type>=0);

        std::vector<uint8_t> hash(hashdefs[m_type].hashsize);
        if (!hashdefs[m_type].final(vectorptr(hash), vectorptr(m_state)))
            throw std::runtime_error("hash-final");

        return hash;
    }
    std::vector<uint8_t> CalcHash(const std::vector<uint8_t> & data, int type)
    {
        assert(type>=0 && type<(int)NRHASHTYPES);
        std::vector<uint8_t> hash(hashdefs[type].hashsize);
        if (!hashdefs[type].calc(vectorptr(data), data.size(), vectorptr(hash)))
            throw std::runtime_error("hash-calc");

        return hash;
    }
    int hashtype() const { return m_type; }
    const char *hashname() const
    {
        if (m_type<0) return "unknown";
        return hashdefs[m_type].name;
    }
};
