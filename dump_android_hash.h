#include <vector>
// hashing functions for android - sha1 and md5 are present in the bionic libc.a
// so we avoid having to link an external openssl library

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
};

#define MD5_DIGEST_LENGTH		20

typedef struct {
	uint32_t hash[4];
	uint32_t block[16];
	uint64_t count;
} MD5_CTX;

extern "C" {
extern void	MD5_Init(MD5_CTX *);
extern void	MD5_Update(MD5_CTX *, const u_char *, u_int);
extern void	MD5_Final(u_char[MD5_DIGEST_LENGTH], MD5_CTX *);
}
#define SHA1_DIGEST_LENGTH		20

typedef struct {
	uint32_t state[5];
	uint32_t count[2];
	uint8_t buffer[64];
} SHA1_CTX;


extern "C" {
extern void	SHA1Init(SHA1_CTX *);
extern void	SHA1Update(SHA1_CTX *, const u_char *, u_int);
extern void	SHA1Final(u_char[SHA1_DIGEST_LENGTH], SHA1_CTX *);
};

struct hashdefinition hashdefs[]= {
{"MD5",   sizeof(MD5_CTX), MD5_DIGEST_LENGTH, (PFN_Init)MD5_Init, (PFN_Update)MD5_Update, (PFN_Final)MD5_Final},
{"SHA1",  sizeof(SHA1_CTX), SHA1_DIGEST_LENGTH, (PFN_Init)SHA1Init, (PFN_Update)SHA1Update, (PFN_Final)SHA1Final},
};
#define NRHASHTYPES (sizeof(hashdefs)/sizeof(*hashdefs))
class CryptHash {
private:
    int m_type;
    std::vector<uint8_t>  m_state;
public:
    enum { 
            MD5,
            SHA1,
            HASHTYPECOUNT 
    }; 

    CryptHash() : m_type(-1) { }
    bool Close() { return true; }
    bool InitHash(int type)
    {
        if (type<0 || type>=(int)NRHASHTYPES)
            return false;
        m_type= type;
        m_state.resize(hashdefs[m_type].statesize);
        return 0!=hashdefs[m_type].init(&m_state[0]);
    }
    bool AddData(const std::vector<uint8_t> & data)
    {
        if (m_type<0) return false;
        return 0!=hashdefs[m_type].update(&m_state[0], &data[0], data.size());
    }
    bool GetHash(std::vector<uint8_t> & hash)
    {
        if (m_type<0) return false;
        hash.resize(hashdefs[m_type].hashsize);
        return 0!=hashdefs[m_type].final(&hash[0], &m_state[0]);
    }
    bool CalcHash(const std::vector<uint8_t> & data, std::vector<uint8_t> & hash, int type)
    {
        if (type<0 || type>=(int)NRHASHTYPES) return false;
        hashdefinition & H= hashdefs[type];
        hash.resize(H.hashsize);

        std::vector<uint8_t>  state(H.statesize);
        if (!H.init(&state[0]))
            return false;
        if (!H.update(&state[0], &data[0], data.size()))
            return false;
        if (!H.final(&hash[0], &state[0]))
            return false;

        return true;
    }
    int hashtype() const { return m_type; }
    const char*hashname() const
    {
        if (m_type<0) return "unknown";
        return hashdefs[m_type].name;
    }
};

