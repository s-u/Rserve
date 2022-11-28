#ifndef MD5_H
#define MD5_H

typedef unsigned int uint32;

struct MD5Context {
        uint32 buf[4];
        uint32 bits[2];
        unsigned char in[64];
};

void MD5Init(struct MD5Context *ctx);
void MD5Update(struct MD5Context *ctx, const unsigned char *buf, unsigned len);
void MD5Final(unsigned char digest[16],struct MD5Context *ctx);
void MD5Transform(uint32 buf[4], uint32 in[16]);

typedef struct MD5Context MD5_CTX;

unsigned char *md5hash(const void *buf, int len, unsigned char hash[16]);

#endif /* !MD5_H */
