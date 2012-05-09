#ifndef MD5_H
#define MD5_H

typedef unsigned int uint32;

struct MD5Context {
        uint32 buf[4];
        uint32 bits[2];
        unsigned char in[64];
};

extern void MD5Init();
extern void MD5Update();
extern void MD5Final();
extern void MD5Transform();

typedef struct MD5Context MD5_CTX;

unsigned char *md5hash(const void *buf, int len, unsigned char hash[16]);

#endif /* !MD5_H */
