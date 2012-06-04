void base64encode(const unsigned char *src, int len, char *dst);
int base64decode(const char *src, void *dst, int max_len);

static const char *b64tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* dst must be at least (len + 2) / 3 * 4 + 1 bytes long and will be NUL terminated when done */
void base64encode(const unsigned char *src, int len, char *dst) {
    while (len > 0) {
	*(dst++) = b64tab[src[0] >> 2];
	*(dst++) = b64tab[((src[0] & 0x03) << 4) | ((src[1] & 0xf0) >> 4)];
	*(dst++) = (len > 1) ? b64tab[((src[1] & 0x0f) << 2) | ((src[2] & 0xc0) >> 6)] : '=';
	*(dst++) = (len > 2) ? b64tab[src[2] & 0x3f] : '=';
	src += 3;
	len -= 3;
    }
    *dst = 0;
}

static unsigned int val(const char **src) {
    while (1) {
	char c = **src;
	if (c) src[0]++; else return 0x10000;
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	if (c == '=')
	    return 0x10000;
	/* we loop as to skip any blanks, newlines etc. */
    }
}

/* returns the decoded length or -1 if max_len was not enough */
int base64decode(const char *src, void *dst, int max_len) {
    unsigned char *t = (unsigned char*) dst, *end = t + max_len;
    while (*src && t < end) {
	unsigned int v = val(&src);
	if (v > 64) break;
	*t = v << 2;
	v = val(&src);
	*t |= v >> 4;
	if (v < 64) {
	    if (++t == end) return -1;
	    *t = v << 4;
	    v = val(&src);
	    *t |= v >> 2;
	    if (v < 64) {
		if (++t == end) return -1;
		*t = v << 6;
		v = val(&src);
		*t |= v & 0x3f;
		if (v < 64) t++;
	    }
	}
    }
    return (int) (t - (unsigned char*) dst);
}
