static const char *b64tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64encode(const unsigned char *src, int len, char *dst) {
    while (len > 0) {
	*(dst++) = b64tab[src[0] >> 2];
	*(dst++) = b64tab[((src[0] & 0x03) << 4) | ((src[1] & 0xf0) >> 4)];
	*(dst++) = (len > 1) ? b64tab[((src[1] & 0x0f) << 2) | ((src[2] & 0xc0) >> 6)] : '=';
	*(dst++) = (len > 2) ? b64tab[src[2] & 0x3f] : '=';
	src += 3;
	len -= 3;
    }
}
