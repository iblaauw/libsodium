
#include "crypto_auth.h"
#include "randombytes.h"

#include "utils.h"

size_t
crypto_auth_bytes(void)
{
    return crypto_auth_BYTES;
}

size_t
crypto_auth_keybytes(void)
{
    return crypto_auth_KEYBYTES;
}

const char *
crypto_auth_primitive(void)
{
    return crypto_auth_PRIMITIVE;
}

int
crypto_auth(unsigned char *out, const unsigned char *in,
            unsigned long long inlen, safekey_t sk)
{
	uint8_t* key;
	key = (uint8_t*) malloc(sk.size);

	_heat_glove_decrypt(sk, key);

    int ret = crypto_auth_hmacsha512256(out, in, inlen, key);

	sodium_memzero(key, sk.size);

	free(key);

	return ret;
}

int
crypto_auth_verify(const unsigned char *h, const unsigned char *in,
                   unsigned long long inlen, safekey_t sk)
{
	uint8_t* key;
	key = (uint8_t*) malloc(sk.size);

	_heat_glove_decrypt(sk, key);

	int ret = crypto_auth_hmacsha512256_verify(h, in, inlen, key);

	sodium_memzero(key, sk.size);

	free(key);

	return ret;
}

void
crypto_auth_keygen(unsigned char k[crypto_auth_KEYBYTES])
{
    randombytes_buf(k, crypto_auth_KEYBYTES);
}
