
#include "crypto_kdf.h"
#include "randombytes.h"

#include "stdlib.h"
#include "string.h"
#include "crypto_secretbox.h"
#include "utils.h"

const char *
crypto_kdf_primitive(void)
{
    return crypto_kdf_PRIMITIVE;
}

size_t
crypto_kdf_bytes_min(void)
{
    return crypto_kdf_BYTES_MIN;
}

size_t
crypto_kdf_bytes_max(void)
{
    return crypto_kdf_BYTES_MAX;
}

size_t
crypto_kdf_contextbytes(void)
{
    return crypto_kdf_CONTEXTBYTES;
}

size_t
crypto_kdf_keybytes(void)
{
    return crypto_kdf_KEYBYTES;
}

int
crypto_kdf_derive_from_key(unsigned char *subkey, size_t subkey_len,
                           uint64_t subkey_id,
                           const char ctx[crypto_kdf_CONTEXTBYTES],
                           const unsigned char key[crypto_kdf_KEYBYTES])
{
    return crypto_kdf_blake2b_derive_from_key(subkey, subkey_len,
                                              subkey_id, ctx, key);
}

//void
//crypto_kdf_keygen(unsigned char k[crypto_kdf_KEYBYTES])
//{
//    randombytes_buf(k, crypto_kdf_KEYBYTES);
//}


safekey_t
crypto_keygen(size_t size) {
	uint8_t* temp_key = (uint8_t*) malloc(size);
	randombytes_buf(temp_key, size);

	safekey_t k = _heat_glove_encrypt(size, temp_key);
	sodium_memzero(temp_key, size);
	free(temp_key);

	return k;
}

safekey_t
crypto_keygen_file(size_t size, const char* filename) {
	safekey_t k = {0};

	return k;
}

void
crypto_keyfree(safekey_t k) {
	sodium_memzero(k.key, k.size + crypto_secretbox_MACBYTES);
	sodium_memzero(k.nonce, crypto_secretbox_NONCEBYTES);

	free(k.key);
	free(k.nonce);

	k.key = NULL;
	k.nonce = NULL;

}

int
crypto_key_extract(safekey_t sk, uint8_t* master) {
	printf("*** WARNING: You are extracting your secret key in plaintext ***\n");

	return _heat_glove_decrypt(sk, master);

}

