
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
internal_keygen(size_t size, uint8_t* temp_key) {
	uint8_t* key; // encrypted key to return in safekey_t
	uint8_t* nonce;
	uint8_t master_ext[crypto_secretbox_KEYBYTES];
	long master;

	key = (uint8_t*) malloc(size + crypto_secretbox_MACBYTES);
	nonce = (uint8_t*) malloc(crypto_secretbox_NONCEBYTES);

	// create a nonce	
	randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

	// get master key from debug reg
	master = rd_debug();	

	// extend master key to 32 BYTES for secretbox encrypting TODO:use diff alg
	for(int i=0; i < crypto_secretbox_KEYBYTES; i+= sizeof(long))
	{
		memcpy(master_ext+i, &master, sizeof(long));
	}

	// clear master key
	sodium_memzero(&master, sizeof(long));

	// encrypt key
	crypto_secretbox_easy(key, temp_key, size, nonce, master_ext);

	// clear master key extended form
	sodium_memzero(master_ext, crypto_secretbox_KEYBYTES);


	safekey_t k = { key, nonce, size };

	return k;
}

safekey_t
crypto_keygen(size_t size) {
	uint8_t* temp_key = (uint8_t*) malloc(size);
	safekey_t k = internal_keygen(size, temp_key);
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
	free(k.key);
	free(k.nonce);

	k.key = NULL;
	k.nonce = NULL;

}
