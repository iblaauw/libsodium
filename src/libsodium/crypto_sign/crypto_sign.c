
#include "crypto_sign.h"

size_t
crypto_sign_statebytes(void)
{
    return sizeof(crypto_sign_state);
}

size_t
crypto_sign_bytes(void)
{
    return crypto_sign_BYTES;
}

size_t
crypto_sign_seedbytes(void)
{
    return crypto_sign_SEEDBYTES;
}

size_t
crypto_sign_publickeybytes(void)
{
    return crypto_sign_PUBLICKEYBYTES;
}

size_t
crypto_sign_secretkeybytes(void)
{
    return crypto_sign_SECRETKEYBYTES;
}

const char *
crypto_sign_primitive(void)
{
    return crypto_sign_PRIMITIVE;
}

int
crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                         const unsigned char *seed)
{
    return crypto_sign_ed25519_seed_keypair(pk, sk, seed);
}

int
crypto_sign_keypair(unsigned char *pk, safekey_t *sk)
{
	unsigned char* temp_key;
	temp_key = (unsigned char*) malloc(crypto_sign_SECRETKEYBYTES);

    int ret = crypto_sign_ed25519_keypair(pk, temp_key);

	//*(sk) = _heat_glove_encrypt(crypto_sign_SECRETKEYBYTES, temp_key);

	sodium_memzero(temp_key, crypto_sign_SECRETKEYBYTES);

	free(temp_key);

	return ret;
}

int
crypto_sign(unsigned char *sm, unsigned long long *smlen_p,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk)
{
    return crypto_sign_ed25519(sm, smlen_p, m, mlen, sk);
}

int
crypto_sign_open(unsigned char *m, unsigned long long *mlen_p,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk)
{
    return crypto_sign_ed25519_open(m, mlen_p, sm, smlen, pk);
}

int
crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
                     const unsigned char *m, unsigned long long mlen,
                     const safekey_t sk)
{
	uint8_t* master;
	master = (uint8_t*) malloc(sk.size);

	//_heat_glove_decrypt(sk, master); 

    int ret = crypto_sign_ed25519_detached(sig, siglen_p, m, mlen, master);

	sodium_memzero(master, sk.size);

	free(master);

	return ret;
}

int
crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m,
                            unsigned long long mlen, const unsigned char *pk)
{
    return crypto_sign_ed25519_verify_detached(sig, m, mlen, pk);
}

int
crypto_sign_init(crypto_sign_state *state)
{
    return crypto_sign_ed25519ph_init(state);
}

int
crypto_sign_update(crypto_sign_state *state, const unsigned char *m,
                   unsigned long long mlen)
{
    return crypto_sign_ed25519ph_update(state, m, mlen);
}

int
crypto_sign_final_create(crypto_sign_state *state, unsigned char *sig,
                         unsigned long long *siglen_p, const unsigned char *sk)
{
    return crypto_sign_ed25519ph_final_create(state, sig, siglen_p, sk);
}

int
crypto_sign_final_verify(crypto_sign_state *state, unsigned char *sig,
                         const unsigned char *pk)
{
    return crypto_sign_ed25519ph_final_verify(state, sig, pk);
}
