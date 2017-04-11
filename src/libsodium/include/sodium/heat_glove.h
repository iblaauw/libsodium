#ifndef __HEAT_GLOVE_H__
#define __HEAT_GLOVE_H__

#include <stdint.h>

typedef struct safekey_t {
	uint8_t * key;
	uint8_t * nonce;
	size_t size;
} safekey_t;

int wr_debug(uint32_t key);

long rd_debug(void);

void _heat_glove_init();

void _heat_glove_encrypt(uint8_t* buf, size_t size);

void _heat_glove_decrypt(uint8_t* buf, size_t size);

#endif // __HEAT_GLOVE_H__
