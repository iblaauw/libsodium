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

safekey_t _heat_glove_encrypt(size_t size, uint8_t* temp_key);

void _heat_glove_decrypt(safekey_t sk, uint8_t* buf);

#endif // __HEAT_GLOVE_H__
