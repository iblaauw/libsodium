#ifndef __HG_ENCDEC_H__
#define __HG_ENCDEC_H__

#include "stdint.h"

void _hg_encrypt(uint32_t master, uint8_t* user_key, size_t size);
void _hg_decrypt(uint32_t master, uint8_t* user_key, size_t size);

#endif
