#include "stdio.h"
#include "_hg_encdec.h"

uint32_t enc(uint32_t key, uint8_t* skey);

uint32_t dec(uint32_t key, uint8_t* skey);

void _hg_encrypt(uint32_t master, uint8_t* user_key, size_t size) {
	if (size % 16) {
		printf("not 16 byte divisible\n");
		return -1;
	}
	int num_times = size / 16;
	for (int cnt = 0; cnt < num_times; cnt++) {
		enc(master, user_key + (cnt*16));
	}

}

void _hg_decrypt(uint32_t master, uint8_t* user_key, size_t size) {
	if (size % 16) {
		printf("not 16 byte divisible\n");
		return -1;
	}
	int num_times = size / 16;
	for (int cnt = 0; cnt < num_times; cnt++) {
		dec(master, user_key + (cnt*16));
	}

}
