#include "stdio.h"
#include "stdint.h"

uint32_t enc(uint8_t* key, uint8_t* skey);

void printb(uint8_t* buf, size_t size) {
	printf("0x");
	for(int i = 0; i < size; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}

int encrypt(uint8_t* master, uint8_t* user_key, size_t size) {
	if (size % 16) {
		printf("not 16 byte divisible\n");
		return -1;
	}
	int num_times = size / 16;
	for (int cnt = 0; cnt < num_times; cnt++) {
		enc(master, user_key + (cnt*16));
	}
	fwrite(user_key, 1, size, stdout);

}

int main() {
//	uint32_t master = 0xAAAAAAAA;
//	uint8_t buf[16] __attribute__((aligned(16)));
//
//	printf("ptxt buf: ");
//	printb(buf, 16);
//	uint32_t val = enc(master, buf);
//	
//	printf("val should be A's: %x, and pntr: %x\n", val, buf);
//	
//	printf("enc buf: ");
//	printb(buf, 16);

	uint8_t key[16] = {0};
	uint8_t chunks[16] = {0};

	int num_times = 0;	

	FILE * fp = freopen(NULL, "rb", stdin);
	fread(key, 1, sizeof(key), fp);
	
	while(fread(chunks, 1, sizeof(chunks), fp) ) {
		encrypt(key, chunks, 16);
		num_times++;
	}
	//printf("num time: %d\n", num_times);

	//printb(key, 16);
	//printb(chunks, 16);

	return 0;

}
