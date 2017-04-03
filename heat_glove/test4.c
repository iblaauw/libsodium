#include <sodium.h>
#include "sodium/debug_io.h"

#define MESSAGE ((const unsigned char *) "test")
#define MESSAGE_LEN 5
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)

void printb(uint8_t* arr, size_t size) {
	printf("0x");
	for(int i = 0; i < size; i++) {
		printf("%x", arr[i]);
	}
	printf("\n");
}

int main() {
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char key[crypto_secretbox_KEYBYTES];
	unsigned char ciphertext[CIPHERTEXT_LEN];

	wr_debug(343);

	randombytes_buf(nonce, sizeof nonce);
	randombytes_buf(key, sizeof key);

	crypto_secretbox_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce, key);

	unsigned char decrypted[MESSAGE_LEN];
	if (crypto_secretbox_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce, key) != 0) {
			/* message forged! */
			printf("message forged!\n");
	}
	printf("message: %s\n", decrypted);

return 0;
}
