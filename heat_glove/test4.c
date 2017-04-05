#include <sodium.h>


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
	unsigned char ciphertext[CIPHERTEXT_LEN];

	sodium_init();

	safekey_t sk = crypto_keygen(12);

//	printf("enc key: ");
//	printb(sk.key, 12 + 16);
//	printf("\n");
//
//	printf("nonce: ");
//	printb(sk.nonce, 24);
//	printf("\n");


	randombytes_buf(nonce, sizeof nonce);

	crypto_secretbox_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce, sk);

	unsigned char decrypted[MESSAGE_LEN];
	if (crypto_secretbox_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce, sk) != 0) {
			/* message forged! */
			printf("message forged!\n");
	}
	printf("message: %s\n", decrypted);

return 0;
}
