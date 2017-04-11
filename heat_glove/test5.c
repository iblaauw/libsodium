#include <sodium.h>


#define MESSAGE ((const unsigned char *) "test")
#define MESSAGE_LEN 5

void printb(uint8_t* arr, size_t size) {
	printf("0x");
	for(int i = 0; i < size; i++) {
		printf("%02x", arr[i]);
	}
	printf("\n");
}

int main() {
	unsigned char mac[crypto_auth_BYTES];

	sodium_init();

	//safekey_t sk = crypto_keygen(crypto_auth_KEYBYTES);
	uint8_t key[crypto_auth_KEYBYTES];

	randombytes_buf(key, crypto_auth_KEYBYTES);

	crypto_auth(mac, MESSAGE, MESSAGE_LEN, key);

	if (crypto_auth_verify(mac, MESSAGE, MESSAGE_LEN, key) != 0) {
			/* message forged! */
			printf("message forged!\n");
	}
	printf("mac: ");
	printb(mac, crypto_auth_BYTES);

return 0;
}
