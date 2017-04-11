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
	sodium_init();
	
	
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];

	crypto_sign_keypair(pk, sk);

	unsigned char signed_message[crypto_sign_BYTES + MESSAGE_LEN];
	unsigned long long signed_message_len;

	crypto_sign(signed_message, &signed_message_len, MESSAGE, MESSAGE_LEN, sk);

	unsigned char unsigned_message[MESSAGE_LEN];
	unsigned long long unsigned_message_len;

	if (crypto_sign_open(unsigned_message, &unsigned_message_len, 
							signed_message, signed_message_len, pk) != 0) {
			printf("incorrect signature!\n");
	}

	printf("unsigned message: %s\n", unsigned_message);

return 0;
}
