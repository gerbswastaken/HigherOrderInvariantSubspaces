#include <iostream>
#include <bitset>

#include <stdint.h>


#include "Zorro.h"
#include "PrintCipher48.h"

void print(uint8_t arr[4][4]) {
	std::cout << "At " << std::hex << arr << ": ";
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			std::cout << std::hex << (int)arr[i][j] << " ";
		}
	}
	std::cout << '\n';
}

int main() {
	std::cout << "Hello World!"<<'\n';

	uint8_t in_plaintext[4][4] = {
		{0xe7, 0xb2, 0x9d, 0xea},
		{0xb4, 0xc0, 0xf4, 0x0c},
		{0xb4, 0xf1, 0x70, 0xd3},
		{0xa1, 0x5e, 0x9f, 0x36}
	};

	uint8_t in_ciphertext[4][4] = {
		{0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00}
	};

	uint8_t in_key[4][4] = {
		{0xeb, 0x01, 0xff, 0xaf},
		{0x14, 0xac, 0xd0, 0xea},
		{0x69, 0x98, 0xe5, 0xea},
		{0x6e, 0x67, 0x37, 0x7d}
	};

	Zorro* zorro_test = new Zorro;
	zorro_test->encrypt(in_plaintext, in_ciphertext, in_key, 6);

	std::cout << "Plaintext: ";
	print(in_plaintext);
	std::cout << "Key: ";
	print(in_key);
	std::cout << "Ciphertext: ";
	print(in_ciphertext);

	std::cout << "PRINTCIPHER48 TIME:\n";


	uint64_t* plaintext_test = new uint64_t;
	*plaintext_test = 0x00004c847555c35b;
	uint64_t* key_test = new uint64_t;
	*key_test = 0x0000c28895ba327b;
	uint32_t* permutation_key_test = new uint32_t;
	*permutation_key_test = 0x69d2cdb6;
	uint64_t* ciphertext_test = new uint64_t;
	*ciphertext_test = 0x0000000000000000;

	PrintCipher48* print_test = new PrintCipher48;
	print_test->encrypt(plaintext_test, ciphertext_test, key_test, permutation_key_test, 48);

	return 0;
}