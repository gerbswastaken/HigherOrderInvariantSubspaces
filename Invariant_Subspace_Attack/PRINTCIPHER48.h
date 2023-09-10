#ifndef PRINTCIPHER48_H
#define PRINTCIPHER48

#include <iostream>
#include <bitset>

#include "Cipher.h"

class PrintCipher48 : public Cipher
{
	public:
		void init() override;		// Initialization for running PRINTCIPHER48
		void round_constant(void* data, int i) override;	// Adds i^th round constant to data
		void round_function(void* data) override;		//Performs PRINTCIPHER48 round function

		void print_state(void* data) override;

		// PrintCipher48 is a little weird since the S-Box is a 3 bit S-Box. Hence, we can't break
		// up the plaintext/ciphertext/key into uint8_t blocks. Instead, we'll take a single uint64_t
		// and just ignore the 16 MSBs. That should make it easier to deal with!
		void encrypt(uint64_t* plaintext, uint64_t* ciphertext, uint64_t* key, uint32_t* permutation_key, int rounds);

	private:

		void printcipher48_round(uint64_t* state, uint64_t* key, uint32_t* permutation_key, int current_round);

		// Each round of PRINTCIPHER48 consists of:
		// a Key-XORing step:
		void key_xor(uint64_t* state, uint64_t* key);
		// a Linear Diffusion step:
		void linear_permutation(uint64_t* state);
		// an adding Round Constants step:
		void add_round_constants(uint64_t* state, int current_round);
		// ... and finally a keyed s-box step:
		void keyed_sbox(uint64_t* state, uint32_t* permutation_key);


		// Again, the S-Box is only a 3-bit sbox, but uint8_t is the smallest bit size we can go.
		// 0 -> 0, 1 -> 1, 2 -> 3, 3 -> 6, 4 -> 7, 5 -> 4, 6 -> 5, 7 -> 2  
		// However, before applying the S-box, we actually permute the bits according to the perm_key
		// This permutation procedure takes 2 bits from the perm_key at a time and maps them to a 
		// 3-bit -> 3-bit permutation in the state:
		// 00 : c_2 c_1 c_0 -> c_2 c_1 c_0 (0->0, 1->1, 2->2, 3->3, 4->4, 5->5, 6->6, 7->7)
		// 01 : c_2 c_1 c_0 -> c_1 c_2 c_0 (0->0, 1->1, 2->4, 3->5, 4->2, 5->3, 6->6, 7->7)
		// 10 : c_2 c_0 c_1 -> c_2 c_1 c_0 (0->0, 1->2, 2->1, 3->3, 4->4, 5->6, 6->5, 7->7)
		// 11 : c_2 c_1 c_0 -> c_0 c_1 c_2 (0->0, 1->4, 2->2, 3->6, 4->1, 5->5, 6->3, 7->7)
		// 
		// Hence, we actually get effectively 4 s-boxes, and we apply the one corresponding to the 
		// 2-bits taken from the perm-key (for each of the corresponding sets of 3 bits in the state)
		// S_0: 0 -> 0, 1 -> 1, 2 -> 3, 3 -> 6, 4 -> 7, 5 -> 4, 6 -> 5, 7 -> 2
		// S_1: 0 -> 0, 1 -> 1, 2 -> 7, 3 -> 4, 4 -> 3, 5 -> 6, 6 -> 5, 7 -> 2
		// S_2: 0 -> 0, 1 -> 3, 2 -> 1, 3 -> 6, 4 -> 7, 5 -> 5, 6 -> 4, 7 -> 2
		// S_3: 0 -> 0, 1 -> 7, 2 -> 3, 3 -> 5, 4 -> 1, 5 -> 4, 6 -> 6, 7 -> 2
		
		uint8_t print_sbox[4][8] = {
			{ 0x00, 0x01, 0x03, 0x06, 0x07, 0x04, 0x05, 0x02 },
			{ 0x00, 0x01, 0x07, 0x04, 0x03, 0x06, 0x05, 0x02 },
			{ 0x00, 0x03, 0x01, 0x06, 0x07, 0x05, 0x04, 0x02 },
			{ 0x00, 0x07, 0x03, 0x05, 0x01, 0x04, 0x06, 0x02 }
		};

		// While we can calculate these in code, it's faster to look them up, since it's always the same
		uint8_t round_constants[48] =
		{
			0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3e, 0x3d, 0x3b, 
			0x37, 0x2f, 0x1e, 0x3c, 0x39, 0x33, 0x27, 0x0e,
			0x1d, 0x3a, 0x35, 0x2b, 0x16, 0x2c, 0x18, 0x30,
			0x21, 0x02, 0x05, 0x0b, 0x17, 0x2e, 0x1c, 0x38, 
			0x31, 0x23, 0x06, 0x0d, 0x1b, 0x36, 0x2d, 0x1a,
			0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04
		};



};

#endif
