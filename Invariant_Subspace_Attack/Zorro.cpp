#include "Zorro.h"

void Zorro::init()
{
	// No initialization required!
}

void Zorro::round_constant(void* data, int i)
{
	uint8_t state[4][4] = {};
	AC(state, i + 1);
	memcpy(data, state, 16);
}

void Zorro::round_function(void* data)
{
	uint8_t(*state)[4] = (uint8_t(*)[4]) data;		// Converting data[16] into data[4][4]
	SR(state);
	MC(state);
	SB(state);
}

void Zorro::print_state(void* data)
{
	uint8_t state[4][4];
	memcpy(state, data, 16);
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			std::cout << std::hex << data << "\t" << state[i][j] << '\n';
		}
	}
}

void Zorro::encrypt(uint8_t plaintext[4][4], uint8_t ciphertext[4][4], uint8_t key[4][4], int rounds)
{
	// Here steps and rounds are used interchangably; most ciphers proceed in rounds, while zorro splits
	// up rounds into steps.

	// Copying the plaintext into the ciphertext
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			ciphertext[i][j] = plaintext[i][j];
		}
	}
		
	// Applying the key to the ciphertext before beginning the cipher operation
	AK(ciphertext, key);

	// Performing the Zorro steps
	for (int i = 0; i < rounds; ++i) {
		zorro_step(ciphertext, key, (4 * i));
	}
}

void Zorro::zorro_step(uint8_t state[4][4], uint8_t key[4][4], int round)
{
	zorro_round(state, round);
	zorro_round(state, round + 1);
	zorro_round(state, round + 2);
	zorro_round(state, round + 3);
	AK(state, key);
}

void Zorro::zorro_round(uint8_t state[4][4], int round)
{
	SB(state);
	AC(state, round + 1);
	SR(state);
	MC(state);
}

void Zorro::SB(uint8_t state[4][4])
{
	for (int i = 0; i < 4; ++i) {
		state[0][i] = zorro_sbox[state[0][i]];
	}
}

void Zorro::AC(uint8_t state[4][4], int round)
{
	state[0][0] ^= round;
	state[0][1] ^= round;
	state[0][2] ^= round;
	state[0][3] ^= round << 3;
}

void Zorro::SR(uint8_t state[4][4])
{
	uint8_t temp;
	temp = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = temp;
	temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
	temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
	temp = state[3][0]; state[3][0] = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = temp;
}

void Zorro::MC(uint8_t state[4][4])
{
	uint8_t c[4];

	c[0] = state[0][0]; c[1] = state[1][0]; c[2] = state[2][0]; c[3] = state[3][0];
	state[0][0] = GF_mul2[c[0]]; state[0][0] ^= GF_mul3[c[1]]; state[0][0] ^= c[2]; state[0][0] ^= c[3];
	state[1][0] = c[0]; state[1][0] ^= GF_mul2[c[1]]; state[1][0] ^= GF_mul3[c[2]]; state[1][0] ^= c[3];
	state[2][0] = c[0]; state[2][0] ^= c[1]; state[2][0] ^= GF_mul2[c[2]]; state[2][0] ^= GF_mul3[c[3]];
	state[3][0] = GF_mul3[c[0]]; state[3][0] ^= c[1]; state[3][0] ^= c[2]; state[3][0] ^= GF_mul2[c[3]];

	c[0] = state[0][1]; c[1] = state[1][1]; c[2] = state[2][1]; c[3] = state[3][1];
	state[0][1] = GF_mul2[c[0]]; state[0][1] ^= GF_mul3[c[1]]; state[0][1] ^= c[2]; state[0][1] ^= c[3];
	state[1][1] = c[0]; state[1][1] ^= GF_mul2[c[1]]; state[1][1] ^= GF_mul3[c[2]]; state[1][1] ^= c[3];
	state[2][1] = c[0]; state[2][1] ^= c[1]; state[2][1] ^= GF_mul2[c[2]]; state[2][1] ^= GF_mul3[c[3]];
	state[3][1] = GF_mul3[c[0]]; state[3][1] ^= c[1]; state[3][1] ^= c[2]; state[3][1] ^= GF_mul2[c[3]];

	c[0] = state[0][2]; c[1] = state[1][2]; c[2] = state[2][2]; c[3] = state[3][2];
	state[0][2] = GF_mul2[c[0]]; state[0][2] ^= GF_mul3[c[1]]; state[0][2] ^= c[2]; state[0][2] ^= c[3];
	state[1][2] = c[0]; state[1][2] ^= GF_mul2[c[1]]; state[1][2] ^= GF_mul3[c[2]]; state[1][2] ^= c[3];
	state[2][2] = c[0]; state[2][2] ^= c[1]; state[2][2] ^= GF_mul2[c[2]]; state[2][2] ^= GF_mul3[c[3]];
	state[3][2] = GF_mul3[c[0]]; state[3][2] ^= c[1]; state[3][2] ^= c[2]; state[3][2] ^= GF_mul2[c[3]];

	c[0] = state[0][3]; c[1] = state[1][3]; c[2] = state[2][3]; c[3] = state[3][3];
	state[0][3] = GF_mul2[c[0]]; state[0][3] ^= GF_mul3[c[1]]; state[0][3] ^= c[2]; state[0][3] ^= c[3];
	state[1][3] = c[0]; state[1][3] ^= GF_mul2[c[1]]; state[1][3] ^= GF_mul3[c[2]]; state[1][3] ^= c[3];
	state[2][3] = c[0]; state[2][3] ^= c[1]; state[2][3] ^= GF_mul2[c[2]]; state[2][3] ^= GF_mul3[c[3]];
	state[3][3] = GF_mul3[c[0]]; state[3][3] ^= c[1]; state[3][3] ^= c[2]; state[3][3] ^= GF_mul2[c[3]];
}

void Zorro::AK(uint8_t state[4][4], uint8_t key[4][4])
{
	for (int i = 0; i < 4; ++i) {
		for (int j = 0; j < 4; ++j) {
			state[i][j] ^= key[i][j];
		}
	}
}

