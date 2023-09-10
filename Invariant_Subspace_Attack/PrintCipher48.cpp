#include "PrintCipher48.h"

void PrintCipher48::init()
{
}

void PrintCipher48::round_constant(void* data, int i)
{
}

void PrintCipher48::round_function(void* data)
{
}

void PrintCipher48::print_state(void* data)
{
}

void PrintCipher48::encrypt(uint64_t* plaintext, uint64_t* ciphertext, uint64_t* key, uint32_t* permutation_key, int rounds)
{
	*ciphertext = *plaintext;
	for (int i = 0; i < rounds; ++i) {
		printcipher48_round(ciphertext, key, permutation_key, i);
		std::cout <<"Round "<<i<<": "<< std::hex << *ciphertext << '\n';
	}
}

void PrintCipher48::key_xor(uint64_t* state, uint64_t* key)
{
	*state ^= *key;
}

void PrintCipher48::linear_permutation(uint64_t* state)
{
	uint64_t final_state = 0x0000000000000000;
	for (int i = 0; i < (48 - 1); ++i) {
		int temp_index = ((3 * i) % 47);
		uint64_t temp_bit = (((static_cast<uint64_t>(0x0000000000000001) << i) & (*state)) >> i);
		/*
		Technically it should be like this:
		if (temp_bit == 1) {
			final_state = final_state | (temp_bit << temp_index);
		}
		But we don't actually have to run this check! If temp_bit = 0, since our final_state = 0x00000000
		the position ((3 * i) % 47)^th position of final_state is already 0. If temp_bit = 1, then we
		need to change it; this can be done by an OR mask. ORing with all 0s is equivalent to doing nothing.
		Also the i -> ((3 * i) % 47) mapping is one-one, so each i will map to a unique ((3 * i) % 47).

		NO NEED TO RUN THIS CHECK, WE CAN PROCEED WITH A DIRECT | with a mask.
		*/
		final_state = final_state | (temp_bit << temp_index);
	}
	final_state = final_state | (static_cast<uint64_t>(0x0000800000000000) & (*state));
	*state = final_state;
}

void PrintCipher48::add_round_constants(uint64_t* state, int current_round)
{
	uint64_t temp = (static_cast<uint64_t>(0x000000000000003f) & (*state)) ^ (static_cast<uint64_t>(round_constants[current_round]));
	*state = (*state) & static_cast<uint64_t>(0xffffffffffffffc0) | temp;
}

void PrintCipher48::keyed_sbox(uint64_t* state, uint32_t* permutation_key)
{
	//std::cout << std::bitset<64>(*state) << " " << *permutation_key << '\n';
	// 
	// Now, we need to read the permutation_key 2 bits at a time to determine which s_box to use
	for (int i = 0; i < 16; ++i) {	// permutation_key is 32 bits, ie 16 sets of 2 bits

		//std::cout << "Round " << i << '\n';

		uint32_t mask_sbox = (0x00000003 << (2 * i)); // Mask for the required bits in permutation_key
		mask_sbox = (mask_sbox & *permutation_key) >> (2 * i); // Grabs the required 2 bits and brings them back to LSB
		// Now that we have the 2 bits, we can use this to determine which sbox to use
		uint64_t mask_state = (static_cast<uint64_t>(0x0000000000000007) << (3 * i)); // Mask for the corresponding bits in state
		
		//std::cout << std::bitset<64>(mask_state) << '\n';
		
		uint64_t sbox_value = ((mask_state & *state) >> (3 * i)); // Grabs the required 3 bits and brings them back to LSB
		
		//std::cout << mask_sbox << " " << sbox_value << '\n';
		
		sbox_value = (uint64_t)print_sbox[(int)mask_sbox][(int)sbox_value]; // We now have the output of the correct sbox in sbox_value
		*state = (*state & (~mask_state)); // Clear the bits in that section so we can replace them!
		*state = (*state ^ (sbox_value << (3 * i))); // Copy the bits into state
	}
}

void PrintCipher48::printcipher48_round(uint64_t* state, uint64_t* key, uint32_t* permutation_key, int current_round)
{
	key_xor(state, key);
	linear_permutation(state);
	add_round_constants(state, current_round);
	keyed_sbox(state, permutation_key);
}