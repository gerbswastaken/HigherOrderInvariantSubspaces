#ifndef CIPHER_H
#define CIPHER_H

class Cipher
{
	public:
		// Some public parameters that all ciphers will have:
		int state_size;		// The size of the state of the cipher, in bits
		int num_round_constants;		// The number of round constants that will be added

		virtual void init() = 0;		// If any initialization is required for running the cipher
		virtual void round_constant(void* data, int i) = 0;		//Adds i^th round constant to data
		virtual void round_function(void* data) = 0;		//performs one round function on the data

		virtual void print_state(void* data) = 0;
};

#endif
