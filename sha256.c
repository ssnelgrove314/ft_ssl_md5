#include "sha256.h"

int	SHA256_input(sha256_ctx_t *context, const uint8_t *message_array, unsigned int length)
{
	if (!length)
		return sha_success;
	if (!context || !message_array)
		return sha_null;
	if (context->computed)
	{
		context->corrupted = sha_state_error;
		return (sha_state_error);
	}
	if (context->corrupted)
		return (context->corrupted);
	while (length-- && !context->corrupted)
	{
		context->message_block[context->message_block_index++] = (*message_array & 0xFF);
		if (!SHA256_ADD_LENGTH(context, 8) && (context->message_block_index == SHA256_MESSAGE_BLOCK_SIZE))
			SHA256_process_message_block(context);
		message_array++;
	}
	return (sha_success);
}

int SHA256_final_bits(sha256_ctx_t *context, const uint8_t message_bits, unsigned int length)
{
	uint8_t masks[8] = {
      /* 0 0b00000000 */ 0x00, /* 1 0b10000000 */ 0x80,
      /* 2 0b11000000 */ 0xC0, /* 3 0b11100000 */ 0xE0,
      /* 4 0b11110000 */ 0xF0, /* 5 0b11111000 */ 0xF8,
      /* 6 0b11111100 */ 0xFC, /* 7 0b11111110 */ 0xFE
};
	uint8_t markbit[8] = {
      /* 0 0b10000000 */ 0x80, /* 1 0b01000000 */ 0x40,
      /* 2 0b00100000 */ 0x20, /* 3 0b00010000 */ 0x10,
      /* 4 0b00001000 */ 0x08, /* 5 0b00000100 */ 0x04,
      /* 6 0b00000010 */ 0x02, /* 7 0b00000001 */ 0x01
};
	if (!length)
		return (sha_success);
	if (!context)
		return (sha_null);
	if ((context->computed) || (length >= 8) || (length == 0))
	{
		context->corrupted = sha_state_error;
		return (sha_state_error);
	}
	if (context->corrupted)
		return (context->corrupted);
	SHA256_ADD_LENGTH(context, length);
	SHA256_finalize(context, (uint8_t)((message_bits & masks[length]) | markbit[length]));
	return (sha_success);
}

int SHA256_result(sha256_ctx_t *context, uint8_t Message_Digest[])
{
	return SHA256_result_n(context, Message_Digest, SHA256_HASH_SIZE);
}

static void SHA256_finalize(sha256_ctx_t *context, uint8_t Pad_Byte)
{
	int i;

	SHA256_pad_message(context, Pad_Byte);
	i = 0;
	while (i < SHA256_MESSAGE_BLOCK_SIZE)
	{
		context->message_block[i] = 0;
		i++; //NOTE THIS MAY NEED TO GO ABOVE THE PREVIOUS LINE
	}
	context->length_low = 0;  /* and clear length */
	context->length_high = 0;
	context->computed = 1;
}

static void SHA256_pad_message(sha256_ctx_t *context, uint8_t Pad_Byte)
{
	if (context->message_block_index >= (SHA256_MESSAGE_BLOCK_SIZE - 8))
	{
		context->message_block[context->message_block_index++] = Pad_Byte;
		while (context->message_block_index < SHA256_MESSAGE_BLOCK_SIZE)
			context->message_block[context->message_block_index++] = 0;
		SHA256_process_message_block(context);
	}
	else
		context->message_block[context->message_block_index++] = Pad_Byte;
	while (context->message_block_index < (SHA256_MESSAGE_BLOCK_SIZE - 8))
		context->message_block[context->message_block_index++] = 0;
	context->message_block[56] = (uint8_t)(context->length_high >> 24);
	context->message_block[57] = (uint8_t)(context->length_high >> 16);
	context->message_block[58] = (uint8_t)(context->length_high >> 8);
	context->message_block[59] = (uint8_t)(context->length_high);
	context->message_block[60] = (uint8_t)(context->length_low >> 24);
	context->message_block[61] = (uint8_t)(context->length_low >> 16);
	context->message_block[62] = (uint8_t)(context->length_low >> 8);
	context->message_block[63] = (uint8_t)(context->length_low);
	SHA256_process_message_block(context);
}

static void SHA256_process_message_block(sha256_ctx_t *context)
{
	static const uint32_t K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
		0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
		0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
		0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
		0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
		0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
		0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
		0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
		0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
		0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
	int        t, t4;                   /* Loop counter */
	uint32_t   temp1, temp2;            /* Temporary word value */
	uint32_t   W[64];                   /* Word sequence */
	uint32_t   A, B, C, D, E, F, G, H;  /* Word buffers */

	t = 0;
	t4 = 0;
	while (t < 16)
	{
		W[t] = (((uint32_t)context->message_block[t4]) << 24) | 
			(((uint32_t)context->message_block[t4 + 1]) << 16) |
			(((uint32_t)context->message_block[t4 + 2]) << 8) |
			(((uint32_t)context->message_block[t4 + 3]));
		t4 += 4;
		t++;
	}
	t = 16;
	while (t < 64)
	{
		W[t] = SHA256_sigma1(W[t-2]) + W[t-7] + SHA256_sigma0(W[t-15]) + W[t-16];
		t++;
	}
	A = context->inter_hash[0];
	B = context->inter_hash[1];
	C = context->inter_hash[2];
	D = context->inter_hash[3];
	E = context->inter_hash[4];
	F = context->inter_hash[5];
	G = context->inter_hash[6];
	H = context->inter_hash[7];
	t = 0;
	while (t < 64)
	{
		temp1 = H + SHA256_SIGMA1(E) + SHA_Ch(E,F,G) + K[t] + W[t];
		temp2 = SHA256_SIGMA0(A) + SHA_Maj(A,B,C);
		H = G;
		G = F;
		F = E;
		E = D + temp1;
		D = C;
		C = B;
		B = A;
		A = temp1 + temp2;
		t++;
	}
	context->inter_hash[0] += A;
	context->inter_hash[1] += B;
	context->inter_hash[2] += C;
	context->inter_hash[3] += D;
	context->inter_hash[4] += E;
	context->inter_hash[5] += F;
	context->inter_hash[6] += G;
	context->inter_hash[7] += H;
	context->message_block_index = 0;
}

static int SHA256_reset(sha256_ctx_t *context, uint32_t *H0)
{
	if (!context)
		return (sha_null);
	context->length_low           = 0;
	context->length_high          = 0;
	context->message_block_index  = 0;
	context->inter_hash[0] = H0[0];
	context->inter_hash[1] = H0[1];
	context->inter_hash[2] = H0[2];
	context->inter_hash[3] = H0[3];
	context->inter_hash[4] = H0[4];
	context->inter_hash[5] = H0[5];
	context->inter_hash[6] = H0[6];
	context->inter_hash[7] = H0[7];
	context->computed  = 0;
	context->corrupted = 0;
	return (sha_success);
}

static int SHA256_result_n(sha256_ctx_t *context, uint8_t Message_Digest[], int HashSize)
{
	int i;

	if (!context || !Message_Digest)
		return (sha_null);
	if (context->corrupted)
		return context->corrupted;
	if (!context->computed)
		SHA256_finalize(context, 0x80);
	i = 0;
	while (i < HashSize)
	{
		Message_Digest[i] = (uint8_t)(context->inter_hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) ));
		i++;
	}
	return (sha_success);
}