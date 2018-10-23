#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
# define SHA256_HASH_SIZE 32
# define SHA256_HASH_SIZE_BITS 256
# define SHA256_MESSAGE_BLOCK_SIZE 64

typedef enum sha_constants_s
{
	sha_success = 0,
	sha_null,
	sha_input_too_long,
	sha_state_error,
	sha_bad_param
}	sha_constants_e;

typedef struct sha256_ctx_s
{
	uint32_t inter_hash[SHA256_HASH_SIZE / 4];
	uint32_t length_low;
	uint32_t length_high;
	int_least16_t message_block_index;
	uint8_t message_block[SHA256_MESSAGE_BLOCK_SIZE];
	int computed;
	int corrupted;
} sha256_ctx_t;

# define SHA256_SHR(bits, word) ((word) >> (bits))
# define SHA256_ROTL(bits, word) (((word) << (bits) | ((word) << (32 - (bits)))))
# define SHA256_ROTR(bits, word) (((word) >> (bits)) | ((word) << (32 - (bits))))
#define SHA256_SIGMA0(word) (SHA256_ROTR( 2,word) ^ SHA256_ROTR(13,word) ^ SHA256_ROTR(22,word))
#define SHA256_SIGMA1(word) (SHA256_ROTR( 6,word) ^ SHA256_ROTR(11,word) ^ SHA256_ROTR(25,word))
#define SHA256_sigma0(word) (SHA256_ROTR( 7,word) ^ SHA256_ROTR(18,word) ^ SHA256_SHR( 3,word))
#define SHA256_sigma1(word) (SHA256_ROTR(17,word) ^ SHA256_ROTR(19,word) ^ SHA256_SHR(10,word))

static uint32_t add_temp;
#define SHA256_ADD_LENGTH(ctx, length) \
	(add_temp = (ctx)->length_low, (ctx)->corrupted = \
	(((ctx)->length_low += (length)) < add_temp) && \
	(++(ctx)->length_high == 0) ? 1 : 0)

static void SHA256_finalize(sha256_ctx_t *context, uint8_t Pad_Byte);
static void SHA256_pad_message(sha256_ctx_t *context, uint8_t Pad_Byte);
static void SHA256_process_message_block(sha256_ctx_t *context);
static int SHA256_reset(sha256_ctx_t *context, uint32_t *H0);
static int SHA256_result_n(sha256_ctx_t *context, uint8_t Message_Digest[], int HashSize);
static uint32_t SHA256_H0[SHA256_HASH_SIZE / 4] = {
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

int SHA256_input(sha256_ctx_t *, const uint8_t *bytes, unsigned int bytecount);
int SHA256_final_bits(sha256_ctx_t *, const uint8_t bits, unsigned int bitcount);
int SHA256_result(sha256_ctx_t *, uint8_t Message_Digest[SHA256_HASH_SIZE]);
#endif