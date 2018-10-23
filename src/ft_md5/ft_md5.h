#ifndef FT_MD5_H
#define FT_MD5_H

# include <stdint.h>
# include <string.h>
# include <stdio.h>

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

#define GET_UINT32_LE(n, b, i)\
{ \
	(n) = ((uint32_t) (b)[(i)]) \
	| ((uint32_t)(b)[(i) + 1] << 8) \
	| ((uint32_t)(b)[(i) + 2] << 16) \
	| ((uint32_t)(b)[(i) + 3] << 24); \
}

#define PUT_UINT32_LE(n, b, i) \
{ \
	(b)[(i)] = (unsigned char)(((n)) & 0xFF); \
	(b)[(i) + 1] = (unsigned char)(((n) >> 8) & 0xFF); \
	(b)[(i) + 2] = (unsigned char)(((n) >> 16) & 0xFF); \
	(b)[(i) + 3] = (unsigned char)(((n) >> 24) & 0xFF); \
}

typedef struct		s_md5_ctx
{
	uint32_t			state[4];
	uint32_t			count[2];
	unsigned char buffer[64];
}					t_md5_ctx;

void md5_init(t_md5_ctx *ctx);
void md5_update(t_md5_ctx *ctx, unsigned char *something, unsigned int count);
void md5_final(unsigned char output[16], t_md5_ctx *ctx);

static void md5_transform(uint32_t state[4], unsigned char test[64]);
static void md5_encode(unsigned char *a, uint32_t *b, unsigned int c);
static void md5_decode(uint32_t *a, unsigned char *b, unsigned int c);
static void md5_memcpy(unsigned char *src, unsigned char *dst, unsigned int len);
static void md5_memset(unsigned char *ptr, int value, unsigned int len);
static void md5_print(unsigned char digest[16]);

#endif