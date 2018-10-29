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

static uint32_t md5_constants[] =
{0xd76aa478,
0xe8c7b756,
0x242070db,
0xc1bdceee,
0xf57c0faf,
0x4787c62a,
0xa8304613,
0xfd469501,
0x698098d8,
0x8b44f7af,
0xffff5bb1,
0x895cd7be,
0x6b901122,
0xfd987193,
0xa679438e,
0x49b40821,
0xf61e2562,
0xc040b340,
0x265e5a51,
0xe9b6c7aa,
0xd62f105d,
 0x2441453,
0xd8a1e681,
0xe7d3fbc8,
0x21e1cde6,
0xc33707d6,
0xf4d50d87,
0x455a14ed,
0xa9e3e905,
0xfcefa3f8,
0x676f02d9,
0x8d2a4c8a,
0xfffa3942,
0x8771f681,
0x6d9d6122,
0xfde5380c,
0xa4beea44,
0x4bdecfa9,
0xf6bb4b60,
0xbebfbc70,
0x289b7ec6,
0xeaa127fa,
0xd4ef3085,
0x4881d05,
0xd9d4d039,
0xe6db99e5,
0x1fa27cf8,
0xc4ac5665,
0xf4292244,
0x432aff97,
0xab9423a7,
0xfc93a039,
0x655b59c3,
0x8f0ccc92,
0xffeff47d,
0x85845dd1,
0x6fa87e4f,
0xfe2ce6e0,
0xa3014314,
0x4e0811a1,
0xf7537e82,
0xbd3af235,
0x2ad7d2bb,
0xeb86d391,
};

enum e_fghi {
	MD5_F_FF,
	MD5_G_GG,
	MD5_H_HH,
	MD5_I_II,
};

typedef struct s_md5_ffgghhii_param
{
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t x[16];
	uint32_t s;
	uint32_t ac[16];
	char			ffgghhii_selector;
}					t_md5_ffgghhii_param;

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

static const uint32_t s_rounds[] = {
	7,
	12,
	17,
	22,
	5,
	9,
	14,
	20,
	4,
	11,
	16,
	23,
	6,
	10,
	15,
	21,
};

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