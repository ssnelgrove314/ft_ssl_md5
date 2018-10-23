/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA256_H
# define SHA256_H

# include <stddef.h>
# include <stdint.h>
# include <stdlib.h>
# include <stdio.h>
# include <memory.h>

# define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
# define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
# define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
# define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
# define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
# define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
# define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
# define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

# define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

typedef	uint8_t		byte_t;             // 8-bit byte
typedef	uint32_t	word_t;             // 32-bit word, change to "long" for 16-bit machines
typedef	struct		sha256_ctx_s
{
					byte_t data[64];
					word_t datalen;
					unsigned long long bitlen;
					word_t state[8];
}					sha256_ctx_t;

typedef struct		sha256_transform_vars_s
{
	word_t			a;
	word_t			b;
	word_t			c;
	word_t			d;
	word_t			e;
	word_t			f;
	word_t			g;
	word_t			h;
	word_t			i;
	word_t			j;
	word_t			k;
	word_t			t1;
	word_t			t2;
	word_t			m[64];
}					sha256_transform_vars_t;

void				sha256_init(sha256_ctx_t *ctx);
void				sha256_update(sha256_ctx_t *ctx, const byte_t data[], size_t len);
void				sha256_final(sha256_ctx_t *ctx, byte_t hash[]);
static void				sha256_string(char *str);
static void				sha256_print(unsigned char digest[32]);

#endif