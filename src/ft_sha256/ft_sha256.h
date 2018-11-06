#ifndef FT_SHA256_H
# define FT_SHA256_H

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

# define SHA256_BLOCK_SIZE 32

typedef	struct			sha256_ctx_s
{
						uint8_t data[64];
						uint32_t datalen;
						unsigned long long bitlen;
						uint32_t state[8];
}						sha256_ctx_t;

typedef struct			sha256_transform_vars_s
{
	uint32_t			a;
	uint32_t			b;
	uint32_t			c;
	uint32_t			d;
	uint32_t			e;
	uint32_t			f;
	uint32_t			g;
	uint32_t			h;
	uint32_t			i;
	uint32_t			j;
	uint32_t			k;
	uint32_t			t1;
	uint32_t			t2;
	uint32_t			m[64];
}						sha256_transform_vars_t;

void					sha256_init(sha256_ctx_t *ctx);
void					sha256_update(sha256_ctx_t *ctx, const uint8_t data[], size_t len);
void					sha256_final(sha256_ctx_t *ctx, uint8_t hash[]);
char					*sha256_string(char *str);
void					sha256_print(unsigned char digest[32]);

#endif