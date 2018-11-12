#ifndef FT_MD5_H
#define FT_MD5_H

# include <stdint.h>
# include <string.h>
# include <stdio.h>

# define MD5_BLOCK_SIZE 16

# define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

typedef struct			s_md5_ffgghhii_param
{
	uint32_t			a;
	uint32_t			b;
	uint32_t			c;
	uint32_t			d;
	uint32_t			x[MD5_BLOCK_SIZE];
	uint32_t			s[4];
	uint32_t			ac[4];
	short				sub_block[4];
	char				ffgghhii_selector;
}						t_md5_ffgghhii_param;

typedef struct			s_md5_ctx
{
	uint32_t			state[4];
	uint32_t			count[2];
	unsigned char 		buffer[64];
}						t_md5_ctx;

void					md5_rounds(t_md5_ffgghhii_param *p, int *i);
void					md5_ffgghhii(t_md5_ffgghhii_param *p);
uint32_t				md5_fghi(uint32_t x, uint32_t y, uint32_t z, char fghi);
void					md5_init(t_md5_ctx *ctx);
void					md5_update(t_md5_ctx *ctx, unsigned char *something, unsigned int count);
void					md5_final(unsigned char output[MD5_BLOCK_SIZE], t_md5_ctx *ctx);
void					md5_transform(uint32_t state[4], unsigned char test[64]);
void					md5_encode(unsigned char *a, uint32_t *b, unsigned int c);
void					md5_decode(uint32_t *a, unsigned char *b, unsigned int c);
void					md5_memcpy(unsigned char *src, unsigned char *dst, unsigned int len);
void					md5_memset(unsigned char *ptr, int value, unsigned int len);
void					md5_print(unsigned char digest[MD5_BLOCK_SIZE]);
char					*md5_string(char *str);
void					md5_handler(void *in);

#endif