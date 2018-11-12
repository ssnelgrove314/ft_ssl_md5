#include "../ft_ssl/ft_ssl.h"
#include "ft_md5_constants.h"

uint32_t md5_fghi(uint32_t x, uint32_t y, uint32_t z, char fghi)
{
	if (fghi == MD5_F_FF)
		return (((x) & (y)) | ((~x) & (z)));
	if (fghi == MD5_G_GG)
		return (((x) & (z)) | ((y) & (~z)));
	if (fghi == MD5_H_HH)
		return (((x) ^ (y) ^ (z)));
	if (fghi == MD5_I_II)
		return (((y) ^ ((x) | (~z))));
	return (0);
}

void md5_ffgghhii(t_md5_ffgghhii_param *p)
{
	p->a = p->a + (md5_fghi(p->b, p->c, p->d, p->ffgghhii_selector) + p->x[p->sub_block[0]] + p->ac[0]);
	p->a = ROTATE_LEFT((p->a), (p->s[0]));
	p->a += p->b;
	p->d = p->d + (md5_fghi(p->a, p->b, p->c, p->ffgghhii_selector) + p->x[p->sub_block[1]] + p->ac[1]);
	p->d = ROTATE_LEFT((p->d), (p->s[1]));
	p->d += p->a;
	p->c = p->c + (md5_fghi(p->d, p->a, p->b, p->ffgghhii_selector) + p->x[p->sub_block[2]] + p->ac[2]);
	p->c = ROTATE_LEFT((p->c), (p->s[2]));
	p->c += p->d;
	p->b = p->b + (md5_fghi(p->c, p->d, p->a, p->ffgghhii_selector) + p->x[p->sub_block[3]] + p->ac[3]);
	p->b = ROTATE_LEFT((p->b), (p->s[3]));
	p->b += p->c;
}

void md5_rounds(t_md5_ffgghhii_param *p, int *i)
{
	int j;

	j = -1;
	while (++j < 4)
	{
		p->ffgghhii_selector = g_md5_rounds[*i][0].fghi;
		p->s[0] = g_md5_rounds[*i][j * 4].step;
		p->s[1] = g_md5_rounds[*i][j * 4 + 1].step;
		p->s[2] = g_md5_rounds[*i][j * 4 + 2].step;
		p->s[3] = g_md5_rounds[*i][j * 4 + 3].step;
		p->ac[0] = g_md5_rounds[*i][j * 4].signed_constant;
		p->ac[1] = g_md5_rounds[*i][j * 4 + 1].signed_constant;
		p->ac[2] = g_md5_rounds[*i][j * 4 + 2].signed_constant;
		p->ac[3] = g_md5_rounds[*i][j * 4 + 3].signed_constant;
		p->sub_block[0] = g_md5_rounds[*i][j * 4].sub_block;
		p->sub_block[1] = g_md5_rounds[*i][j * 4 + 1].sub_block;
		p->sub_block[2] = g_md5_rounds[*i][j * 4 + 2].sub_block;
		p->sub_block[3] = g_md5_rounds[*i][j * 4 + 3].sub_block;
		md5_ffgghhii(p);
	}
}

void md5_init(t_md5_ctx *ctx)
{
	ctx->count[0] = 0;
	ctx->count[1] = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

void md5_update(t_md5_ctx *ctx, unsigned char *input, unsigned int input_len)
{
	unsigned int i;
	unsigned int index;
	unsigned int part_len;

	index = (unsigned int)((ctx->count[0] >> 3) & 0x3F);
	if ((ctx->count[0] += ((uint32_t)input_len << 3)) < ((uint32_t)input_len << 3))
		ctx->count[1]++;
	ctx->count[1] += ((uint32_t)input_len >> 29);
	part_len = 64 - index;
	if (input_len >= part_len)
	{
		md5_memcpy(&ctx->buffer[index], input, part_len);
		md5_transform(ctx->state, ctx->buffer);
		i = part_len;
		while (i + 63 < input_len)
		{
			md5_transform(ctx->state, &input[i]);
			i += 64;
		}
		index = 0;
	}
	else
		i = 0;
	md5_memcpy(&ctx->buffer[index], &input[i], input_len - i);
}

void md5_final(unsigned char output[16], t_md5_ctx *ctx)
{
	unsigned char bits[8];
	unsigned int index;
	unsigned int pad_len;

	md5_encode(bits, ctx->count, 8);
	index = (unsigned int)((ctx->count[0] >> 3) & 0x3F);
	pad_len = (index < 56) ? (56 - index) : (120 - index);
	md5_update(ctx, g_md5_padding, pad_len);
	md5_update(ctx, bits, 8);
	md5_encode(output, ctx->state, 16);
	md5_memset((unsigned char *)ctx, 0, sizeof(*ctx));
}

void md5_transform(uint32_t state[4], unsigned char block[64])
{
	t_md5_ffgghhii_param par;
	int i;
	
	i = -1;
	par.a = state[0];
	par.b = state[1];
	par.c = state[2];
	par.d = state[3];
	md5_decode(par.x, block, 64);
	while (++i < 4)
		md5_rounds(&par, &i);
	state[0] += par.a;
	state[1] += par.b;
	state[2] += par.c;
	state[3] += par.d;
	md5_memset((unsigned char *)par.x, 0, sizeof(par.x));
}

void md5_encode(unsigned char *output, uint32_t *input, unsigned int len)
{
	unsigned int i;
	unsigned int j;

	i = 0;
	j = 0;
	while (j < len)
	{
		output[j] = (unsigned char)(input[i] & 0xff);
		output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
		j += 4;
		i++;
	}
}

void md5_decode(uint32_t *output, unsigned char *input, unsigned int len)
{
	unsigned int i;
	unsigned int j;

	i = 0;
	j = 0;
	while (j < len)
	{
		output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) | (((uint32_t)input[j + 2]) << 16) | (((uint32_t)input[j + 3]) << 24);
		i++;
		j+=4;
	}
}

void md5_memcpy(unsigned char *output, unsigned char *input, unsigned int len)
{
	unsigned int i;

	i = 0;
	while (i < len)
	{
		output[i] = input[i];
		i++;
	}
}

void md5_memset(unsigned char *output, int value, unsigned int len)
{
	unsigned int i;

	i = 0;
	while (i < len)
	{
		((char *)output)[i] = (char)value;
		i++;
	}
}

char *md5_digest_tochar(unsigned char digest[16])
{
	t_vector test;
	char *output;
	char buf[3];
	int i;

	output = NULL;
	ft_vector_init(&test, 32);
	i = 0;
	while (i < 16)
	{
		sprintf(buf, "%02x", digest[i]);
		ft_vector_append(&test, (char *)buf);
		i++;
	}
	ft_vector_nappend(&test, "\0", 1);
	output = ft_strdup(test.data);
	ft_vector_free(&test);
	return (output);
}

char *md5_string(char *str)
{
	t_md5_ctx ctx;
	unsigned char digest[16];

	md5_init(&ctx);
	md5_update(&ctx, (unsigned char *)str, ft_strlen(str));
	md5_final(digest, &ctx);
	return (md5_digest_tochar(digest));
}

void md5_handler(void *in)
{
	t_md5_ctx ctx;
	unsigned char digest[16];
	unsigned char filebuf[512];
	int fd;
	int ret;
	t_ft_ssl_input *input;

	input = (t_ft_ssl_input *)in;
	if (input->input_type == SSL_INPUT_STRING || input->input_type == SSL_INPUT_STDIN)
	{
		input->digest = md5_string(input->input);
		return ;
	}
	else if ((fd = ft_fopen(input->filename, "r")) == -1)
		ft_ssl_error(ft_strjoin(input->filename, " is an invalid file"));
	md5_init(&ctx);
	while((ret = read(fd, filebuf, 512)))
		md5_update(&ctx, (unsigned char *)filebuf, ret);
	md5_final(digest, &ctx);
	input->digest = md5_digest_tochar(digest);
}

void md5_print(unsigned char digest[16])
{
	int i;

	i = -1;
	while (++i < MD5_BLOCK_SIZE)
		printf("%02x", digest[i]);
}