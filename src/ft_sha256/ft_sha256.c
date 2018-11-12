#include "../ft_ssl/ft_ssl.h"
#include "ft_sha256_constants.h"

void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[])
{
	sha256_transform_vars_t vars;

	vars.i = 0;
	vars.j = 0;
	while (vars.i < 16)
	{
		vars.m[vars.i] = (data[vars.j] << 24) | (data[vars.j + 1] << 16) | (data[vars.j + 2] << 8) | (data[vars.j + 3]);
		++vars.i;
		vars.j += 4;
	}
	while (vars.i < 64)
	{
		vars.m[vars.i] = SIG1(vars.m[vars.i - 2]) + vars.m[vars.i - 7] + SIG0(vars.m[vars.i - 15]) + vars.m[vars.i - 16];
		++vars.i;
	}
	vars.a = ctx->state[0];
	vars.b = ctx->state[1];
	vars.c = ctx->state[2];
	vars.d = ctx->state[3];
	vars.e = ctx->state[4];
	vars.f = ctx->state[5];
	vars.g = ctx->state[6];
	vars.h = ctx->state[7];
	vars.i = 0;
	while (vars.i < 64)
	{
		vars.t1 = vars.h + EP1(vars.e) + CH(vars.e, vars.f, vars.g) + g_k_values[vars.i] + vars.m[vars.i];
		vars.t2 = EP0(vars.a) + MAJ(vars.a, vars.b, vars.c);
		vars.h = vars.g;
		vars.g = vars.f;
		vars.f = vars.e;
		vars.e = vars.d + vars.t1;
		vars.d = vars.c;
		vars.c = vars.b;
		vars.b = vars.a;
		vars.a = vars.t1 + vars.t2;
		++vars.i;
	}
	ctx->state[0] += vars.a;
	ctx->state[1] += vars.b;
	ctx->state[2] += vars.c;
	ctx->state[3] += vars.d;
	ctx->state[4] += vars.e;
	ctx->state[5] += vars.f;
	ctx->state[6] += vars.g;
	ctx->state[7] += vars.h;
}

void sha256_init(sha256_ctx_t *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t data[], size_t len)
{
	uint32_t i;

	i = 0;
	while (i < len)
	{
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64)
		{
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
		++i;
	}
}

void sha256_final(sha256_ctx_t *ctx, uint8_t hash[])
{
	uint32_t i;

	i = ctx->datalen;
	if (ctx->datalen < 56)
	{
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else
	{
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);
	i = 0;
	while (i < 4)
	{
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
		++i;
	}
}

char *sha256_digest_tochar(unsigned char digest[32])
{
	t_vector test;
	char *output;
	char buf[3];
	int i;

	output = NULL;
	ft_vector_init(&test, 33);
	i = 0;
	while (i < 32)
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

void sha256_handler(void *in)
{
	sha256_ctx_t ctx;
	unsigned char digest[32];
	unsigned char filebuf[512];
	int fd;
	int ret;
	t_ft_ssl_input *input;

	input = (t_ft_ssl_input *)in;
	if (input->input_type == SSL_INPUT_STRING || input->input_type == SSL_INPUT_STDIN)
	{
		input->digest = sha256_string(input->input);
		return ;
	}
	else if ((fd = ft_fopen(input->filename, "r")) == -1)
		ft_ssl_error(ft_strjoin(input->filename, " is an invalid file"));
	sha256_init(&ctx);
	while((ret = read(fd, filebuf, 512)))
		sha256_update(&ctx, (unsigned char *)filebuf, ret);
	sha256_final(&ctx, digest);
	input->digest = sha256_digest_tochar(digest);
}

char *sha256_string(char *str)
{
	sha256_ctx_t ctx;
	unsigned char digest[32];
	char *final;

	sha256_init(&ctx);
	sha256_update(&ctx, (uint8_t *)str, ft_strlen(str));
	sha256_final(&ctx, digest);
	final = sha256_digest_tochar(digest);
	return (final);
}

void sha256_print(unsigned char digest[32])
{
	unsigned int i;

	i = -1;
	while (++i < SHA256_BLOCK_SIZE)
		printf("%02x", digest[i]);
}