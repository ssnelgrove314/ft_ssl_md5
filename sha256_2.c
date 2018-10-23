#include "sha256_2.h"

static const word_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_transform(sha256_ctx_t *ctx, const byte_t data[])
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
		vars.t1 = vars.h + EP1(vars.e) + CH(vars.e, vars.f, vars.g) + k[vars.i] + vars.m[vars.i];
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

void sha256_update(sha256_ctx_t *ctx, const byte_t data[], size_t len)
{
	word_t i;

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

void sha256_final(sha256_ctx_t *ctx, byte_t hash[])
{
	word_t i;

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

static void md5_string(char *str)
{
	sha256_ctx_t ctx;
	unsigned char digest[32];

	sha256_init(&ctx);
	sha256_update(&ctx, (byte_t *)str, strlen(str));
	sha256_final(&ctx, digest);
	printf("SHA256 (\"%s\") = ", str);
	sha256_print(digest);
	printf("\n");
}

static void sha256_print(unsigned char digest[32])
{
	unsigned int i;

	i = 0;
	while (i < 32)
	{
		printf("%02x", digest[i]);
		i++;
	}
}

int main(void)
{
	sha256_ctx_t ctx;
	byte_t test1[] = {"abc"};
	byte_t buff[SHA256_BLOCK_SIZE];

	sha256_init(&ctx);
	sha256_update(&ctx, test1, strlen((char *)test1));
	sha256_final(&ctx, buff);
	sha256_print(buff);
	return (0);
}