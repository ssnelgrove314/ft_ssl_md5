/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_sha256.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssnelgro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 18:37:11 by ssnelgro          #+#    #+#             */
/*   Updated: 2018/11/12 18:37:13 by ssnelgro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_ssl/ft_ssl.h"

void							sha256_init(t_sha256_ctx *ctx)
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

char							*sha256_digest_tochar(unsigned char digest[32])
{
	t_vector					test;
	char						*output;
	char						buf[3];
	int							i;

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

void							sha256_handler(void *in)
{
	t_sha256_ctx				ctx;
	unsigned char				digest[32];
	unsigned char				filebuf[512];
	int							canthavesix[2];
	t_ft_ssl_input				*input;

	input = (t_ft_ssl_input *)in;
	if (input->input_type == SSL_INPUT_STRING ||\
		input->input_type == SSL_INPUT_STDIN)
	{
		input->digest = sha256_string(input->input);
		return ;
	}
	else if ((canthavesix[0] = ft_fopen(input->filename, "r")) == -1)
		ft_ssl_error(ft_strjoin(input->filename, " is an invalid file"));
	sha256_init(&ctx);
	while ((canthavesix[1] = read(canthavesix[0], filebuf, 512)))
		sha256_update(&ctx, (unsigned char *)filebuf, canthavesix[1]);
	sha256_final(&ctx, digest);
	input->digest = sha256_digest_tochar(digest);
}

char							*sha256_string(char *str)
{
	t_sha256_ctx				ctx;
	unsigned char				digest[32];
	char						*final;

	sha256_init(&ctx);
	sha256_update(&ctx, (uint8_t *)str, ft_strlen(str));
	sha256_final(&ctx, digest);
	final = sha256_digest_tochar(digest);
	return (final);
}
