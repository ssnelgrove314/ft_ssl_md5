/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_md5.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssnelgro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 17:09:49 by ssnelgro          #+#    #+#             */
/*   Updated: 2018/11/12 17:09:51 by ssnelgro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_ssl/ft_ssl.h"
#include "ft_md5_constants.h"

void						md5_rounds(\
	t_md5_ffgghhii_param *p,\
	int *i)
{
	int						j;

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

void						md5_update(\
	t_md5_ctx *ctx, unsigned char *input,\
	unsigned int input_len)
{
	unsigned int			i;
	unsigned int			index;
	unsigned int			part_len;

	index = (unsigned int)((ctx->count[0] >> 3) & 0x3F);
	if ((ctx->count[0] +=\
		((uint32_t)input_len << 3)) < ((uint32_t)input_len << 3))
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

void						md5_final(\
	unsigned char output[16],\
	t_md5_ctx *ctx)
{
	unsigned char			bits[8];
	unsigned int			index;
	unsigned int			pad_len;

	md5_encode(bits, ctx->count, 8);
	index = (unsigned int)((ctx->count[0] >> 3) & 0x3F);
	pad_len = (index < 56) ? (56 - index) : (120 - index);
	md5_update(ctx, g_md5_padding, pad_len);
	md5_update(ctx, bits, 8);
	md5_encode(output, ctx->state, 16);
	md5_memset((unsigned char *)ctx, 0, sizeof(*ctx));
}

void						md5_transform(\
	uint32_t state[4],\
	unsigned char block[64])
{
	t_md5_ffgghhii_param	par;
	int						i;

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

void						md5_handler(void *in)
{
	t_md5_ctx				ctx;
	unsigned char			digest[16];
	unsigned char			filebuf[512];
	int						canthavesix[2];
	t_ft_ssl_input			*input;

	input = (t_ft_ssl_input *)in;
	if (input->input_type == SSL_INPUT_STRING ||\
		input->input_type == SSL_INPUT_STDIN)
	{
		input->digest = md5_string(input->input);
		return ;
	}
	else if ((canthavesix[0] = ft_fopen(input->filename, "r")) == -1)
		ft_ssl_error(ft_strjoin(input->filename, " is an invalid file"));
	md5_init(&ctx);
	while ((canthavesix[1] = read(canthavesix[0], filebuf, 512)))
		md5_update(&ctx, (unsigned char *)filebuf, canthavesix[1]);
	md5_final(digest, &ctx);
	input->digest = md5_digest_tochar(digest);
}
