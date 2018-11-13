/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_md5_util.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssnelgro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 17:10:05 by ssnelgro          #+#    #+#             */
/*   Updated: 2018/11/12 17:10:07 by ssnelgro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_ssl/ft_ssl.h"

void				md5_init(\
	t_md5_ctx *ctx)
{
	ctx->count[0] = 0;
	ctx->count[1] = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

uint32_t			md5_fghi(\
	uint32_t x,\
	uint32_t y,\
	uint32_t z,\
	char fghi)
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

void				md5_ffgghhii(\
	t_md5_ffgghhii_param *p)
{
	p->a = p->a + (md5_fghi(p->b, p->c, p->d, p->ffgghhii_selector) +\
		p->x[p->sub_block[0]] + p->ac[0]);
	p->a = ROTATE_LEFT((p->a), (p->s[0]));
	p->a += p->b;
	p->d = p->d + (md5_fghi(p->a, p->b, p->c, p->ffgghhii_selector) +\
		p->x[p->sub_block[1]] + p->ac[1]);
	p->d = ROTATE_LEFT((p->d), (p->s[1]));
	p->d += p->a;
	p->c = p->c + (md5_fghi(p->d, p->a, p->b, p->ffgghhii_selector) +\
		p->x[p->sub_block[2]] + p->ac[2]);
	p->c = ROTATE_LEFT((p->c), (p->s[2]));
	p->c += p->d;
	p->b = p->b + (md5_fghi(p->c, p->d, p->a, p->ffgghhii_selector) +\
		p->x[p->sub_block[3]] + p->ac[3]);
	p->b = ROTATE_LEFT((p->b), (p->s[3]));
	p->b += p->c;
}

void				md5_memcpy(\
	unsigned char *output,\
	unsigned char *input,\
	unsigned int len)
{
	unsigned int	i;

	i = 0;
	while (i < len)
	{
		output[i] = input[i];
		i++;
	}
}

void				md5_memset(\
	unsigned char *output,\
	int value,\
	unsigned int len)
{
	unsigned int	i;

	i = 0;
	while (i < len)
	{
		((char *)output)[i] = (char)value;
		i++;
	}
}
