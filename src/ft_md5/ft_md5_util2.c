/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_md5_util2.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssnelgro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 17:10:09 by ssnelgro          #+#    #+#             */
/*   Updated: 2018/11/12 17:10:11 by ssnelgro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_ssl/ft_ssl.h"

void				md5_encode(\
	unsigned char *output,\
	uint32_t *input,\
	unsigned int len)
{
	unsigned int	i;
	unsigned int	j;

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

void				md5_decode(\
	uint32_t *output,\
	unsigned char *input,\
	unsigned int len)
{
	unsigned int	i;
	unsigned int	j;

	i = 0;
	j = 0;
	while (j < len)
	{
		output[i] = ((uint32_t)input[j]) |\
		(((uint32_t)input[j + 1]) << 8) |\
		(((uint32_t)input[j + 2]) << 16) |\
		(((uint32_t)input[j + 3]) << 24);
		i++;
		j += 4;
	}
}

char				*md5_digest_tochar(\
	unsigned char digest[16])
{
	char			*output;
	char			*tmp;
	int				i;
	unsigned char	c;
	char			*hex_tab;

	hex_tab = "0123456789abcdef";
	output = ft_memalloc(33);
	c = 0;
	i = 0;
	tmp = output;
	while (i < 16)
	{
		c = digest[i];
		*tmp++ = hex_tab[c >> 4];
		*tmp++ = hex_tab[c & 0xf];
		i++;
	}
	return (output);
}

char				*md5_string(\
	char *str)
{
	t_md5_ctx		ctx;
	unsigned char	digest[16];

	md5_init(&ctx);
	md5_update(&ctx, (unsigned char *)str, ft_strlen(str));
	md5_final(digest, &ctx);
	return (md5_digest_tochar(digest));
}
