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
	t_vector		test;
	char			*output;
	char			buf[3];
	int				i;

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
