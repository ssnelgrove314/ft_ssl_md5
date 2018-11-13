/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl_util.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssnelgro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 16:25:42 by ssnelgro          #+#    #+#             */
/*   Updated: 2018/11/12 16:25:43 by ssnelgro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

void	ft_ssl_error(char *str)
{
	printf("%s", str);
	exit(-1);
}

int		ft_ssl_usage(void)
{
	printf("Learn to use this you dumbass");
	return (0);
}

void	input_free(t_ft_ssl_input *tofree)
{
	if (tofree->digest)
		free(tofree->digest);
	if (tofree->filename)
		free(tofree->filename);
	if (tofree->input)
		free(tofree->input);
	free(tofree);
}
