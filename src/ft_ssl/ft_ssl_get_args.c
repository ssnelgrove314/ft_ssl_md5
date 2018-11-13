/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl_get_args.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssnelgro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 15:00:45 by ssnelgro          #+#    #+#             */
/*   Updated: 2018/11/12 15:32:19 by ssnelgro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

t_ft_ssl_prg	g_ssl_funcs[] =
{
	{"md5", &md5_handler, 0, 0},
	{"sha256", &sha256_handler, 0, 0},
};

void					ft_ssl_get_func(char ***argv, t_ft_ssl_prg *prg)
{
	size_t				i;

	i = -1;
	while (++i < SSL_MAX_FUNC)
	{
		if (ft_strequ(g_ssl_funcs[i].name, argv[0][1]))
		{
			prg->name = g_ssl_funcs[i].name;
			prg->ssl_fnc = g_ssl_funcs[i].ssl_fnc;
			return ;
		}
	}
	ft_ssl_error(ft_strjoin(argv[0][1], "is an invalid function"));
}

void					ft_ssl_getflags_options(t_ft_ssl_prg **prg, char ***av)
{
	if (av[0][0][1] == 'p')
		(*prg)->flags->echo_stdin = 1;
	else if (av[0][0][1] == 'q')
		(*prg)->flags->quiet_mode = 1;
	else if (av[0][0][1] == 'r')
		(*prg)->flags->reverse_output_fmt = 1;
	else if (av[0][0][1] == 's')
	{
		(*prg)->flags->string_input = 1;
		(*av) += 1;
	}
}

void					ft_ssl_getflags(char ***argv, t_ft_ssl_prg *prg)
{
	char				**av;

	av = *argv;
	av += 2;
	while (*av)
	{
		if (**av != '-')
		{
			prg->after_flags = av;
			prg->flags->file_flag = 1;
			break ;
		}
		ft_ssl_getflags_options(&prg, &av);
		av += 1;
		prg->after_flags = av;
	}
}

void					ft_ssl_get_s_optstr(char ***argv, t_queue *head)
{
	t_ft_ssl_input		*tmp_input;
	char				**av;

	tmp_input = 0;
	av = *argv;
	av += 2;
	while (*av)
	{
		if (**av == '-' && *(*av + 1) == 's')
		{
			av += 1;
			if (!*av)
				ft_ssl_error("No valid string after -s arg");
			tmp_input = (t_ft_ssl_input *)ft_memalloc(sizeof(t_ft_ssl_input));
			tmp_input->input = ft_strdup(*av);
			tmp_input->input_type = SSL_INPUT_STRING;
			enqueue(head, tmp_input);
		}
		av += 1;
	}
}
