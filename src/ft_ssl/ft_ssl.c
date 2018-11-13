/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssnelgro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 14:56:48 by ssnelgro          #+#    #+#             */
/*   Updated: 2018/11/12 14:56:59 by ssnelgro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

void				ft_ssl_read_stdin(t_ft_ssl_input **tmp)
{
	char			buf[64];
	int				ret;
	t_vector		a;

	ft_vector_init(&a, 64);
	while ((ret = read(STDIN_FILENO, buf, 64)))
		ft_vector_nappend(&a, buf, ret);
	ft_vector_nappend(&a, "\0", 1);
	(*tmp)->input_type = SSL_INPUT_STDIN;
	(*tmp)->input = ft_strdup(a.data);
	ft_vector_free(&a);
}

void				ft_ssl_get_files_and_str(char ***argv, t_ft_ssl_prg *prg,\
		t_queue *head)
{
	t_ft_ssl_input	*tmp;

	tmp = NULL;
	if (prg->flags->echo_stdin ||\
			(!prg->after_flags &&\
			!prg->flags->string_input &&\
			!prg->flags->file_flag))
	{
		tmp = (t_ft_ssl_input *)ft_memalloc(sizeof(t_ft_ssl_input));
		ft_ssl_read_stdin(&tmp);
		enqueue(head, tmp);
	}
	if (prg->flags->string_input)
		ft_ssl_get_s_optstr(argv, head);
	while (*prg->after_flags)
	{
		tmp = (t_ft_ssl_input *)ft_memalloc(sizeof(t_ft_ssl_input));
		tmp->filename = ft_strdup(*prg->after_flags);
		tmp->input_type = SSL_INPUT_FILE;
		prg->after_flags += 1;
		enqueue(head, tmp);
	}
}

int					main(int argc, char **argv)
{
	t_queue			prg_stack;
	t_ft_ssl_prg	prg;
	char			*output;

	prg.flags = (t_ft_ssl_flags *)ft_memalloc(sizeof(t_ft_ssl_flags));
	output = NULL;
	if (argc == 1)
		ft_ssl_usage();
	init_queue(&prg_stack);
	ft_ssl_get_func(&argv, &prg);
	ft_ssl_getflags(&argv, &prg);
	ft_ssl_get_files_and_str(&argv, &prg, &prg_stack);
	output = ft_ssl_process_inputs(&prg, &prg_stack);
	printf("%s", output);
	free(output);
	free(prg.flags);
	return (0);
}
