/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl_printing.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssnelgro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 16:25:39 by ssnelgro          #+#    #+#             */
/*   Updated: 2018/11/12 16:25:40 by ssnelgro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

void				ft_ssl_input_print_quiet(\
	t_ft_ssl_input *tmp_input,\
	t_vector *output)
{
	ft_vector_append(output, tmp_input->digest);
	ft_vector_append(output, "\n");
}

void				ft_ssl_input_print_reverse(\
	t_ft_ssl_input *tmp_input,\
	t_vector *output)
{
	ft_vector_append(output, tmp_input->digest);
	ft_vector_append(output, " ");
	if (tmp_input->input_type == SSL_INPUT_STRING)
	{
		ft_vector_append(output, "\"");
		ft_vector_append(output, tmp_input->input);
		ft_vector_append(output, "\"\n");
	}
	else if (tmp_input->input_type == SSL_INPUT_FILE)
	{
		ft_vector_append(output, tmp_input->filename);
		ft_vector_append(output, "\n");
	}
}

void				ft_ssl_input_print_normal(\
	t_ft_ssl_input *tmp_input,\
	t_vector *output, t_ft_ssl_prg *prg)
{
	ft_vector_append(output, prg->name);
	ft_vector_append(output, "(");
	if (tmp_input->input_type == SSL_INPUT_STRING)
	{
		ft_vector_append(output, "\"");
		ft_vector_append(output, tmp_input->input);
		ft_vector_append(output, "\"");
	}
	else if (tmp_input->input_type == SSL_INPUT_FILE)
		ft_vector_append(output, tmp_input->filename);
	ft_vector_append(output, ") = ");
	ft_vector_append(output, tmp_input->digest);
	ft_vector_append(output, "\n");
}

void				ft_ssl_process_inputs_2(\
	t_ft_ssl_prg *prg,\
	t_vector *output,\
	t_queue *head,\
	t_ft_ssl_input *tmp_input)
{
	tmp_input = (t_ft_ssl_input *)dequeue(head);
	prg->ssl_fnc(tmp_input);
	if (tmp_input->input_type == SSL_INPUT_STDIN)
	{
		if (prg->flags->echo_stdin)
		{
			ft_vector_append(output, tmp_input->input);
			ft_vector_append(output, "\n");
		}
		ft_vector_append(output, tmp_input->digest);
		ft_vector_append(output, "\n");
	}
	else if (prg->flags->quiet_mode)
		ft_ssl_input_print_quiet(tmp_input, output);
	else if (prg->flags->reverse_output_fmt)
		ft_ssl_input_print_reverse(tmp_input, output);
	else
		ft_ssl_input_print_normal(tmp_input, output, prg);
	input_free(tmp_input);
}

char				*ft_ssl_process_inputs(\
	t_ft_ssl_prg *prg,\
	t_queue *head)
{
	t_ft_ssl_input	*tmp_input;
	t_vector		output;
	char			*ret;

	ret = NULL;
	tmp_input = NULL;
	ft_vector_init(&output, 128);
	while (!empty_queue(head))
		ft_ssl_process_inputs_2(prg, &output, head, tmp_input);
	ret = ft_strdup(output.data);
	ft_vector_free(&output);
	return (ret);
}
