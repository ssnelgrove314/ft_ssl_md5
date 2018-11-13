/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssnelgro <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 16:25:32 by ssnelgro          #+#    #+#             */
/*   Updated: 2018/11/12 16:25:34 by ssnelgro         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H

# include "../../libs/libft/libft.h"
# include "../ft_md5/ft_md5.h"
# include "../ft_sha256/ft_sha256.h"
# include <fcntl.h>

# define SSL_MAX_ARGS 1024
# define SSL_MAX_STDIN_LEN 1024
# define SSL_MAX_FUNC 2
# define SSL_BUF 32

typedef struct			s_ft_ssl_flags
{
	uint32_t			echo_stdin : 1;
	uint32_t			quiet_mode : 1;
	uint32_t			reverse_output_fmt : 1;
	uint32_t			string_input : 1;
	uint32_t			file_flag : 1;
}						t_ft_ssl_flags;

enum					e_ssl_inputs{
	SSL_INPUT_FILE,
	SSL_INPUT_STDIN,
	SSL_INPUT_STRING,
};

typedef struct			s_ft_ssl_input
{
	int					input_type;
	char				*filename;
	char				*input;
	char				*digest;
}						t_ft_ssl_input;

typedef void			(*t_ft_ssl_func)(void *input);

typedef struct			s_ft_ssl_prg
{
	char				*name;
	t_ft_ssl_func		ssl_fnc;
	t_ft_ssl_flags		*flags;
	char				**after_flags;
}						t_ft_ssl_prg;

/*
** ft_ssl.c
*/

void					ft_ssl_get_files_and_str(\
	char ***argv,\
	t_ft_ssl_prg *prg,\
	t_queue *head);
void					ft_ssl_read_stdin(\
	t_ft_ssl_input **tmp);

/*
** ft_ssl_get_args.c
*/
void					ft_ssl_get_func(\
	char ***argv,\
	t_ft_ssl_prg *prg);
void					ft_ssl_getflags(\
	char ***argv,\
	t_ft_ssl_prg *prg);
void					ft_ssl_get_s_optstr(\
	char ***argv,\
	t_queue *head);

/*
** ft_ssl_get_args.c
*/

void					ft_ssl_input_print_quiet(\
	t_ft_ssl_input *tmp_input,\
	t_vector *output);
void					ft_ssl_input_print_reverse(\
	t_ft_ssl_input *tmp_input,\
	t_vector *output);
void					ft_ssl_input_print_normal(\
	t_ft_ssl_input *tmp_input,\
	t_vector *output,\
	t_ft_ssl_prg *prg);
char					*ft_ssl_process_inputs(\
	t_ft_ssl_prg *prg,\
	t_queue *head);

/*
** ft_ssl_utils.c
*/

void					input_free(t_ft_ssl_input *tofree);
void					ft_ssl_error(char *msg);
int						ft_ssl_usage(void);

#endif
