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

typedef char *(*t_ft_ssl_func)(char *);

typedef struct			s_ft_ssl_flags
{
	uint32_t			echo_stdin : 1;
	uint32_t			quiet_mode : 1;
	uint32_t			reverse_output_fmt : 1;
	uint32_t			string_input : 1;
	uint32_t			file_flag : 1;
}						t_ft_ssl_flags;

enum e_ssl_inputs{
	SSL_INPUT_FILE,
	SSL_INPUT_STDIN,
	SSL_INPUT_STRING,
};

typedef struct			s_ft_ssl_input
{
	int					input_type;
	char				*filename;
	char				*input;
	size_t				input_len;
	char				*digest;
}						t_ft_ssl_input;

typedef struct			s_ft_ssl_prg
{
	char				*name;
	t_ft_ssl_func		ssl_fnc;
	t_ft_ssl_flags		flags;
	char 				**after_flags;
}						t_ft_ssl_prg;

void ft_ssl_getflags(char ***argv, t_ft_ssl_prg *prg);
void ft_ssl_getsslfunc(char *func, t_ft_ssl_prg *prg);
void ft_ssl_get_stdin(t_stack *head);
char *ft_ssl_process_inputs(t_ft_ssl_prg *prg, t_stack *head);
void ft_ssl_print(t_ft_ssl_prg *prg, t_stack *head);
void ft_ssl_error(char *msg);
int ft_ssl_usage(void);

#endif