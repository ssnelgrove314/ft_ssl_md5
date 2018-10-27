#ifndef FT_SSL_H
# define FT_SSL_H

# include "libft.h"
# include "ft_md5.h"
# include "sha256.h"

# define SSL_MAX_ARGS 1024

typedef void (*t_ft_ssl_func)(char *);

typedef struct			s_ft_ssl_flags
{
	uint32_t			echo_stdin : 1;
	uint32_t			quiet_mode : 1;
	uint32_t			reverse_output_fmt : 1;
	uint32_t			string_input : 1;
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
	char *input;
	size_t input_len;
	char *digest;
}						t_ft_ssl_input;

typedef struct			s_ft_ssl_prg
{
	char				*name;
	t_ft_ssl_func		ssl_fnc;
	t_ft_ssl_flags		flags;
}						t_ft_ssl_prg;

void	usage(void);
void	ft_ssl_error(char *cmd);

#endif