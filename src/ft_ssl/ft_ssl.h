#ifndef FT_SSL_H
# define FT_SSL_H

typedef void (*t_ft_ssl_func)(char *);

typedef struct			s_ft_ssl_input
{
	int					input_type;
	char				*filename;
	char *input;
	size_t input_len;
	char *digest;
	struct s_ft_ssl_input *next;
}						t_ft_ssl_input;

typedef struct			s_ft_ssl_prg
{
	char				*name;
	t_ft_ssl_func		ssl_fnc;
}						t_ft_ssl_prg;

void	usage(void);
void	ft_ssl_error(char *cmd);
void	ft_ssl_error(char *errormsg);
void	ft_ssl_md

#endif