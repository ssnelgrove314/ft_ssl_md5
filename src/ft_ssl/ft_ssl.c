#include "ft_ssl.h"

int main(int argc, char **argv)
{
	t_stack prg_stack;
	t_ft_ssl_prg prg;

	if (argc < 3)
		return (ft_ssl_usage());
	ft_ssl_argparse(argc, argv, &prg, &prg_stack);
}

void ft_ssl_argparse(int argc, char **argv, t_ft_ssl_prg *prg, t_stack *head)
{
	stack_init(head, SSL_MAX_ARGS);
	ft_ssl_getsslfunc(argv[2], prg);
	ft_ssl_getflags(argc, argv, prg, head);
}

void ft_ssl_getflags(int argc, char **argv, t_ft_ssl_prg *prg, t_stack *head)
{
	int i;
	t_ft_ssl_input *tmp_input;

	i = -1;
	argv += 2;
	argc -= 2;
	while (++i < argc)
	{
		if (argv[i][0] == '-')
		{
			if (argv[i][1] == 'p')
				prg->flags.echo_stdin = 1;
			if (argv[i][1] == 'q')
				prg->flags.quiet_mode = 1;
			if (argv[i][1] == 'r')
				prg->flags.reverse_output_fmt = 1;
			if (argv[i][1] == 's')
			{
				tmp_input = ft_memalloc(sizeof(t_ft_ssl_input));
				if (argv[i + 1][0])
					tmp_input->input = ft_strdup(argv[i + 1]);
				else
				{
					free(tmp_input);
					tmp_input = 0;
					ft_ssl_error("No valid string after -s flag");
					return ;
				}
				tmp_input->input_type = SSL_INPUT_STRING;
				tmp_input->input_len = ft_strlen(tmp_input->input);
				prg->flags.string_input = 1;
				stack_push(head, tmp_input);
				tmp_input = 0;
			}
		}
		else if (argv[i][0])
		{
			tmp_input = ft_memalloc(sizeof(t_ft_ssl_input));
			tmp_input->input_type = SSL_INPUT_FILE;
			tmp_input->filename = ft_strdup(argv[i]);
			tmp_input->input = ft_file_to_str(tmp_input->filename);
			tmp_input->input_len = ft_strlen(tmp_input->input);
			stack_push(head, tmp_input);
			tmp_input = 0;
		}
	}
}

void ft_ssl_getsslfunc(char *func, t_ft_ssl_prg *prg)
{
	int i;

	i = -1;
	const t_ft_ssl_prg ssl_functions[] = {
		{"md5", &ft_md5, 0},
		{"sha256", &ft_sha256, 0},
	};
	while (++i < 2)
	{
		if (ft_strcmp(func, ssl_functions[i].name))
		{
			prg->name = ft_strdup(ssl_functions[i].name);
			prg->ssl_fnc = ssl_functions[i].ssl_fnc;
			return ;
		}
	}
	ft_ssl_error("Invalid Function");
}