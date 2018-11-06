#include "ft_ssl.h"


void ft_ssl_error(char *str)
{
	printf("%s", str);
	exit (-1);
}

int ft_ssl_usage(void)
{
	printf("Learn to use this you dumbass");
	return (0);
}

void ft_ssl_get_func(char ***argv, t_ft_ssl_prg *prg)
{
	size_t i;

	t_ft_ssl_prg g_ssl_funcs[] =
	{
		{.name = "md5", .ssl_fnc = &md5_string, .flags = {0}},
		{.name = "sha256", .ssl_fnc = &sha256_string, .flags = {0}},
	};
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
	ft_ssl_error((char *)argv[0]);
}

void ft_ssl_get_s_optstr(int *argc, char ***av, t_ft_ssl_prg *prg, t_stack *head)
{
	t_ft_ssl_input *tmp_input;

	tmp_input = 0;
	*av += 1;
	*argc -= 1;
	if (!av)
		ft_ssl_error("no string after -s option");
	tmp_input = (t_ft_ssl_input *)ft_memalloc(sizeof(t_ft_ssl_input));
	tmp_input->input = ft_strdup(**av);
	tmp_input->input_type = SSL_INPUT_STRING;
	tmp_input->input_len = ft_strlen(tmp_input->input);
	prg->flags.string_input = 1;
	stack_push(head, tmp_input);
}

void ft_ssl_getflags(int *argc, char ***argv, t_ft_ssl_prg *prg, t_stack *head)
{

	*argv += 2;
	*argc -= 2;
	while (*argv && *argc)
	{
		if (***argv == '-')
		{
			if (argv[0][0][1] == 'p')
				prg->flags.echo_stdin = 1;
			else if (argv[0][0][1] == 'q')
				prg->flags.quiet_mode = 1;
			else if (argv[0][0][1] == 'r')
				prg->flags.reverse_output_fmt = 1;
			else if (argv[0][0][1] == 's')
				ft_ssl_get_s_optstr(argc, argv, prg, head);
			else 
				ft_ssl_error("Invalid option");
		}
		else
		{
			prg->flags.file_flag = 1;
			break ;
		}
		*argv += 1;
		*argc -= 1;
	}
}

			// {
			// }
		// else if (argv[0][i][0])
		// {
		// 	tmp_input = ft_memalloc(sizeof(t_ft_ssl_input));
		// 	tmp_input->input_type = SSL_INPUT_FILE;
		// 	tmp_input->filename = ft_strdup(argv[0][i]);

		// 	tmp_input->input = ft_ssl_read_file(tmp_input->filename);
		// 	tmp_input->input_len = ft_strlen(tmp_input->input);
		// 	stack_push(head, tmp_input);
		// 	tmp_input = 0;
		// }

void ft_ssl_input_print_quiet(t_ft_ssl_input *tmp_input, t_vector *output)
{
	ft_vector_append(output, tmp_input->digest);
	ft_vector_append(output, "\n");
}

void ft_ssl_input_print_reverse(t_ft_ssl_input *tmp_input, t_vector *output)
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

void ft_ssl_input_print_normal(t_ft_ssl_input *tmp_input, t_vector *output, t_ft_ssl_prg *prg)
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

void input_free(t_ft_ssl_input *tofree)
{
	if (tofree->digest)
		free (tofree->digest);
	if (tofree->filename)
		free (tofree->filename);
	if (tofree->input)
		free (tofree->input);
	free (tofree);
}

char *ft_ssl_process_inputs(t_ft_ssl_prg *prg, t_stack *head)
{
	t_ft_ssl_input *tmp_input;
	t_vector output;
	char *ret;

	ret = NULL;
	ft_vector_init(&output, 64);
	while (!stack_empty(head))
	{
		tmp_input = (t_ft_ssl_input *)stack_pop(head);
		tmp_input->digest = prg->ssl_fnc(tmp_input->input);
		if (tmp_input->input_type == SSL_INPUT_STDIN)
		{
			if (prg->flags.echo_stdin)
			{
				ft_vector_append(&output, tmp_input->input);
				ft_vector_append(&output, "\n");
			}
			ft_vector_append(&output, tmp_input->digest);
		}
		else if (prg->flags.quiet_mode)
				ft_ssl_input_print_quiet(tmp_input, &output);
		else if (prg->flags.reverse_output_fmt)
			ft_ssl_input_print_reverse(tmp_input, &output);
		else
			ft_ssl_input_print_normal(tmp_input, &output, prg);
		input_free(tmp_input);
	}
	ret = ft_strdup(output.data);
	ft_vector_free(&output);
	return (ret);
}

void ft_ssl_read_file(int fd, t_stack *head, char *filename)
{
	char buf[1024];
	int ret;
	t_vector file;
	t_ft_ssl_input *tmp;

	tmp = (t_ft_ssl_input *)ft_memalloc(sizeof(t_ft_ssl_input));
	ft_vector_init(&file, 64);
	while ((ret = read(fd, buf, 1024)))
		ft_vector_nappend(&file, (char *)buf, ret);
	if (fd == STDIN_FILENO)
		tmp->input_type = SSL_INPUT_STDIN;
	else
	{
		tmp->input_type = SSL_INPUT_FILE;
		tmp->filename = ft_strdup(filename);
	}
	tmp->input = ft_strdup(file.data);
	tmp->input_len = file.len;
	stack_push(head, tmp);
	ft_vector_free(&file);
}

void ft_ssl_get_files(int *argc, char ***argv, t_ft_ssl_prg *prg, t_stack *prg_stack)
{
	int fd;

	fd = 0;
	if (prg->flags.echo_stdin || (!prg->flags.string_input && !prg->flags.file_flag))
		ft_ssl_read_file(STDIN_FILENO, prg_stack, 0);
	while (**argv)
	{
		if ((fd = ft_fopen(**argv, "r")) == -1)
			ft_ssl_error("yo this ain't a file.");
		ft_ssl_read_file(fd, prg_stack, **argv);
		*argv += 1;
		*argc -= 1;
	}
}

int main(int argc, char **argv)
{
	t_stack prg_stack;
	t_ft_ssl_prg prg;
	char *output;

	output = NULL;
	if (argc == 1)
		ft_ssl_usage();
	stack_init(&prg_stack, SSL_MAX_ARGS);
	ft_ssl_get_func(&argv, &prg);
	ft_ssl_getflags(&argc, &argv, &prg, &prg_stack);
	ft_ssl_get_files(&argc, &argv, &prg, &prg_stack);
	output = ft_ssl_process_inputs(&prg, &prg_stack);
	stack_destroy(&prg_stack);
	printf("%s\n", output);
	free(output);
	return (0);
}
