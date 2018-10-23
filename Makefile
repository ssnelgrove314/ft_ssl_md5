NAME	:=	ft_ssl
CC		:=	gcc
CFLAGS	:=	-Wall -Werror -Wextra
LDFLAGS	:=	-Llibs/libft -lft

SRC = $(wildcard src/ft_md5/*.c) \
       $(wildcard src/ft_sha256/*.c) \
       $(wildcard src/ft_ssl/*.c)
OBJ = $(SRC:.c=.o)

$(NAME): $(OBJ) libft
    $(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: libft
libft:
	$(MAKE) -C libs/libft

.PHONY: clean fclean re
clean:
	rm -f $(OBJ)

fclean:
	rm -f $(NAME)

re:
	clean
	fclean
	$(NAME)