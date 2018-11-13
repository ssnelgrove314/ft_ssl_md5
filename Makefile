NAME	:=	ft_ssl
CC		:=	gcc
CFLAGS	:=	-Wall -Werror -Wextra -g 
DEBUG	:=	-fsanitize=address -L/usr/lib/gcc/x86_64-pc-linux-gnu/8.2.1 -lgcc
LDFLAGS	:=	-Llibs/libft -lft

SRC = $(wildcard src/ft_md5/*.c) \
       $(wildcard src/ft_sha256/*.c) \
       $(wildcard src/ft_ssl/*.c)
OBJ = $(SRC:.c=.o)

all: libft $(NAME)

$(NAME): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

.PHONY: libft
libft:
	$(MAKE) -C libs/libft

.PHONY: clean fclean re
clean:
	rm -f $(OBJ)

fclean:
	rm -f $(NAME)

re: fclean all