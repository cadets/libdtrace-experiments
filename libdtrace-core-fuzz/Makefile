CC=	afl-clang
CFLAGS=	-Wall -Wextra -Werror -O0 -ldtrace-core

dtrace_register:
	${CC} ${CFLAGS} dtrace_register.c -o dtrace_register

all:
	dtrace_register

clean:
	rm -f dtrace_register
	rm -rf out/

