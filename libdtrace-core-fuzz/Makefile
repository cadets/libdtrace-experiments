CC=	afl-clang
CFLAGS=	-Wall -Wextra -Werror -O0 -ldtrace-core

dtrace_register:
	${CC} ${CFLAGS} dtrace_register.c -o dtrace_register

dtrace_unregister:
	${CC} ${CFLAGS} dtrace_unregister.c -o dtrace_unregister

all:	dtrace_register dtrace_unregister

clean:
	rm -f dtrace_register
	rm -rf out/

