CC=	afl-clang
CFLAGS=	-Wall -Wextra -Werror -O0 -g -L../libdtrace-core -ldtrace-core

.if defined(_DTRACE_TESTS)
CFLAGS+=	-D_DTRACE_TESTS
.endif

dtrace_register:
	${CC} ${CFLAGS} dtrace_register.c -o dtrace_register

all:
	dtrace_register

clean:
	rm -f dtrace_register
	rm -rf out/

