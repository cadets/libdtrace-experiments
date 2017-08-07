PROG=	instruction_input

CC=	afl-clang

CFLAGS+=	-I/usr/local/include
CFLAGS+=	-D_DTRACE_TESTS

CLEANDIRS+=	out/

LDADD=	-ldtrace-core

MAN=

.include <bsd.prog.mk>
