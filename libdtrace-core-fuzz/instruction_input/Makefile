PROG=	instruction_input

CC=	afl-clang

CFLAGS+=	-I/usr/local/include
.if defined(_DTRACE_TESTS)
CFLAGS+=	-D_DTRACE_TESTS
.endif

CLEANDIRS+=	out/

LDADD=	-ldtrace-core
LDFLAGS+=	-v

MAN=

.include <bsd.prog.mk>

