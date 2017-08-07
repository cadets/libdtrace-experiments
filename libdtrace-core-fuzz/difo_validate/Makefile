PROG=	difo_validate

CC=	afl-clang

CFLAGS+=	-I/usr/local/include
CFLAGS+=	-D_DTRACE_TESTS

CLEANDIRS+=	out/

LDADD=	-ldtrace-core
LDFLAGS+=	-v

MAN=

.include <bsd.prog.mk>
