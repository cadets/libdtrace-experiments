PROG=	dtrace_unregister

CC=	afl-clang

CFLAGS+=	-I/usr/local/include

CLEANFILES+=	out/

LDADD=	-ldtrace-core
LDFLAGS+=	-v

MAN=

.include <bsd.prog.mk>

