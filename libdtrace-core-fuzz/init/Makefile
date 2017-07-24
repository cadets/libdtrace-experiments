PROG=	init

CC=	afl-clang

CFLAGS+=	-I/usr/local/include

CLEANDIRS+=	out/

LDADD=	-ldtrace-core
LDFLAGS+=	-v

MAN=

.include <bsd.prog.mk>

