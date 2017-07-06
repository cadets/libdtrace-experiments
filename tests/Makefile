PROG=	libdtrace_tests

CFLAGS+=	-I/usr/local/include

LDADD=		-L../src/libdtrace -ldtrace
LDADD+=		-L/usr/local/lib -lcheck

LDFLAGS+=	-v

MAN=

.include <bsd.prog.mk>
