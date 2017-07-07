PROG=	libdtrace-core-tests

CFLAGS+=	-I/usr/local/include

LDADD=		-L../libdtrace-core/ -ldtrace-core
LDADD+=		-L/usr/local/lib -latf-c

LDFLAGS+=	-v

MAN=

.include <bsd.prog.mk>
