PROG=	libdtrace-core-tests

SRCS=		libdtrace-core-tests.c ../test-api/dtrace_api.c
CFLAGS+=	-I/usr/local/include

.if defined(_DTRACE_TESTS)
CFLAGS+=	-D_DTRACE_TESTS
.endif

LDADD=		-L../libdtrace-core/ -ldtrace-core
LDADD+=		-L/usr/local/lib -latf-c

LDFLAGS+=	-v

MAN=

.include <bsd.prog.mk>
