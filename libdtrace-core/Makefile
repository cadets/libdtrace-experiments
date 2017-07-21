CC=	afl-clang
LIB=		dtrace-core
SHLIB_MAJOR=	0

SRCS=		dtrace-core.c unr.c dtrace_asm.S
CFLAGS+=	-D_WANT_UCRED -D_WANT_FILE

.if defined(_DTRACE_TESTS)
CFLAGS+=	-D_DTRACE_TESTS
.endif

MAN=

.include <bsd.lib.mk>
