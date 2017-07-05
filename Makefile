LIB=		dtrace
SHLIB_MAJOR=	0

SRCS=		dtrace.c
CFLAGS+=	-D_WANT_UCRED -D_WANT_FILE

MAN=

.include <bsd.lib.mk>
