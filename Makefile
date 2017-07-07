SUBDIR=	libdtrace-core libdtrace-core-tests

.include <bsd.subdir.mk>

test:
	LD_LIBRARY_PATH=${.OBJDIR}/libdtrace-core kyua test
