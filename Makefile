SUBDIR=	libdtrace-core libdtrace-core-tests

.include <bsd.subdir.mk>

test:
	LD_LIBRARY_PATH=${.OBJDIR}/libdtrace-core ${.OBJDIR}/libdtrace-core-tests/libdtrace-core-tests
	/usr/local/bin/tap2junit test-output
