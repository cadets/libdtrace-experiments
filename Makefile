SUBDIR=	libdtrace-core libdtrace-core-tests

.include <bsd.subdir.mk>

test:
	LD_LIBRARY_PATH=${.OBJDIR}/libdtrace-core kyua test

debugtest:
	LD_LIBRARY_PATH=${.OBJDIR}/libdtrace-core kyua debug

junit:
	kyua report-junit

report:
	kyua report
