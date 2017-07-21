SUBDIR=	libdtrace-core libdtrace-core-tests libdtrace-core-fuzz

TEST=
FUZZ=

.include <bsd.subdir.mk>

test:
	LD_LIBRARY_PATH=${.OBJDIR}/libdtrace-core kyua test

debugtest:
	LD_LIBRARY_PATH=${.OBJDIR}/libdtrace-core kyua debug libdtrace-core-tests/libdtrace-core-tests:${TEST}

junit:
	kyua report-junit

report:
	kyua report

fuzz:
	LD_LIBRARY_PATH=${.OBJDIR}/libdtrace-core afl-fuzz -i libdtrace-core-fuzz/in/${FUZZ} -o libdtrace-core-fuzz/out libdtrace-core-fuzz/${FUZZ}
