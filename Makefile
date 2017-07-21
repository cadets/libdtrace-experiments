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
	afl-fuzz -i libdtrace-core-fuzz/${FUZZ}/in -o libdtrace-core-fuzz/${FUZZ}/out libdtrace-core-fuzz/${FUZZ}/${FUZZ}
