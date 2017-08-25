#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

int
main(void)
{
	/*
	 * Tests the initialization of the library
	 */
	int err;

	err = dtrace_init();
	if (err) {
		printf("DTrace not properly initialized: %s\n", strerror(err));
		return (1);
	}

	return (0);
}
