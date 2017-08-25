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
	 * Test the dtrace_providers() function
	 */
	char *provs;
	size_t sz;
	int err;

	err = dtrace_init();
	if (err != 0) {
		printf("DTrace not properly initialized: %s\n", strerror(err));
		return (1);
	}

	provs = dtrace_providers(&sz);

	if (sz != 1 ||
	    strcmp("dtrace", provs) != 0) {
		printf("dtrace_providers returned wrong values: (%zu, %s)\n",
		    sz, provs);
		return (1);
	}

	err = dtrace_deinit();
	if (err != 0) {
		printf("DTrace not properly deinitialized: %s\n", strerror(err));
		return (1);
	}

	return (0);
}

