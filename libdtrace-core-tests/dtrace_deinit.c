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
	 * Initializes the library and tests it's de-initialization
	 *
	 * NOTE: This also tests dtrace_unregister(), so it's not necessary to
	 * separately test it as a black box.
	 */
	int err;

	err = dtrace_init();
	if (err != 0) {
		printf("DTrace not properly initialized: %s\n", strerror(err));
		return (1);
	}

	err = dtrace_deinit();
	if (err != 0) {
		printf("DTrace not properly deinitialized: %s\n", strerror(err));
		return (1);
	}

	return (0);
}

