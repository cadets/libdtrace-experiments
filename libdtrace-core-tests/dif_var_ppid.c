#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

#include "dtcheck.h"

int
main(void)
{
	/*
	 * Test the ppid variable.
	 */
	dtapi_conf_t *dtapi_conf;
	pid_t rd;
	int err;

	err = dtrace_init();
	DTCHECK(err, ("DTrace not properly initialized: %s", strerror(err)));

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);


	rd = dtapi_var_ppid(dtapi_conf, &err);
	DTCHECK(err, ("PPID failed: %s\n", strerror(err)));
	DTCHECK(rd != getppid(), ("rd (%d) != %d\n", rd, getppid()));

	dtapi_deinit(dtapi_conf);
	err = dtrace_deinit();
	DTCHECK(err, ("DTrace not properly deinitialized: %s", strerror(err)));
	return (0);
}

