#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

#include "dtcheck.h"

int
main(void)
{
	/*
	 * Test the strtok() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	char *rd;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = NULL;

	rd = dtapi_strtok(dtapi_conf, "hello-world", "-", &err);
	DTCHECK(err, ("STRSTR failed: %s\n", strerror(err)));
	DTCHECK(strcmp("world", rd) != 0, ("rd (%s) != world", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

