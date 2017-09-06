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
	 * Test the substr() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	char *rd;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = NULL;

	rd = dtapi_substr(dtapi_conf, "hello world", 0, 5, &err);
	DTCHECK(err, ("SUBSTR failed: %s\n", strerror(err)));
	DTCHECK(strcmp("hello", rd) != 0, ("rd (%s) != hello\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

