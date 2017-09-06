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
	 * Test the strjoin() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	char *rd;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = NULL;

	rd = dtapi_strjoin(dtapi_conf, "hello ", "world", &err);
	DTCHECK(err, ("STRJOIN failed: %s\n", strerror(err)));
	DTCHECK(strcmp("hello world", rd) != 0,
	    ("rd (%s) != hello world\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

