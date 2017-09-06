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
	 * Test the strstr() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	char *rd;
	const char *big = "hello world";
	const char *little = "world";
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = NULL;

	rd = dtapi_strstr(dtapi_conf, big, little, &err);
	DTCHECK(err, ("STRSTR failed: %s\n", strerror(err)));
	DTCHECK(big + sizeof("hello ") - 1 != rd, ("rd (%p) != %p\n",
	    rd, big + sizeof("hello ") - 1));

	dtapi_deinit(dtapi_conf);
	return (0);
}

