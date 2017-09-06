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
	 * Test the lltostr() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	char *rd;
	int err;

	dtapi_conf = dtapi_init(1000, 20, DTRACE_ACCESS_KERNEL);

	rd = dtapi_lltostr(dtapi_conf, 4123, &err);
	DTCHECK(err, ("LLTOSTR: failed: %s\n", strerror(err)));
	DTCHECK(strcmp("4123", rd) != 0, ("rd (%s) != 4123\n", rd));

	rd = dtapi_lltostr(dtapi_conf, -4131, &err);
	DTCHECK(err, ("LLTOSTR: failed: %s\n", strerror(err)));
	DTCHECK(strcmp("-4131", rd) != 0, ("rd (%s) != -4131\n", rd));

	rd = dtapi_lltostr(dtapi_conf, 0, &err);
	DTCHECK(err, ("LLTOSTR: failed: %s\n", strerror(err)));
	DTCHECK(*rd != '0', ("rd (%s) != 0\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

