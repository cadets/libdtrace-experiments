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
	 * Test the bcopy() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	void *rd;
	const char *buf = "hello world";
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = 0;

	rd = dtapi_bcopy(dtapi_conf, buf, 10, &err);
	DTCHECK(err, ("BCOPY failed: %s\n", strerror(err)));
	DTCHECK(strcmp(buf, rd) == 0, ("rd (%s) != %s\n", (char *)rd, buf));

	dtapi_deinit(dtapi_conf);
	return (0);
}

