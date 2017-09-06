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
	 * Test the dirname() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	char *rd;
	int err;

	dtapi_conf = dtapi_init(1000, 20, DTRACE_ACCESS_KERNEL);

	rd = dtapi_dirname(dtapi_conf, "test/foo/bar/baz", &err);
	DTCHECK(err, ("DIRNAME failed: %s\n", strerror(err)));
	DTCHECK(strcmp("test/foo/bar", rd) != 0,
	    ("rd (%s) != test/foo/bar\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

