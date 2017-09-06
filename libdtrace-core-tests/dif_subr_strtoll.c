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
	 * Test the strtoll() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	int64_t rd;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);

	rd = dtapi_strtoll(dtapi_conf, "4123", &err);
	DTCHECK(err, ("STRTOLL: failed: %s\n", strerror(err)));
	DTCHECK(rd != 4123, ("rd (%ld) != 4123\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "abc", &err);
	DTCHECK(err, ("STRTOLL: failed: %s\n", strerror(err)));
	DTCHECK(rd != 0, ("rd (%ld) != 0\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "-1234", &err);
	DTCHECK(err, ("STRTOLL: failed: %s\n", strerror(err)));
	DTCHECK(rd != -1234, ("rd (%ld) != -1234\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "-1234a", &err);
	DTCHECK(err, ("STRTOLL: failed: %s\n", strerror(err)));
	DTCHECK(rd != -1234, ("rd (%ld) != 0\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "1234a", &err);
	DTCHECK(err, ("STRTOLL: failed: %s\n", strerror(err)));
	DTCHECK(rd != 1234, ("rd (%ld) != 0\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "s1234", &err);
	DTCHECK(err, ("STRTOLL: failed: %s\n", strerror(err)));
	DTCHECK(rd != 0, ("rd (%ld) != 0\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "12a34", &err);
	DTCHECK(err, ("STRTOLL: failed: %s\n", strerror(err)));
	DTCHECK(rd != 12, ("rd (%ld) != 0\n", rd));

	rd = dtapi_strtoll(dtapi_conf, "    12a34", &err);
	DTCHECK(err, ("STRTOLL: failed: %s\n", strerror(err)));
	DTCHECK(rd != 12, ("rd (%ld) != 0\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

