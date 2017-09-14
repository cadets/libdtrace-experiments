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
	 * Test the uid variable.
	 */
	dtapi_conf_t *dtapi_conf;
	uid_t rd;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);

	rd = dtapi_var_uid(dtapi_conf, &err);
	DTCHECK(err, ("UID failed: %s\n", strerror(err)));
	DTCHECK(rd != getuid(), ("rd (%d) != %d\n", rd, getuid()));

	dtapi_deinit(dtapi_conf);
	return (0);
}

