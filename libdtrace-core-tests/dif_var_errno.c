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
	 * Test the errno variable.
	 */
	dtapi_conf_t *dtapi_conf;
	errno_t rd;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);

	rd = dtapi_var_errno(dtapi_conf, &err);
	DTCHECK(err, ("ERRNO failed: %s\n", strerror(err)));
	DTCHECK(rd != errno, ("rd (%d) != %d\n", rd, errno)); 

	dtapi_deinit(dtapi_conf);
	return (0);
}

