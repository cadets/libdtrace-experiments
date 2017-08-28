#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

int
main(void)
{
	/*
	 * Test the NOT operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_not(dtapi_conf, 0, &err);

	if (err) {
		printf("NOT failed: %s\n", strerror(err));
		return (1);
	}

	if (rd != 0xFFFFFFFFFFFFFFFF) {
		printf("rd (%#lx) != 0xFFFFFFFFFFFFFFFF\n", rd);
		return (1);
	}

	rd = dtapi_op_not(dtapi_conf, 0xD06ED00D, &err);

	if (err) {
		printf("NOT failed: %s\n", strerror(err));
		return (1);
	}

	if (rd != 0xFFFFFFFF2F912FF2) {
		printf("rd (%#lx) != 0xFFFFFFFF2F912FF\n", rd);
		return (1);
	}


	dtapi_deinit(dtapi_conf);
	return (0);
}

