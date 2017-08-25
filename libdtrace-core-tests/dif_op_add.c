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
	 * Test the ADD operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_add(dtapi_conf, 100, 50, &err);

	if (err) {
		printf("ADD failed: %s\n", strerror(err));
		return (1);
	}

	if (rd != 150) {
		printf("rd (%lu) != 150\n", rd);
		return (1);
	}

	rd = dtapi_op_add(dtapi_conf, 0xFFFFFFFFFFFFFFFF, 1, &err);

	if (err) {
		printf("ADD failed: %s\n", strerror(err));
		return (1);
	}

	if (rd != 0) {
		printf("rd (%lu) != 0\n", rd);
		return (1);
	}

	dtapi_deinit(dtapi_conf);
	return (0);
}




