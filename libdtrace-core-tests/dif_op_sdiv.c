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
	int64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_sdiv(dtapi_conf, 1024, -2, &err);

	if (err) {
		printf("SDIV failed: %s\n", strerror(err));
		return (1);
	}

	if (rd != -512) {
		printf("rd (%ld) != -512\n", rd);
		return (1);
	}

	rd = dtapi_op_sdiv(dtapi_conf, -1024, 2, &err);

	if (err) {
		printf("SDIV failed: %s\n", strerror(err));
		return (1);
	}

	if (rd != -512) {
		printf("rd (%ld) != -512\n", rd);
		return (1);
	}

	rd = dtapi_op_sdiv(dtapi_conf, 1024, 2, &err);

	if (err) {
		printf("SDIV failed: %s\n", strerror(err));
		return (1);
	}

	if (rd != 512) {
		printf("rd (%ld) != 512\n", rd);
		return (1);
	}

	rd = dtapi_op_sdiv(dtapi_conf, -1024, -2, &err);

	if (err) {
		printf("SDIV failed: %s\n", strerror(err));
		return (1);
	}

	if (rd != 512) {
		printf("rd (%ld) != 512\n", rd);
		return (1);
	}

	rd = dtapi_op_sdiv(dtapi_conf, 1024, 0, &err);

	if (err != EINVAL) {
		printf("SDIV failed (expected EINVAL): %s\n", strerror(err));
		return (1);
	}

	if (rd != 0) {
		printf("rd (%ld) != 512\n", rd);
		return (1);
	}

	dtapi_deinit(dtapi_conf);
	return (0);
}

