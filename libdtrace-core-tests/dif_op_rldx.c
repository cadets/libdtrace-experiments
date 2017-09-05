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
	 * Test the RLDX operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	uint64_t var;
	uint64_t rd;

	var = 73;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_rldx(dtapi_conf, var, &err);

	DTCHECK(err, ("RLDX failed: %s\n", strerror(err)));
	DTCHECK(rd != 73,
	    ("rd (%lu) != 73\n", rd));

	var = 256;
	rd = dtapi_op_rldx(dtapi_conf, (uint32_t) var, &err);

	DTCHECK(err, ("RLDX failed: %s\n", strerror(err)));
	DTCHECK(rd != 256,
	    ("rd (%lu) != 256\n", rd));

	var = 1 << 16;
	rd = dtapi_op_rldx(dtapi_conf, (uint32_t) var, &err);

	DTCHECK(err, ("RLDX failed: %s\n", strerror(err)));
	DTCHECK(rd != 1 << 16,
	    ("rd (%lu) != 1 << 16\n", rd));

	var = 1ULL << 32;
	rd = dtapi_op_rldx(dtapi_conf, (uint32_t) var, &err);

	DTCHECK(err, ("RLDX failed: %s\n", strerror(err)));
	DTCHECK(rd != 0,
	    ("rd (%lu) != 0\n", rd));

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshift-count-overflow"
	var = 1ULL << 64;
#pragma clang diagnostic pop

	rd = dtapi_op_rldx(dtapi_conf, (uint32_t) var, &err);

	DTCHECK(err, ("RLDX failed: %s\n", strerror(err)));
	DTCHECK(rd != 0,
	    ("rd (%lu) != 0\n", rd));

	dtapi_deinit(dtapi_conf);

	return (0);
}

