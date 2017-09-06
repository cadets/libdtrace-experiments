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
	 * Test the ntohs() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	dtapi_conf = dtapi_init(1000, 20, DTRACE_ACCESS_KERNEL);

	rd = dtapi_ntohs(dtapi_conf, 0x1234, &err);
	DTCHECK(err, ("NTOHS failed: %s\n", strerror(err)));
#if BYTE_ORDER == LITTLE_ENDIAN
	DTCHECK(rd != 0x3412, ("rd (%lx) != 0x3412\n", rd));
#else
	DTCHECK(rd != 0x1234, ("rd (%lx) != 0x1234\n", rd));
#endif

	dtapi_deinit(dtapi_conf);
	return (0);
}

