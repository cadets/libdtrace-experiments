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
	 * Test the htons() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	dtapi_conf = dtapi_init(1000, 20, DTRACE_ACCESS_KERNEL);

#if BYTE_ORDER == LITTLE_ENDIAN
	rd = dtapi_htons(dtapi_conf, 0x1234, &err);
#else
	rd = dtapi_htons(dtapi_conf, 0x3412, &err);
#endif
	DTCHECK(err, ("HTONS failed: %s\n", strerror(err)));
	DTCHECK(rd != 0x3412, ("rd (%lx) != 0x3412\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

