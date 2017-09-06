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
	 * Test the ntohl() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	dtapi_conf = dtapi_init(1000, 20, DTRACE_ACCESS_KERNEL);

	rd = dtapi_ntohl(dtapi_conf, 0x12345600, &err);
	DTCHECK(err, ("NTOHL failed: %s\n", strerror(err)));
#if BYTE_ORDER == LITTLE_ENDIAN
	DTCHECK(rd != 0x563412, ("rd (%lx) != 0x563412\n", rd));
#else
	DTCHECK(rd != 0x12345600, ("rd (%lx) != 0x12345600\n", rd));
#endif

	dtapi_deinit(dtapi_conf);
	return (0);
}

