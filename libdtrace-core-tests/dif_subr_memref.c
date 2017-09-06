#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

#include "dtcheck.h"

int
main(void)
{
	/*
	 * Test the memref() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	const char *str = "hello world";
	uintptr_t *rd;
	size_t str_len;
	int err;

	str_len = strlen(str);

	dtapi_conf = dtapi_init(1000, 50, DTRACE_ACCESS_KERNEL);

	rd = dtapi_memref(dtapi_conf, (uintptr_t) str, str_len, &err);
	DTCHECK(err, ("MEMREF failed: %s\n", strerror(err)));
	DTCHECK(rd[0] != (uintptr_t) str, ("rd[0] (%" PRIuPTR ") != %p\n", rd[0], str));
	DTCHECK(rd[1] != str_len, ("rd[1] (%zu) != %zu\n", rd[1], str_len));

	dtapi_deinit(dtapi_conf);
	return (0);
}

