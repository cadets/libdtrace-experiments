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
	 * Test the strchr() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	char *rd;
	const char *str = "hello world";
	char *str_nonnull;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = 0;

	rd = dtapi_strrchr(dtapi_conf, str, 'r', &err);
	DTCHECK(err, ("STRCHR failed: %s\n", strerror(err)));
	DTCHECK(rd - str != 8, ("rd (%p) != %p\n", rd, str + 8));

	rd = dtapi_strrchr(dtapi_conf, str, 'x', &err);
	DTCHECK(err, ("STRCHR failed: %s\n", strerror(err)));
	DTCHECK(rd != NULL, ("rd (%p) != NULL\n", rd));

	str_nonnull = malloc(11);
	strcpy(str_nonnull, "hello world");
	rd = dtapi_strrchr(dtapi_conf, str_nonnull, 'x', &err);
	DTCHECK(err, ("STRCHR failed: %s\n", strerror(err)));
	DTCHECK(rd != NULL, ("rd (%p) != NULL\n", rd));
	free(str_nonnull);

	dtapi_deinit(dtapi_conf);
	return (0);
}

