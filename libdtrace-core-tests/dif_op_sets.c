#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

#include "dtcheck.h"

#define	N_ENTRIES	(1 << 7)

int
main(void)
{
	/*
	 * Test the SETS operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;
	char *strtab;

	strtab = malloc(N_ENTRIES * 32);
	DTCHECK(strtab == NULL, ("malloc failed: %s\n", strerror(errno)));

	strcpy(strtab, "teststring");

	dtapi_conf = dtapi_init_full(100, 32, DTRACE_ACCESS_KERNEL, NULL, strtab);

	rd = dtapi_op_sets(dtapi_conf, 0, &err);
	DTCHECK(err, ("SETS failed: %s\n", strerror(err)));
	DTCHECK(strcmp((char *)rd, "teststring") != 0,
	    ("rd (%s) != teststring\n", (char *) rd));

	dtapi_deinit(dtapi_conf);

	free(strtab);
	return (0);
}

