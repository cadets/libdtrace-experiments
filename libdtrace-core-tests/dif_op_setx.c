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
	 * Test the SETX operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;
	size_t i;
	uint64_t *inttab;

	inttab = calloc(N_ENTRIES, sizeof(uint64_t));
	DTCHECK(inttab == NULL, ("calloc failed: %s\n", strerror(errno)));

	for (i = 0; i < N_ENTRIES; i++) {
		inttab[i] = arc4random();
	}

	dtapi_conf = dtapi_init_full(100, 20, DTRACE_ACCESS_KERNEL, inttab, NULL);

	for (i = 0; i < N_ENTRIES; i++) {
		rd = dtapi_op_setx(dtapi_conf, i, &err);
		DTCHECK(err, ("SETX failed: %s\n", strerror(err)));
		DTCHECK(rd != inttab[i], ("rd (%lu) != %lu\n", rd, inttab[i]));
	}

	dtapi_deinit(dtapi_conf);

	free(inttab);
	return (0);
}

