#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

#include "dtcheck.h"

int
main(void)
{
	/*
	 * Test an unknown variable.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);

	rd = dtapi_var_arbitrary(dtapi_conf, DIF_VAR_OTHER_UBASE - 1,  &err);
	DTCHECK(err, ("Getting %d failed: %s\n", DIF_VAR_OTHER_UBASE - 1, strerror(err)));
	DTCHECK(rd != EOPNOTSUPP, ("rd (%lu) != EOPNOTSUPP\n", rd)); 

	dtapi_deinit(dtapi_conf);
	return (0);
}

