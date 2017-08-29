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
	 * Test the CMP operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);

	dtapi_op_cmp(dtapi_conf, 20, 5, &err);
	DTCHECK(err, ("CMP failed: %s\n", strerror(err)));

	dtapi_state = dtapi_getstate(dtapi_conf);

	DTCHECK(dtapi_state->cc_r != 15,
	    ("cc_r (%ld) != 15\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_n != 0,
	    ("cc_n (%ld) != 0\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_z != 0,
	    ("cc_z (%hhu) != 0\n", dtapi_state->cc_z));
	DTCHECK(dtapi_state->cc_v != 0,
	    ("cc_v (%hhu) != 0\n", dtapi_state->cc_v));
	DTCHECK(dtapi_state->cc_c != 0,
	    ("cc_c (%hhu) != 0\n", dtapi_state->cc_c));

	dtapi_op_cmp(dtapi_conf, 20, 20, &err);
	DTCHECK(err, ("CMP failed: %s\n", strerror(err)));

	dtapi_state = dtapi_getstate(dtapi_conf);

	DTCHECK(dtapi_state->cc_r != 0,
	    ("cc_r (%ld) != 0\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_n != 0,
	    ("cc_n (%ld) != 0\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_z != 1,
	    ("cc_z (%hhu) != 1\n", dtapi_state->cc_z));
	DTCHECK(dtapi_state->cc_v != 0,
	    ("cc_v (%hhu) != 0\n", dtapi_state->cc_v));
	DTCHECK(dtapi_state->cc_c != 0,
	    ("cc_c (%hhu) != 0\n", dtapi_state->cc_c));

	dtapi_op_cmp(dtapi_conf, 10, 20, &err);
	DTCHECK(err, ("CMP failed: %s\n", strerror(err)));

	dtapi_state = dtapi_getstate(dtapi_conf);

	DTCHECK(dtapi_state->cc_r != -10,
	    ("cc_r (%ld) != -10\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_n != 1,
	    ("cc_n (%ld) != 1\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_z != 0,
	    ("cc_z (%hhu) != 0\n", dtapi_state->cc_z));
	DTCHECK(dtapi_state->cc_v != 0,
	    ("cc_v (%hhu) != 0\n", dtapi_state->cc_v));
	DTCHECK(dtapi_state->cc_c != 1,
	    ("cc_c (%hhu) != 1\n", dtapi_state->cc_c));

	dtapi_deinit(dtapi_conf);
	return (0);
}

