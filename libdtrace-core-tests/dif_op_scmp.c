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
	 * Test the SSCMP operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);

	dtapi_op_scmp(dtapi_conf, (uintptr_t) "foo", (uintptr_t) "foo", &err);
	DTCHECK(err, ("SCMP failed: %s\n", strerror(err)));

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

	dtapi_op_scmp(dtapi_conf, (uintptr_t) "foo", (uintptr_t) "eoo", &err);
	DTCHECK(err, ("SCMP failed: %s\n", strerror(err)));

	dtapi_state = dtapi_getstate(dtapi_conf);

	DTCHECK(dtapi_state->cc_r != ('f' - 'e'),
	    ("cc_r (%ld) != ('f' - 'e')\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_n != ('f' - 'e' < 0),
	    ("cc_n (%ld) != ('f' - 'e' < 0)\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_z != ('f' - 'e' == 0),
	    ("cc_z (%hhu) != ('f' - 'e' == 0)\n", dtapi_state->cc_z));
	DTCHECK(dtapi_state->cc_v != 0,
	    ("cc_v (%hhu) != 0\n", dtapi_state->cc_v));
	DTCHECK(dtapi_state->cc_c != 0,
	    ("cc_c (%hhu) != 0\n", dtapi_state->cc_c));

	dtapi_op_scmp(dtapi_conf, (uintptr_t) "eoo", (uintptr_t) "foo", &err);
	DTCHECK(err, ("SCMP failed: %s\n", strerror(err)));

	dtapi_state = dtapi_getstate(dtapi_conf);

	DTCHECK(dtapi_state->cc_r != ('e' - 'f'),
	    ("cc_r (%ld) != ('e' - 'f')\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_n != ('e' - 'f' < 0),
	    ("cc_n (%ld) != ('e' - 'f' < 0)\n", dtapi_state->cc_r));
	DTCHECK(dtapi_state->cc_z != ('e' - 'f' == 0),
	    ("cc_z (%hhu) != ('e' - 'f' == 0)\n", dtapi_state->cc_z));
	DTCHECK(dtapi_state->cc_v != 0,
	    ("cc_v (%hhu) != 0\n", dtapi_state->cc_v));
	DTCHECK(dtapi_state->cc_c != 0,
	    ("cc_c (%hhu) != 1\n", dtapi_state->cc_c));

	dtapi_deinit(dtapi_conf);
	return (0);
}


