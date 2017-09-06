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
	 * Test the strlen() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	size_t rd;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = 0;

	rd = dtapi_strlen(dtapi_conf, "test", &err);
	DTCHECK(err, ("STRLEN failed: %s\n", strerror(err)));
	DTCHECK(rd != 4, ("rd (%zu) != 4\n", rd));

	rd = dtapi_strlen(dtapi_conf, NULL, &err);
	DTCHECK(err, ("STRLEN failed: %s\n", strerror(err)));
	DTCHECK(rd != 0, ("rd (%zu) != 0\n", rd));

	rd = dtapi_strlen(dtapi_conf,
	    "abcdwoaifjaewijdoifjewoidjefoiwjdoie"
	    "wfjewoijdeoifjewoidjewoifjweodijeiwof"
	    "aweodfiowjfoiewjiodewoifjiewjfoewijde"
	    "wjfewoijdoiwejfoiwjdoiwjofiwejdiweoif"
	    "jweodjioefjioewjdiojewoifjioewjaodfae"
	    "wofjowedijfewoifjewodjewiodeiuwahdeiw", &err);
	DTCHECK(err, ("STRLEN failed: %s\n", strerror(err)));
	DTCHECK(rd != 20, ("rd (%zu) != 20\n", rd));

	dtapi_deinit(dtapi_conf);
	return (0);
}

