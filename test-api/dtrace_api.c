#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"

#include "dtrace_api.h"

size_t
dtapi_strlen(const char *s, int *err)
{
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	size_t retsize;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 20;

	estate->dtes_ttop = 0;
	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[3] = (uint64_t) s;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	/*
	 * Given the current specification, PUSHTR can not return an error.
	 */
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_CALL(DIF_SUBR_STRLEN, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);
	assert(estate->dtes_regs[3] == 4);
	
	retsize = estate->dtes_regs[3];

	free(mstate);
	free(vstate);
	free(state);
	free(estate);

	return (retsize);
}

void
dtapi_bcopy(const void *src, const void *dst, size_t len, int *err)
{

}

char *
dtapi_strchr(const char *s, int c, int *err)
{

}

char *
dtapi_strrchr(const char *s, int c, int *err)
{

}

char *
dtapi_strstr(const char *big, const char *little, int *err)
{

}

char *
dtapi_strtok(char *str, const char *sep, int *err)
{

}

char *
dtapi_substr(const char *s, size_t index, size_t len, int *err)
{

}

char *
dtapi_toupper(const char *s, int *err)
{

}

char *
dtapi_tolower(const char *s, int *err)
{

}

char *
dtapi_strjoin(const char *first, const char *second, int *err)
{

}

long long
dtapi_strtoll(const char *s, int *err)
{

}

char *
dtapi_lltostr(long long num, int *err)
{

}

uint16_t
dtapi_htons(uint16_t hostshort, int *err)
{

}

uint32_t
dtapi_htonl(uint32_t hostlong, int *err)
{

}

uint64_t
dtapi_htonll(uint64_t hostlonglong, int *err)
{

}

uint16_t
dtapi_ntohs(uint16_t netshort, int *err)
{

}

uint32_t
dtapi_ntohl(uint32_t netlong, int *err)
{

}

uint64_t
dtapi_ntohll(uint64_t netlonglong, int *err)
{

}

char *
dtapi_basename(const char *path, int *err)
{

}

char *
dtapi_dirname(const char *path, int *err)
{

}

char *
dtapi_cleanpath(const char *path, int *err)
{

}

uintptr_t *
dtapi_memref(uintptr_t ptr, int *err)
{

}
