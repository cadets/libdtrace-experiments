#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"

#include "dtrace_api.h"

struct dtapi_conf {
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
};

/*
 * Currently we just assume kernel access.
 */
dtapi_conf_t *
dtapi_init(size_t scratch_size, size_t strsize, uint32_t access)
{
	dtapi_conf_t *conf;
	char *scratch;

	conf = calloc(1, sizeof(dtapi_conf_t));
	conf->mstate = calloc(1, sizeof (dtrace_mstate_t));
	conf->vstate = calloc(1, sizeof (dtrace_vstate_t));
	conf->state = calloc(1, sizeof (dtrace_state_t));
	conf->estate = calloc(1, sizeof (dtrace_estate_t));

	scratch = calloc(1, scratch_size);

	conf->mstate->dtms_scratch_base = (uintptr_t) scratch;
	conf->mstate->dtms_scratch_ptr = (uintptr_t) scratch;
	conf->mstate->dtms_scratch_size = scratch_size;
	conf->mstate->dtms_access = access;

	conf->state->dts_options[DTRACEOPT_STRSIZE] = strsize;

	conf->estate->dtes_regs[DIF_REG_R0] = 0;

	return (conf);
}

void
dtapi_deinit(dtapi_conf_t *conf)
{
	free((void *) conf->mstate->dtms_scratch_base);
	free(conf->mstate);
	free(conf->vstate);
	free(conf->state);
	free(conf->estate);
}

size_t
dtapi_strlen(dtapi_conf_t *conf, const char *s, int *err)
{
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;

	mstate = conf->mstate;
	vstate = conf->vstate;
	state = conf->state;
	estate = conf->estate;

	state->dts_options[DTRACEOPT_STRSIZE] = 20;

	estate->dtes_regs[3] = (uint64_t) s;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_CALL(DIF_SUBR_STRLEN, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);
	
	return (estate->dtes_regs[3]);
}

void *
dtapi_bcopy(dtapi_conf_t *conf, const void *src,
    size_t len, int *err)
{
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	void *dst;

	mstate = conf->mstate;
	vstate = conf->vstate;
	state = conf->state;
	estate = conf->estate;

	estate->dtes_regs[1] = len;
	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_ALLOCS(1, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);
	if (estate->dtes_regs[3] == 0) {
		*err = ENOMEM;
		return (NULL);
	}

	dst = (void *) estate->dtes_regs[3];

	estate->dtes_regs[3] = (uint64_t) src;
	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 0, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = (uint64_t) dst;
	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 0, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[2] = sizeof(size_t);
	estate->dtes_regs[3] = len;
	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_CALL(DIF_SUBR_BCOPY, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return (dst);
}

static char *
dtapi_strchr_generic(dtapi_conf_t *conf, const char *s,
    int c, int *err, uint16_t subr)
{
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;

	mstate = conf->mstate;
	vstate = conf->vstate;
	state = conf->state;
	estate = conf->estate;

	estate->dtes_regs[3] = (uint64_t) s;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = c;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 0, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_CALL(subr, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return ((char *) estate->dtes_regs[3]);
}

char *
dtapi_strchr(dtapi_conf_t *conf, const char *s, int c, int *err)
{
	return (dtapi_strchr_generic(conf, s, c, err, DIF_SUBR_STRCHR));
}

char *
dtapi_strrchr(dtapi_conf_t *conf, const char *s, int c, int *err)
{
	return (dtapi_strchr_generic(conf, s, c, err, DIF_SUBR_STRRCHR));
}

char *
dtapi_strstr(dtapi_conf_t *conf, const char *big, const char *little, int *err)
{
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;

	mstate = conf->mstate;
	vstate = conf->vstate;
	state = conf->state;
	estate = conf->estate;

	estate->dtes_regs[3] = (uint64_t) big;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = (uint64_t) little;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 0xBAAAAAAAD;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRSTR, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return ((char *) estate->dtes_regs[3]);
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
