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

static uint64_t
dtapi_reg_op(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err, uint16_t op)
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

	estate->dtes_regs[1] = r1_val;
	estate->dtes_regs[2] = r2_val;

	instr = DIF_INSTR_FMT(op, 1, 2, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return (estate->dtes_regs[3]);
}

uint64_t
dtapi_op_or(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, r1_val, r2_val, err, DIF_OP_OR));
}

uint64_t
dtapi_op_xor(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, r1_val, r2_val, err, DIF_OP_XOR));
}

uint64_t
dtapi_op_and(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, r1_val, r2_val, err, DIF_OP_AND));
}

uint64_t
dtapi_op_sll(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, r1_val, r2_val, err, DIF_OP_SLL));
}

uint64_t
dtapi_op_srl(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, r1_val, r2_val, err, DIF_OP_SRL));
}

uint64_t
dtapi_op_sub(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, r1_val, r2_val, err, DIF_OP_SUB));
}

uint64_t
dtapi_op_add(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, r1_val, r2_val, err, DIF_OP_ADD));
}

uint64_t
dtapi_op_mul(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, r1_val, r2_val, err, DIF_OP_MUL));
}

uint64_t
dtapi_op_sdiv(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, r1_val, r2_val, err, DIF_OP_SDIV));
}

uint64_t
dtapi_op_udiv(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, r1_val, r2_val, err, DIF_OP_UDIV));
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

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);
	
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

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

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

	instr = DIF_INSTR_CALL(subr, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

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

	instr = DIF_INSTR_CALL(DIF_SUBR_STRSTR, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return ((char *) estate->dtes_regs[3]);
}

char *
dtapi_strtok(dtapi_conf_t *conf, char *str, const char *sep, int *err)
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

	estate->dtes_regs[3] = (uint64_t) str;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = (uint64_t) sep;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_CALL(DIF_SUBR_STRTOK, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_tupregs[0].dttk_value = 0;
	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRTOK, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return ((char *) estate->dtes_regs[3]);
}

char *
dtapi_substr(dtapi_conf_t *conf, const char *s,
    size_t index, size_t len, int *err)
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

	estate->dtes_regs[3] = index;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = len;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_CALL(DIF_SUBR_SUBSTR, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return ((char *) estate->dtes_regs[3]);
}

static char *
dtapi_tox(dtapi_conf_t *conf, const char *s, int *err, uint16_t subr)
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
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_CALL(subr, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return ((char *) estate->dtes_regs[3]);
}

char *
dtapi_toupper(dtapi_conf_t *conf, const char *s, int *err)
{
	return (dtapi_tox(conf, s, err, DIF_SUBR_TOUPPER));
}

char *
dtapi_tolower(dtapi_conf_t *conf, const char *s, int *err)
{
	return (dtapi_tox(conf, s, err, DIF_SUBR_TOLOWER));
}

char *
dtapi_strjoin(dtapi_conf_t *conf, const char *first, const char *second, int *err)
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

	estate->dtes_regs[3] = (uint64_t) first;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = (uint64_t) second;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_CALL(DIF_SUBR_STRJOIN, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return ((char *) estate->dtes_regs[3]);
}

int64_t
dtapi_strtoll(dtapi_conf_t *conf, const char *s, int *err)
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

	instr = DIF_INSTR_CALL(DIF_SUBR_STRTOLL, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return (estate->dtes_regs[3]);
}

char *
dtapi_lltostr(dtapi_conf_t *conf, int64_t num, int *err)
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

	estate->dtes_regs[3] = num;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_CALL(DIF_SUBR_LLTOSTR, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return ((char *) estate->dtes_regs[3]);
}

static uint64_t
dtapi_xtoyz(dtapi_conf_t *conf, uint64_t x, int *err, uint16_t subr)
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

	estate->dtes_regs[3] = x;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_CALL(subr, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return (estate->dtes_regs[3]);
}

uint16_t
dtapi_htons(dtapi_conf_t *conf, uint16_t hostshort, int *err)
{

	return (dtapi_xtoyz(conf, hostshort, err, DIF_SUBR_HTONS));
}

uint32_t
dtapi_htonl(dtapi_conf_t *conf, uint32_t hostlong, int *err)
{

	return (dtapi_xtoyz(conf, hostlong, err, DIF_SUBR_HTONL));
}

uint64_t
dtapi_htonll(dtapi_conf_t *conf, uint64_t hostlonglong, int *err)
{

	return (dtapi_xtoyz(conf, hostlonglong, err, DIF_SUBR_HTONLL));
}

uint16_t
dtapi_ntohs(dtapi_conf_t *conf, uint16_t netshort, int *err)
{

	return (dtapi_xtoyz(conf, netshort, err, DIF_SUBR_NTOHS));
}

uint32_t
dtapi_ntohl(dtapi_conf_t *conf, uint32_t netlong, int *err)
{

	return (dtapi_xtoyz(conf, netlong, err, DIF_SUBR_NTOHL));
}

uint64_t
dtapi_ntohll(dtapi_conf_t *conf, uint64_t netlonglong, int *err)
{

	return (dtapi_xtoyz(conf, netlonglong, err, DIF_SUBR_NTOHLL));
}

static char *
dtapi_pathop(dtapi_conf_t *conf, const char *path, int *err, uint16_t subr)
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

	estate->dtes_regs[3] = (uint64_t) path;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_CALL(subr, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return ((char *) estate->dtes_regs[3]);
}

char *
dtapi_basename(dtapi_conf_t *conf, const char *path, int *err)
{

	return (dtapi_pathop(conf, path, err, DIF_SUBR_BASENAME));
}

char *
dtapi_dirname(dtapi_conf_t *conf, const char *path, int *err)
{

	return (dtapi_pathop(conf, path, err, DIF_SUBR_DIRNAME));
}

char *
dtapi_cleanpath(dtapi_conf_t *conf, const char *path, int *err)
{

	return (dtapi_pathop(conf, path, err, DIF_SUBR_CLEANPATH));
}

uintptr_t *
dtapi_memref(dtapi_conf_t *conf, uintptr_t ptr, size_t len, int *err)
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

	estate->dtes_regs[3] = (uint64_t) ptr;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = len;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 2, 3);
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_CALL(DIF_SUBR_MEMREF, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	instr = DIF_INSTR_FLUSHTS;
	(void) dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return ((uintptr_t *) estate->dtes_regs[3]);
}
