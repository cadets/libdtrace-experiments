/*-
* Copyright (c) 2017 Domagoj Stolfa
* All rights reserved.
*
* This software was developed by BAE Systems, the University of Cambridge
* Computer Laboratory, and Memorial University under DARPA/AFRL contract
* FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
* (TC) research program.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"

#include "dtrace_api.h"

#define	INTTAB_SIZE	100

struct dtapi_conf {
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dtapi_state_t *dstate;
};

/*
 * Currently we just assume kernel access.
 */
dtapi_conf_t *
dtapi_init_full(size_t scratch_size, size_t strsize,
    uint32_t access, const uint64_t *inttab, const char *strtab)
{
	dtapi_conf_t *conf;
	char *scratch;

	conf = calloc(1, sizeof(dtapi_conf_t));
	conf->mstate = calloc(1, sizeof (dtrace_mstate_t));
	conf->vstate = calloc(1, sizeof (dtrace_vstate_t));
	conf->state = calloc(1, sizeof (dtrace_state_t));
	conf->estate = calloc(1, sizeof (dtrace_estate_t));
	conf->dstate = calloc(1, sizeof (dtrace_dstate_t));

	scratch = calloc(1, scratch_size);

	conf->mstate->dtms_scratch_base = (uintptr_t) scratch;
	conf->mstate->dtms_scratch_ptr = (uintptr_t) scratch;
	conf->mstate->dtms_scratch_size = scratch_size;
	conf->mstate->dtms_access = access;

	conf->state->dts_options[DTRACEOPT_STRSIZE] = strsize;

	conf->estate->dtes_regs[DIF_REG_R0] = 0;
	conf->estate->dtes_inttab = inttab;
	conf->estate->dtes_strtab = strtab;

	return (conf);
}

dtapi_conf_t *
dtapi_init(size_t scratch_size, size_t strsize, uint32_t access)
{

	return (dtapi_init_full(scratch_size, strsize, access, NULL, NULL));
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

void
dtapi_set_textlen(dtapi_conf_t *conf, uint_t textlen)
{

	conf->estate->dtes_textlen = textlen;
}

dtapi_state_t *
dtapi_getstate(dtapi_conf_t *conf)
{

	return (conf->dstate);
}

void
dtapi_op_nop(dtapi_conf_t *conf, int *err)
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

	instr = DIF_INSTR_FMT(DIF_OP_NOP, 1, 2, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);
}

uint_t
dtapi_op_ret(dtapi_conf_t *conf, int *err)
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

	instr = DIF_INSTR_FMT(DIF_OP_RET, 1, 2, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return (estate->dtes_pc);
}

static uint64_t
dtapi_reg_op(dtapi_conf_t *conf, uint64_t r1,
    uint64_t r2, uint64_t rd, uint64_t r1_val,
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

	estate->dtes_regs[r1] = r1_val;
	estate->dtes_regs[r2] = r2_val;
	estate->dtes_regs[DIF_REG_R0] = 0;

	instr = DIF_INSTR_FMT(op, r1, r2, rd);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return (estate->dtes_regs[rd]);
}

uint64_t
dtapi_op_or(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_OR));
}

uint64_t
dtapi_op_xor(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_XOR));
}

uint64_t
dtapi_op_and(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_AND));
}

uint64_t
dtapi_op_sll(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_SLL));
}

uint64_t
dtapi_op_srl(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_SRL));
}

uint64_t
dtapi_op_sra(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_SRA));
}

uint64_t
dtapi_op_sub(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_SUB));
}

uint64_t
dtapi_op_add(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_ADD));
}

uint64_t
dtapi_op_mul(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_MUL));
}

uint64_t
dtapi_op_sdiv(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_SDIV));
}

uint64_t
dtapi_op_udiv(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_UDIV));
}

uint64_t
dtapi_op_srem(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_SREM));
}

uint64_t
dtapi_op_urem(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 2, 3, r1_val, r2_val, err, DIF_OP_UREM));
}

uint64_t
dtapi_op_not(dtapi_conf_t *conf, uint64_t r1_val, int *err)
{

	return (dtapi_reg_op(conf, 1, 0, 3, r1_val, 0, err, DIF_OP_NOT));
}

uint64_t
dtapi_op_mov(dtapi_conf_t *conf, uint64_t r1_val, int *err)
{
	return (dtapi_reg_op(conf, 1, 0, 3, r1_val, 0, err, DIF_OP_MOV));
}

void
dtapi_op_cmp(dtapi_conf_t *conf, uint64_t r1_val,
    uint64_t r2_val, int *err)
{

	(void) dtapi_reg_op(conf, 1, 2, 0, r1_val, r2_val, err, DIF_OP_CMP);
	conf->dstate->cc_r = conf->estate->dtes_cc_r;
	conf->dstate->cc_c = conf->estate->dtes_cc_c;
	conf->dstate->cc_z = conf->estate->dtes_cc_z;
	conf->dstate->cc_n = conf->estate->dtes_cc_n;
	conf->dstate->cc_v = conf->estate->dtes_cc_v;
}

void
dtapi_op_scmp(dtapi_conf_t *conf, uintptr_t r1_val,
    uintptr_t r2_val, int *err)
{

	(void) dtapi_reg_op(conf, 1, 2, 0, r1_val, r2_val, err, DIF_OP_SCMP);
	conf->dstate->cc_r = conf->estate->dtes_cc_r;
	conf->dstate->cc_c = conf->estate->dtes_cc_c;
	conf->dstate->cc_z = conf->estate->dtes_cc_z;
	conf->dstate->cc_n = conf->estate->dtes_cc_n;
	conf->dstate->cc_v = conf->estate->dtes_cc_v;
}

void
dtapi_op_tst(dtapi_conf_t *conf, uint64_t r1_val, int *err)
{
	(void) dtapi_reg_op(conf, 1, 0, 0, r1_val, 0, err, DIF_OP_TST);
	conf->dstate->cc_r = conf->estate->dtes_cc_r;
	conf->dstate->cc_c = conf->estate->dtes_cc_c;
	conf->dstate->cc_z = conf->estate->dtes_cc_z;
	conf->dstate->cc_n = conf->estate->dtes_cc_n;
	conf->dstate->cc_v = conf->estate->dtes_cc_v;
}

static uint_t
dtapi_branch_op(dtapi_conf_t *conf, uint_t where, int *err, uint16_t op)
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

	instr = DIF_INSTR_BRANCH(op, where);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return (estate->dtes_pc);
}

uint_t
dtapi_op_ba(dtapi_conf_t *conf, uint_t where, int *err)
{

	return (dtapi_branch_op(conf, where, err, DIF_OP_BA));
}

uint_t
dtapi_op_be(dtapi_conf_t *conf, uint_t where, int *err)
{

	return (dtapi_branch_op(conf, where, err, DIF_OP_BE));
}

uint_t
dtapi_op_bne(dtapi_conf_t *conf, uint_t where, int *err)
{

	return (dtapi_branch_op(conf, where, err, DIF_OP_BNE));
}

uint_t
dtapi_op_bg(dtapi_conf_t *conf, uint_t where, int *err)
{

	return (dtapi_branch_op(conf, where, err, DIF_OP_BG));
}

uint_t
dtapi_op_bgu(dtapi_conf_t *conf, uint_t where, int *err)
{

	return (dtapi_branch_op(conf, where, err, DIF_OP_BGU));
}

uint_t
dtapi_op_bge(dtapi_conf_t *conf, uint_t where, int *err)
{

	return (dtapi_branch_op(conf, where, err, DIF_OP_BGE));
}

uint_t
dtapi_op_bgeu(dtapi_conf_t *conf, uint_t where, int *err)
{

	return (dtapi_branch_op(conf, where, err, DIF_OP_BGEU));
}

uint_t
dtapi_op_bl(dtapi_conf_t *conf, uint_t where, int *err)
{

	return (dtapi_branch_op(conf, where, err, DIF_OP_BL));
}

uint_t
dtapi_op_blu(dtapi_conf_t *conf, uint_t where, int *err)
{

	return (dtapi_branch_op(conf, where, err, DIF_OP_BLU));
}

uint_t
dtapi_op_ble(dtapi_conf_t *conf, uint_t where, int *err)
{

	return (dtapi_branch_op(conf, where, err, DIF_OP_BLE));
}

uint_t
dtapi_op_bleu(dtapi_conf_t *conf, uint_t where, int *err)
{

	return (dtapi_branch_op(conf, where, err, DIF_OP_BLEU));
}

static uint64_t
dtapi_op_load(dtapi_conf_t *conf, uint64_t var, int *err, uint16_t op)
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

	estate->dtes_regs[1] = (uintptr_t) &var;

	instr = DIF_INSTR_LOAD(op, 1, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return (estate->dtes_regs[3]);
}

uint64_t
dtapi_op_ldsb(dtapi_conf_t *conf, int8_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_LDSB));
}

uint64_t
dtapi_op_ldsh(dtapi_conf_t *conf, int16_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_LDSH));
}

uint64_t
dtapi_op_ldsw(dtapi_conf_t *conf, int32_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_LDSW));
}

uint64_t
dtapi_op_ldub(dtapi_conf_t *conf, uint8_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_LDUB));
}

uint64_t
dtapi_op_lduh(dtapi_conf_t *conf, uint16_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_LDUH));
}

uint64_t
dtapi_op_lduw(dtapi_conf_t *conf, uint32_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_LDUW));
}

uint64_t
dtapi_op_ldx(dtapi_conf_t *conf, uint64_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_LDX));
}

uint64_t
dtapi_op_rldsb(dtapi_conf_t *conf, int8_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_RLDSB));
}

uint64_t
dtapi_op_rldsh(dtapi_conf_t *conf, int16_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_RLDSH));
}

uint64_t
dtapi_op_rldsw(dtapi_conf_t *conf, int32_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_RLDSW));
}

uint64_t
dtapi_op_rldub(dtapi_conf_t *conf, uint8_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_RLDUB));
}

uint64_t
dtapi_op_rlduh(dtapi_conf_t *conf, uint16_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_RLDUH));
}

uint64_t
dtapi_op_rlduw(dtapi_conf_t *conf, uint32_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_RLDUW));
}

uint64_t
dtapi_op_rldx(dtapi_conf_t *conf, uint64_t var, int *err)
{

	return (dtapi_op_load(conf, var, err, DIF_OP_RLDX));
}

static uint64_t
dif_op_ldga(dtapi_conf_t *conf, uint64_t var,
    uint64_t r2, int *err)
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

	instr = DIF_INSTR_FMT(DIF_OP_LDGA, var, r2, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return (estate->dtes_regs[3]);
}

static uint64_t
dif_op_ldgs(dtapi_conf_t *conf, uint64_t var, int *err)
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

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, var, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return (estate->dtes_regs[3]);
}

uint64_t
dtapi_var_args(dtapi_conf_t *conf, uint64_t arg[5], uint64_t idx,
    dtrace_id_t probeid, int *err)
{
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dtrace_probe_t *probe;
	dif_instr_t instr;

	mstate = conf->mstate;
	vstate = conf->vstate;
	state = conf->state;
	estate = conf->estate;

	memcpy(mstate->dtms_arg, arg, sizeof(uint64_t) * 5);
	mstate->dtms_probe = dtrace_getprobe(probeid);
	mstate->dtms_present |= DTRACE_MSTATE_ARGS;

	estate->dtes_regs[2] = idx;

	return (dif_op_ldga(conf, DIF_VAR_ARGS, 2, err));
}

void	
dtapi_var_set_epid(dtapi_conf_t *conf, uint64_t val)
{

	conf->mstate->dtms_epid = val;
}

uint64_t
dtapi_var_epid(dtapi_conf_t *conf, int *err)
{
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dtrace_probe_t *probe;
	dif_instr_t instr;

	mstate = conf->mstate;
	vstate = conf->vstate;
	state = conf->state;
	estate = conf->estate;

	mstate->dtms_present |= DTRACE_MSTATE_EPID;

	return (dif_op_ldgs(conf, DIF_VAR_EPID, err));
}

void	
dtapi_set_probe(dtapi_conf_t *conf, dtrace_id_t probeid)
{

	conf->mstate->dtms_probe = dtrace_getprobe(probeid);
}

uint64_t
dtapi_var_id(dtapi_conf_t *conf, int *err)
{

	conf->mstate->dtms_present |= DTRACE_MSTATE_PROBE;
	return (dif_op_ldgs(conf, DIF_VAR_ID, err));
}

static char *
dtapi_var_probeX(dtapi_conf_t *conf, uint64_t var, int *err)
{

	conf->mstate->dtms_present |= DTRACE_MSTATE_PROBE;
	return ((char *)dif_op_ldgs(conf, var, err));
}

char *
dtapi_var_probeprov(dtapi_conf_t *conf, int *err)
{

	return (dtapi_var_probeX(conf, DIF_VAR_PROBEPROV, err));
}

char *
dtapi_var_probemod(dtapi_conf_t *conf, int *err)
{

	return (dtapi_var_probeX(conf, DIF_VAR_PROBEMOD, err));
}

char *
dtapi_var_probefunc(dtapi_conf_t *conf, int *err)
{

	return (dtapi_var_probeX(conf, DIF_VAR_PROBEFUNC, err));
}

char *
dtapi_var_probename(dtapi_conf_t *conf, int *err)
{

	return (dtapi_var_probeX(conf, DIF_VAR_PROBENAME, err));
}

pid_t
dtapi_var_pid(dtapi_conf_t *conf, int *err)
{

	conf->state->dts_cred.dcr_action |= DTRACE_CRA_PROC;
	return (dif_op_ldgs(conf, DIF_VAR_PID, err));
}

pid_t
dtapi_var_ppid(dtapi_conf_t *conf, int *err)
{

	conf->state->dts_cred.dcr_action |= DTRACE_CRA_PROC;
	return (dif_op_ldgs(conf, DIF_VAR_PPID, err));
}

uint64_t
dtapi_var_tid(dtapi_conf_t *conf, int *err)
{

	return (dif_op_ldgs(conf, DIF_VAR_TID, err));
}

char *
dtapi_var_execname(dtapi_conf_t *conf, int *err)
{

	return ((char *)dif_op_ldgs(conf, DIF_VAR_EXECNAME, err));
}

uid_t
dtapi_var_uid(dtapi_conf_t *conf, int *err)
{

	conf->state->dts_cred.dcr_action |= DTRACE_CRA_PROC;
	return (dif_op_ldgs(conf, DIF_VAR_UID, err));
}

gid_t
dtapi_var_gid(dtapi_conf_t *conf, int *err)
{

	conf->state->dts_cred.dcr_action |= DTRACE_CRA_PROC;
	return (dif_op_ldgs(conf, DIF_VAR_GID, err));
}

errno_t
dtapi_var_errno(dtapi_conf_t *conf, int *err)
{

	return (dif_op_ldgs(conf, DIF_VAR_ERRNO, err));
}

uint64_t
dtapi_var_arbitrary(dtapi_conf_t *conf, uint64_t var, int *err)
{

	return (dif_op_ldgs(conf, var, err));
}

uint64_t
dtapi_op_setx(dtapi_conf_t *conf, uint64_t index, int *err)
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

	instr = DIF_INSTR_SETX(index, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return (estate->dtes_regs[3]);
}

/*
 * We keep SETX and SETS separated in the case where the virtual address is not
 * a pointer, as it will allow us to more easily abstract that away without then
 * having to break it up in two functions.
 */
uint64_t
dtapi_op_sets(dtapi_conf_t *conf, uint64_t index, int *err)
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

	instr = DIF_INSTR_SETS(index, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	return (estate->dtes_regs[3]);
}

void
dtapi_op_pushtr(dtapi_conf_t *conf, uint8_t type,
    uint64_t size, uint64_t ptr, int *err)
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

	estate->dtes_regs[2] = size;
	estate->dtes_regs[3] = ptr;

	instr = DIF_INSTR_FMT(DIF_OP_PUSHTR, type, 2, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);
}

void
dtapi_op_pushtv(dtapi_conf_t *conf, uint64_t val, int *err)
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

	estate->dtes_regs[3] = val;

	instr = DIF_INSTR_FMT(DIF_OP_PUSHTV, 0, 0, 3);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);
}

void
dtapi_op_popts(dtapi_conf_t *conf, int *err)
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

	instr = DIF_INSTR_FMT(DIF_OP_POPTS, 0, 0, 0);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);
}

void
dtapi_op_flushts(dtapi_conf_t *conf, int *err)
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

	instr = DIF_INSTR_FMT(DIF_OP_FLUSHTS, 0, 0, 0);
	*err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);
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

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 0, 3);
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

