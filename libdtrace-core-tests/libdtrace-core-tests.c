#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <atf-c.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"

static void
dtrace_nullop(void)
{}

static dtrace_pops_t test_provider_ops = {
(void (*)(void *, dtrace_probedesc_t *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *, dtrace_argdesc_t *))dtrace_nullop,
/*(uint64_t (*)(void *, dtrace_id_t, void *, int, int))dtrace_nullop,*/
NULL,
(int (*)(void *, dtrace_id_t, void *))dtrace_nullop,
(void (*)(void *, dtrace_id_t, void *))dtrace_nullop
};

static dtrace_pattr_t test_provider_attr = {
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
};

ATF_TC_WITHOUT_HEAD(dtrace_init);
ATF_TC_BODY(dtrace_init, tc)
{
	/*
	 * Tests the initialization of the library
	 */
	int err;

	err = dtrace_init();
	ATF_CHECK_EQ(0, err);
}

ATF_TC_WITHOUT_HEAD(dtrace_deinit);
ATF_TC_BODY(dtrace_deinit, tc)
{
	/*
	 * Initializes the library and tests it's de-initialization
	 *
	 * NOTE: This also tests dtrace_unregister(), so it's not necessary to
	 * separately test it as a black box.
	 */
	int err;

	err = dtrace_init();
	if (err != 0)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));

	err = dtrace_deinit();

	ATF_CHECK_EQ(0, err);
}

ATF_TC_WITHOUT_HEAD(dtrace_providers);
ATF_TC_BODY(dtrace_providers, tc)
{
	/*
	 * Test the dtrace_providers() function
	 */
	char *provs;
	size_t sz;
	int err;

	err = dtrace_init();
	if (err != 0)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));

	provs = dtrace_providers(&sz);

	ATF_CHECK_EQ(1, sz);
	ATF_CHECK_STREQ("dtrace", provs);

	err = dtrace_deinit();
	if (err != 0)
		atf_tc_fail("DTrace not properly deinitialized: %s", strerror(err));
}

ATF_TC_WITHOUT_HEAD(dtrace_register);
ATF_TC_BODY(dtrace_register, tc)
{
	/*
	 * Test the provider registration
	 */
	dtrace_provider_id_t id;
	int err;
	size_t sz;
	char (*provs)[DTRACE_PROVNAMELEN];

	err = dtrace_init();
	if (err)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));

	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	ATF_CHECK_EQ(0, err);

	provs = (char (*)[DTRACE_PROVNAMELEN]) dtrace_providers(&sz);
	ATF_CHECK_EQ(2, sz);
	ATF_CHECK_STREQ(provs[0], "dtrace");
	ATF_CHECK_STREQ(provs[1], "test_provider");

	err = dtrace_unregister(id);
	ATF_CHECK_EQ(0, err);

	err = dtrace_deinit();
	if (err)
		atf_tc_fail("DTrace not properly deinitialized: %s", strerror(err));
}

ATF_TC_WITHOUT_HEAD(dtrace_probe_create);
ATF_TC_BODY(dtrace_probe_create, tc)
{
	/*
	 * Test probe creation
	 */
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	int err;

	err = dtrace_init();
	if (err)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));

	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	ATF_CHECK_EQ(0, err);

	probeid = dtrace_probe_create(id, "test", "probe",
	    "foo", 0, NULL);

	err = dtrace_unregister(id);
	ATF_CHECK_EQ(0, err);

	err = dtrace_deinit();
	if (err)
		atf_tc_fail("DTrace not properly deinitialized: %s", strerror(err));
}

ATF_TC_WITHOUT_HEAD(dtrace_probe_lookup);
ATF_TC_BODY(dtrace_probe_lookup, tc)
{
	/*
	 * Test probe creation
	 */
	dtrace_id_t probeid, lookupid;
	dtrace_provider_id_t id;
	int err;

	err = dtrace_init();
	if (err)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));

	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	ATF_CHECK_EQ(0, err);

	probeid = dtrace_probe_create(id, "test", "probe",
	    "foo", 0, NULL);
	lookupid = dtrace_probe_lookup(id, "test", "probe", "foo");
	ATF_CHECK_EQ(probeid, lookupid);

	err = dtrace_unregister(id);
	ATF_CHECK_EQ(0, err);

	err = dtrace_deinit();
	if (err)
		atf_tc_fail("DTrace not properly deinitialized: %s", strerror(err));
}

ATF_TC_WITHOUT_HEAD(dtrace_probe);
ATF_TC_BODY(dtrace_probe, tc)
{
	/*
	 * Test whether or not DTrace probe segfaults.
	 *
	 * TODO: Test the results of dtrace_probe() by trying to figure out
	 * whether or not the buffer snapshot is correct. We have to build an
	 * API for that.
	 */
	dtrace_id_t probeid, lookupid;
	dtrace_provider_id_t id;
	int err;

	err = dtrace_init();
	if (err)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));

	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	ATF_CHECK_EQ(0, err);

	probeid = dtrace_probe_create(id, "test", "probe",
	    "foo", 0, NULL);

	lookupid = dtrace_probe_lookup(id, "test", "probe", "foo");
	ATF_CHECK_EQ(probeid, lookupid);

	dtrace_probe(probeid, 0, 0, 0, 0, 0);

	err = dtrace_unregister(id);
	ATF_CHECK_EQ(0, err);

	err = dtrace_deinit();
	if (err)
		atf_tc_fail("DTrace not properly deinitialized: %s", strerror(err));
}

/*
 * We define _DTRACE_TESTS in order to be able to test the DIF interpreter and
 * various other things that should usually not be exposed to the clients of the
 * library.
 */
#ifdef _DTRACE_TESTS

ATF_TC_WITHOUT_HEAD(DIF_OP_NOP);
ATF_TC_BODY(DIF_OP_NOP, tc)
{
	/*
	 * Test the NOP operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	uint64_t regs[DIF_DIR_NREGS];
	const uint64_t *inttab;
	const char *strtab;
	uint64_t rval;
	int64_t cc_r;
	uint_t pc;
	uint_t textlen;
	uint8_t cc_c;
	uint8_t cc_n;
	uint8_t cc_v;
	uint8_t cc_z;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	pc = estate->dtes_pc = 0;
	regs[DIF_REG_R0] = estate->dtes_regs[DIF_REG_R0] = 0;
	regs[1] = estate->dtes_regs[1] = 0;
	regs[2] = estate->dtes_regs[2] = 0;
	regs[3] = estate->dtes_regs[3] = 0;
	cc_c = estate->dtes_cc_c = 0;
	cc_v = estate->dtes_cc_v = 0;
	cc_n = estate->dtes_cc_n = 0;
	cc_z = estate->dtes_cc_z = 0;
	cc_r = estate->dtes_cc_r = 0;
	textlen = estate->dtes_textlen = 100;
	inttab = estate->dtes_inttab = NULL;
	strtab = estate->dtes_strtab = NULL;

	instr = DIF_INSTR_FMT(DIF_OP_NOP, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(pc, estate->dtes_pc);
	ATF_CHECK_EQ(regs[DIF_REG_R0], estate->dtes_regs[DIF_REG_R0]);
	ATF_CHECK_EQ(regs[1], estate->dtes_regs[1]);
	ATF_CHECK_EQ(regs[2], estate->dtes_regs[2]);
	ATF_CHECK_EQ(regs[3], estate->dtes_regs[3]);
	ATF_CHECK_EQ(cc_c, estate->dtes_cc_c);
	ATF_CHECK_EQ(cc_v, estate->dtes_cc_v);
	ATF_CHECK_EQ(cc_n, estate->dtes_cc_n);
	ATF_CHECK_EQ(cc_z, estate->dtes_cc_z);
	ATF_CHECK_EQ(cc_r, estate->dtes_cc_r);
	ATF_CHECK_EQ(textlen, estate->dtes_textlen);
	ATF_CHECK_EQ(inttab, estate->dtes_inttab);
	ATF_CHECK_EQ(strtab, estate->dtes_strtab);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);

}

ATF_TC_WITHOUT_HEAD(DIF_OP_RET);
ATF_TC_BODY(DIF_OP_RET, tc)
{
	/*
	 * Test the OR operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[3] = EPERM;
	estate->dtes_pc = 0;
	estate->dtes_textlen = 1000;

	instr = DIF_INSTR_FMT(DIF_OP_RET, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(EPERM, estate->dtes_rval);
	ATF_CHECK_EQ(EPERM, estate->dtes_regs[3]);
	ATF_CHECK_EQ(1000, estate->dtes_pc);
	ATF_CHECK_EQ(1000, estate->dtes_textlen);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_OR);
ATF_TC_BODY(DIF_OP_OR, tc)
{
	/*
	 * Test the OR operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xD00000D;
	estate->dtes_regs[2] = 0x006F000;

	instr = DIF_INSTR_FMT(DIF_OP_OR, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06F00D, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_XOR);
ATF_TC_BODY(DIF_OP_XOR, tc)
{
	/*
	 * Test the XOR operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xEF90FC5;
	estate->dtes_regs[2] = 0x3FFFFC8;

	instr = DIF_INSTR_FMT(DIF_OP_XOR, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06F00D, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_AND);
ATF_TC_BODY(DIF_OP_AND, tc)
{
	/*
	 * Test the AND operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xD06F00D;
	estate->dtes_regs[2] = 0xD00000D;

	instr = DIF_INSTR_FMT(DIF_OP_AND, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD00000D, estate->dtes_regs[3]);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SLL);
ATF_TC_BODY(DIF_OP_SLL, tc)
{
	/*
	 * Test the SLL operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xD06; /* 0xD0G << 20 == 0xD0600000 */
	estate->dtes_regs[2] = 20;

	instr = DIF_INSTR_FMT(DIF_OP_SLL, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD0600000, estate->dtes_regs[3]);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SRL);
ATF_TC_BODY(DIF_OP_SRL, tc)
{
	/*
	 * Test the SRL operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xD0600000; /* 0xD0G00000 >> 20 == 0xD0G */
	estate->dtes_regs[2] = 20;

	instr = DIF_INSTR_FMT(DIF_OP_SRL, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SUB);
ATF_TC_BODY(DIF_OP_SUB, tc)
{
	/*
	 * Test the XOR operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xD06E;
	estate->dtes_regs[2] = 0xC368;

	instr = DIF_INSTR_FMT(DIF_OP_SUB, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_ADD);
ATF_TC_BODY(DIF_OP_ADD, tc)
{
	/*
	 * Test the ADD operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xD06;
	estate->dtes_regs[2] = 0xC368;

	instr = DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_regs[3]);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_MUL);
ATF_TC_BODY(DIF_OP_MUL, tc)
{
	/*
	 * Test the MUL operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 1024;
	estate->dtes_regs[2] = 2;

	instr = DIF_INSTR_FMT(DIF_OP_MUL, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2048, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SDIV);
ATF_TC_BODY(DIF_OP_SDIV, tc)
{
	/*
	 * Test the SDIV operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 1024;
	estate->dtes_regs[2] = -2;

	instr = DIF_INSTR_FMT(DIF_OP_SDIV, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(-512, estate->dtes_regs[3]);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = -1024;
	estate->dtes_regs[2] = 2;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(-512, estate->dtes_regs[3]);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 1024;
	estate->dtes_regs[2] = 2;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(512, estate->dtes_regs[3]);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = -1024;
	estate->dtes_regs[2] = -2;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(512, estate->dtes_regs[3]);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = -1024;
	estate->dtes_regs[2] = 0;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(EINVAL, err);
	ATF_CHECK_EQ(0, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_UDIV);
ATF_TC_BODY(DIF_OP_UDIV, tc)
{
	/*
	 * Test the UDIV operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 1024;
	estate->dtes_regs[2] = 2;

	instr = DIF_INSTR_FMT(DIF_OP_UDIV, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(512, estate->dtes_regs[3]);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 1024;
	estate->dtes_regs[2] = 0;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(EINVAL, err);
	ATF_CHECK_EQ(0, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SREM);
ATF_TC_BODY(DIF_OP_SREM, tc)
{
	/*
	 * Test the SREM operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 1024;
	estate->dtes_regs[2] = 513;

	instr = DIF_INSTR_FMT(DIF_OP_SREM, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(511, estate->dtes_regs[3]);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = -1024;
	estate->dtes_regs[2] = 513;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(-511, estate->dtes_regs[3]);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = -1024;
	estate->dtes_regs[2] = -513;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(-511, estate->dtes_regs[3]);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 1024;
	estate->dtes_regs[2] = 0;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(EINVAL, err);
	ATF_CHECK_EQ(0, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_UREM);
ATF_TC_BODY(DIF_OP_UREM, tc)
{
	/*
	 * Test the UREM operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 1024;
	estate->dtes_regs[2] = 513;

	instr = DIF_INSTR_FMT(DIF_OP_UREM, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(511, estate->dtes_regs[3]);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 1024;
	estate->dtes_regs[2] = 0;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(EINVAL, err);
	ATF_CHECK_EQ(0, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_NOT);
ATF_TC_BODY(DIF_OP_NOT, tc)
{
	/*
	 * Test the NOT operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0x0;

	instr = DIF_INSTR_FMT(DIF_OP_NOT, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xFFFFFFFFFFFFFFFF, estate->dtes_regs[3]);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xD06ED00D;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xFFFFFFFF2F912FF2, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_MOV);
ATF_TC_BODY(DIF_OP_MOV, tc)
{
	/*
	 * Test the MOV operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xD06;

	instr = DIF_INSTR_FMT(DIF_OP_MOV, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_CMP_R1_GT_R2);
ATF_TC_BODY(DIF_OP_CMP_R1_GT_R2, tc)
{
	/*
	 * Test the CMP operation of the DTrace machine when r1 is greater than
	 * r2.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 20;
	estate->dtes_regs[2] = 5;

	instr = DIF_INSTR_FMT(DIF_OP_CMP, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(15, estate->dtes_cc_r);
	ATF_CHECK_EQ(0, estate->dtes_cc_n);
	ATF_CHECK_EQ(0, estate->dtes_cc_z);
	ATF_CHECK_EQ(0, estate->dtes_cc_v);
	ATF_CHECK_EQ(0, estate->dtes_cc_c);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_CMP_R1_EQ_R2);
ATF_TC_BODY(DIF_OP_CMP_R1_EQ_R2, tc)
{
	/*
	 * Test the CMP operation of the DTrace machine when r1 is equal to r2.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 20;
	estate->dtes_regs[2] = 20;

	instr = DIF_INSTR_FMT(DIF_OP_CMP, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_cc_r);
	ATF_CHECK_EQ(0, estate->dtes_cc_n);
	ATF_CHECK_EQ(1, estate->dtes_cc_z);
	ATF_CHECK_EQ(0, estate->dtes_cc_v);
	ATF_CHECK_EQ(0, estate->dtes_cc_c);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_CMP_R1_LT_R2);
ATF_TC_BODY(DIF_OP_CMP_R1_LT_R2, tc)
{
	/*
	 * Test the CMP operation of the DTrace machine when r1 is lesser than
	 * r2.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 10;
	estate->dtes_regs[2] = 20;

	instr = DIF_INSTR_FMT(DIF_OP_CMP, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(-10, estate->dtes_cc_r);
	ATF_CHECK_EQ(1, estate->dtes_cc_n);
	ATF_CHECK_EQ(0, estate->dtes_cc_z);
	ATF_CHECK_EQ(0, estate->dtes_cc_v);
	ATF_CHECK_EQ(1, estate->dtes_cc_c);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

/*
 * TODO: We should write more proper CMP tests.
 */

ATF_TC_WITHOUT_HEAD(DIF_OP_TST);
ATF_TC_BODY(DIF_OP_TST, tc)
{
	/*
	 * Test the TST operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 1;

	instr = DIF_INSTR_FMT(DIF_OP_TST, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_cc_n);
	ATF_CHECK_EQ(0, estate->dtes_cc_z);
	ATF_CHECK_EQ(0, estate->dtes_cc_v);
	ATF_CHECK_EQ(0, estate->dtes_cc_c);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_cc_n);
	ATF_CHECK_EQ(1, estate->dtes_cc_z);
	ATF_CHECK_EQ(0, estate->dtes_cc_v);
	ATF_CHECK_EQ(0, estate->dtes_cc_c);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BA);
ATF_TC_BODY(DIF_OP_BA, tc)
{
	/*
	 * Test the BA operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BA, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

/*
 * TODO: We should test these instructions by adding CMP in there too.
 */

ATF_TC_WITHOUT_HEAD(DIF_OP_BE);
ATF_TC_BODY(DIF_OP_BE, tc)
{
	/*
	 * Test the BE operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_z = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BE, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_z = 1;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BNE);
ATF_TC_BODY(DIF_OP_BNE, tc)
{
	/*
	 * Test the BNE operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_z = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BNE, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_z = 1;

	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BG_SUCCESS_POS);
ATF_TC_BODY(DIF_OP_BG_SUCCESS_POS, tc)
{
	/*
	 * Test the BG operation of the DTrace machine when it branches.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_z = 0;
	estate->dtes_cc_n = 0;
	estate->dtes_cc_v = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BG, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BG_FAIL_POS);
ATF_TC_BODY(DIF_OP_BG_FAIL_POS, tc)
{
	/*
	 * Test the BG operation of the DTrace machine when it doesn't branch.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_z = 0;
	estate->dtes_cc_n = 0;
	estate->dtes_cc_v = 1;

	instr = DIF_INSTR_BRANCH(DIF_OP_BG, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BG_SUCCESS_NEG);
ATF_TC_BODY(DIF_OP_BG_SUCCESS_NEG, tc)
{
	/*
	 * Test the BG operation of the DTrace machine when it does branch, but
	 * with a negative number as an argument.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_z = 0;
	estate->dtes_cc_n = 1;
	estate->dtes_cc_v = 1;

	instr = DIF_INSTR_BRANCH(DIF_OP_BG, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BG_FAIL_NEG);
ATF_TC_BODY(DIF_OP_BG_FAIL_NEG, tc)
{
	/*
	 * Test the BG operation of the DTrace machine when it doesn't branch,
	 * but with a negative number as an argument.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_z = 0;
	estate->dtes_cc_n = 1;
	estate->dtes_cc_v = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BG, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BGU_SUCCESS);
ATF_TC_BODY(DIF_OP_BGU_SUCCESS, tc)
{
	/*
	 * Test the BGU operation of the DTrace machine when it branches.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_c = 0;
	estate->dtes_cc_z = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BGU, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BGU_FAIL);
ATF_TC_BODY(DIF_OP_BGU_FAIL, tc)
{
	/*
	 * Test the BGU operation of the DTrace machine when it doesn't branch.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_c = 0;
	estate->dtes_cc_z = 1;

	instr = DIF_INSTR_BRANCH(DIF_OP_BGU, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BGE_SUCCESS_POS);
ATF_TC_BODY(DIF_OP_BGE_SUCCESS_POS, tc)
{
	/*
	 * Test the BGE operation of the DTrace machine when it branches given a
	 * positive number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_n = 0;
	estate->dtes_cc_v = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BGE, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BGE_SUCCESS_NEG);
ATF_TC_BODY(DIF_OP_BGE_SUCCESS_NEG, tc)
{
	/*
	 * Test the BGE operation of the DTrace machine when it branches given a
	 * negative number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_n = 1;
	estate->dtes_cc_v = 1;

	instr = DIF_INSTR_BRANCH(DIF_OP_BGE, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BGE_FAIL_POS);
ATF_TC_BODY(DIF_OP_BGE_FAIL_POS, tc)
{
	/*
	 * Test the BGE operation of the DTrace machine when it doesn't branch
	 * given a positive number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_n = 0;
	estate->dtes_cc_v = 1;

	instr = DIF_INSTR_BRANCH(DIF_OP_BGE, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BGE_FAIL_NEG);
ATF_TC_BODY(DIF_OP_BGE_FAIL_NEG, tc)
{
	/*
	 * Test the BGE operation of the DTrace machine when it doesn't branch
	 * given a negative number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_n = 1;
	estate->dtes_cc_v = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BGE, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BGEU_SUCCESS);
ATF_TC_BODY(DIF_OP_BGEU_SUCCESS, tc)
{
	/*
	 * Test the BGEU operation of the DTrace machine when it branches.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_c = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BGEU, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BGEU_FAIL);
ATF_TC_BODY(DIF_OP_BGEU_FAIL, tc)
{
	/*
	 * Test the BGEU operation of the DTrace machine when it doesn't branch.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_c = 1;

	instr = DIF_INSTR_BRANCH(DIF_OP_BGEU, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BL_SUCCESS_POS);
ATF_TC_BODY(DIF_OP_BL_SUCCESS_POS, tc)
{
	/*
	 * Test the BL operation of the DTrace machine when it branches given a
	 * positive number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_n = 0;
	estate->dtes_cc_v = 1;

	instr = DIF_INSTR_BRANCH(DIF_OP_BL, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BL_SUCCESS_NEG);
ATF_TC_BODY(DIF_OP_BL_SUCCESS_NEG, tc)
{
	/*
	 * Test the BL operation of the DTrace machine when it branches given
	 * a negative number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_n = 1;
	estate->dtes_cc_v = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BL, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BL_FAIL_POS);
ATF_TC_BODY(DIF_OP_BL_FAIL_POS, tc)
{
	/*
	 * Test the BL operation of the DTrace machine when it doesn't branch
	 * given a positive number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_n = 0;
	estate->dtes_cc_v = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BL, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BL_FAIL_NEG);
ATF_TC_BODY(DIF_OP_BL_FAIL_NEG, tc)
{
	/*
	 * Test the BL operation of the DTrace machine when it doesn't branch
	 * given a negative number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_n = 1;
	estate->dtes_cc_v = 1;

	instr = DIF_INSTR_BRANCH(DIF_OP_BL, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BLU_SUCCESS);
ATF_TC_BODY(DIF_OP_BLU_SUCCESS, tc)
{
	/*
	 * Test the BLU operation of the DTrace machine when it branches.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_c = 1;

	instr = DIF_INSTR_BRANCH(DIF_OP_BLU, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BLU_FAIL);
ATF_TC_BODY(DIF_OP_BLU_FAIL, tc)
{
	/*
	 * Test the BLU operation of the DTrace machine when it doesn't branch.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_c = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BLU, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BLE_SUCCESS_POS);
ATF_TC_BODY(DIF_OP_BLE_SUCCESS_POS, tc)
{
	/*
	 * Test the BLE operation of the DTrace machine when it branches given a
	 * positive number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_z = 0;
	estate->dtes_cc_n = 0;
	estate->dtes_cc_v = 1;

	instr = DIF_INSTR_BRANCH(DIF_OP_BLE, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BLE_SUCCESS_NEG);
ATF_TC_BODY(DIF_OP_BLE_SUCCESS_NEG, tc)
{
	/*
	 * Test the BLE operation of the DTrace machine when it branches given a
	 * negative number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_z = 0;
	estate->dtes_cc_n = 1;
	estate->dtes_cc_v = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BLE, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BLE_FAIL_POS);
ATF_TC_BODY(DIF_OP_BLE_FAIL_POS, tc)
{
	/*
	 * Test the BLE operation of the DTrace machine when it doesn't branch
	 * given a positive number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_z = 0;
	estate->dtes_cc_n = 0;
	estate->dtes_cc_v = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BLE, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BLE_FAIL_NEG);
ATF_TC_BODY(DIF_OP_BLE_FAIL_NEG, tc)
{
	/*
	 * Test the BLE operation of the DTrace machine when it doesn't branch
	 * given a negative number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_z = 0;
	estate->dtes_cc_n = 1;
	estate->dtes_cc_v = 1;

	instr = DIF_INSTR_BRANCH(DIF_OP_BLE, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BLEU_SUCCESS);
ATF_TC_BODY(DIF_OP_BLEU_SUCCESS, tc)
{
	/*
	 * Test the BLEU operation of the DTrace machine when it branches.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_c = 1;
	estate->dtes_cc_z = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BLEU, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BLEU_FAIL);
ATF_TC_BODY(DIF_OP_BLEU_FAIL, tc)
{
	/*
	 * Test the BLEU operation of the DTrace machine when it doesn't branch.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_pc = 0;
	estate->dtes_cc_c = 0;
	estate->dtes_cc_z = 0;

	instr = DIF_INSTR_BRANCH(DIF_OP_BLEU, 0xD06E);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_pc);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_LDSB_NEG);
ATF_TC_BODY(DIF_OP_LDSB_NEG, tc)
{
	/*
	 * Test the LDSB operation of the DTrace machine given a negative number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int8_t *var;

	var = malloc(sizeof (int8_t));
	*var = -1;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_LDSB, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xFFFFFFFFFFFFFFFF, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_LDSB_POS);
ATF_TC_BODY(DIF_OP_LDSB_POS, tc)
{
	/*
	 * Test the LDSB operation of the DTrace machine given a positive number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int8_t *var;

	var = malloc(sizeof (int8_t));
	*var = 73;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_LDSB, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(73, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_LDSH_NEG);
ATF_TC_BODY(DIF_OP_LDSH_NEG, tc)
{
	/*
	 * Test the LDSH operation of the DTrace machine given a negative number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int16_t *var;

	var = malloc(sizeof (int16_t));
	*var = -1;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_LDSH, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xFFFFFFFFFFFFFFFF, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_LDSH_POS);
ATF_TC_BODY(DIF_OP_LDSH_POS, tc)
{
	/*
	 * Test the LDSH operation of the DTrace machine given a positive number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int16_t *var;

	var = malloc(sizeof (int16_t));
	*var = 7357;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_LDSH, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(7357, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_LDSW_NEG);
ATF_TC_BODY(DIF_OP_LDSW_NEG, tc)
{
	/*
	 * Test the LDSW operation of the DTrace machine given a negative number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int32_t *var;

	var = malloc(sizeof (int16_t));
	*var = -1;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_LDSW, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xFFFFFFFFFFFFFFFF, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_LDSW_POS);
ATF_TC_BODY(DIF_OP_LDSW_POS, tc)
{
	/*
	 * Test the LDSW operation of the DTrace machine given a positive number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int32_t *var;

	var = malloc(sizeof (int16_t));
	*var = 7357116;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_LDSW, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(7357116, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_LDX);
ATF_TC_BODY(DIF_OP_LDX, tc)
{
	/*
	 * Test the LDX operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	uint64_t *var;

	var = malloc(sizeof (uint64_t));
	*var = 7357116;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_LDX, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(7357116, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_LDUB);
ATF_TC_BODY(DIF_OP_LDUB, tc)
{
	/*
	 * Test the LDUB operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	uint8_t *var;

	var = malloc(sizeof (uint8_t));
	*var = 73;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_LDUB, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(73, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_LDUH);
ATF_TC_BODY(DIF_OP_LDUH, tc)
{
	/*
	 * Test the LDUH operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	uint16_t *var;

	var = malloc(sizeof (uint16_t));
	*var = 7357;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_LDUH, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(7357, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_LDUW);
ATF_TC_BODY(DIF_OP_LDUW, tc)
{
	/*
	 * Test the LDUW operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	uint32_t *var;

	var = malloc(sizeof (uint32_t));
	*var = 73571116;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_LDUW, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(73571116, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

/*
 * TODO: RLD* are not properly implemented due to the fact that dtrace_canload()
 * is not implemented and just returns 1. We should implement that in order to
 * test these properly, but the tests are outlined in order for completeness.
 */
ATF_TC_WITHOUT_HEAD(DIF_OP_RLDSB_NEG);
ATF_TC_BODY(DIF_OP_RLDSB_NEG, tc)
{
	/*
	 * Test the RLDSB operation of the DTrace machine given a negative number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int8_t *var;

	var = malloc(sizeof (int8_t));
	*var = -1;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_RLDSB, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xFFFFFFFFFFFFFFFF, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_RLDSB_POS);
ATF_TC_BODY(DIF_OP_RLDSB_POS, tc)
{
	/*
	 * Test the RLDSB operation of the DTrace machine given a positive number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int8_t *var;

	var = malloc(sizeof (int8_t));
	*var = 73;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_RLDSB, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(73, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_RLDSH_NEG);
ATF_TC_BODY(DIF_OP_RLDSH_NEG, tc)
{
	/*
	 * Test the RLDSH operation of the DTrace machine given a negative number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int16_t *var;

	var = malloc(sizeof (int16_t));
	*var = -1;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_RLDSH, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xFFFFFFFFFFFFFFFF, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_RLDSH_POS);
ATF_TC_BODY(DIF_OP_RLDSH_POS, tc)
{
	/*
	 * Test the RLDSH operation of the DTrace machine given a positive number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int16_t *var;

	var = malloc(sizeof (int16_t));
	*var = 7357;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_RLDSH, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(7357, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_RLDSW_NEG);
ATF_TC_BODY(DIF_OP_RLDSW_NEG, tc)
{
	/*
	 * Test the RLDSW operation of the DTrace machine given a negative number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int32_t *var;

	var = malloc(sizeof (int16_t));
	*var = -1;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_RLDSW, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xFFFFFFFFFFFFFFFF, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_RLDSW_POS);
ATF_TC_BODY(DIF_OP_RLDSW_POS, tc)
{
	/*
	 * Test the RLDSW operation of the DTrace machine given a positive number.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int32_t *var;

	var = malloc(sizeof (int16_t));
	*var = 7357116;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_RLDSW, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(7357116, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_RLDX);
ATF_TC_BODY(DIF_OP_RLDX, tc)
{
	/*
	 * Test the RLDX operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	uint64_t *var;

	var = malloc(sizeof (uint64_t));
	*var = 7357116;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_LDX, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(7357116, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_RLDUB);
ATF_TC_BODY(DIF_OP_RLDUB, tc)
{
	/*
	 * Test the RLDUB operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	uint8_t *var;

	var = malloc(sizeof (uint8_t));
	*var = 73;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_RLDUB, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(73, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_RLDUH);
ATF_TC_BODY(DIF_OP_RLDUH, tc)
{
	/*
	 * Test the RLDUH operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	uint16_t *var;

	var = malloc(sizeof (uint16_t));
	*var = 7357;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_RLDUH, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(7357, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_RLDUW);
ATF_TC_BODY(DIF_OP_RLDUW, tc)
{
	/*
	 * Test the RLDUW operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	uint32_t *var;

	var = malloc(sizeof (uint32_t));
	*var = 73571116;
	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) var;

	instr = DIF_INSTR_FMT(DIF_OP_RLDUW, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(73571116, estate->dtes_regs[3]);

	free(var);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SCMP_EQ);
ATF_TC_BODY(DIF_OP_SCMP_EQ, tc)
{
	/*
	 * Test the SCMP operation of the DTrace machine when the two strings
	 * are equal.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	const char *str1 = "foo";
	const char *str2 = "foo";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 3;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) str1;
	estate->dtes_regs[2] = (uintptr_t) str2;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_FMT(DIF_OP_SCMP, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_cc_r);
	ATF_CHECK_EQ(0, estate->dtes_cc_n);
	ATF_CHECK_EQ(1, estate->dtes_cc_z);
	ATF_CHECK_EQ(0, estate->dtes_cc_c);
	ATF_CHECK_EQ(0, estate->dtes_cc_v);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SCMP_STR1_GT_STR2);
ATF_TC_BODY(DIF_OP_SCMP_STR1_GT_STR2, tc)
{
	/*
	 * Test the SCMP operation of the DTrace machine when the the first
	 * string has a letter that is greater in ASCII value than the second
	 * string.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	const char *str1 = "foo";
	const char *str2 = "eoo";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 3;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) str1;
	estate->dtes_regs[2] = (uintptr_t) str2;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_FMT(DIF_OP_SCMP, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(('f' - 'e'), estate->dtes_cc_r);
	ATF_CHECK_EQ(('f' - 'e') < 0, estate->dtes_cc_n);
	ATF_CHECK_EQ(('f' - 'e') == 0, estate->dtes_cc_z);
	ATF_CHECK_EQ(0, estate->dtes_cc_c);
	ATF_CHECK_EQ(0, estate->dtes_cc_v);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SCMP_STR1_LT_STR2);
ATF_TC_BODY(DIF_OP_SCMP_STR1_LT_STR2, tc)
{
	/*
	 * Test the SCMP operation of the DTrace machine when the the first
	 * string has a letter that is lesser in ASCII value than the second
	 * string.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	const char *str1 = "eoo";
	const char *str2 = "foo";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 3;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) str1;
	estate->dtes_regs[2] = (uintptr_t) str2;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_FMT(DIF_OP_SCMP, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(('e' - 'f'), estate->dtes_cc_r);
	ATF_CHECK_EQ(('e' - 'f') < 0, estate->dtes_cc_n);
	ATF_CHECK_EQ(('e' - 'f') == 0, estate->dtes_cc_z);
	ATF_CHECK_EQ(0, estate->dtes_cc_c);
	ATF_CHECK_EQ(0, estate->dtes_cc_v);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SCMP_FAIL);
ATF_TC_BODY(DIF_OP_SCMP_FAIL, tc)
{
	/*
	 * Test the SCMP operation of the DTrace machine when the wrong size of
	 * the string is specified. The expected behaviour here is that the
	 * string will only be compared partially (i.e., up to a point of
	 * dts_options[DTRACEOPT_STRSIZE].
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	const char *str1 = "foooooooooooooooo";
	const char *str2 = "foooobaaaaaaaaaar";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 5;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = (uintptr_t) str1;
	estate->dtes_regs[2] = (uintptr_t) str2;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_FMT(DIF_OP_SCMP, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_cc_r);
	ATF_CHECK_EQ(0, estate->dtes_cc_n);
	ATF_CHECK_EQ(1, estate->dtes_cc_z);
	ATF_CHECK_EQ(0, estate->dtes_cc_c);
	ATF_CHECK_EQ(0, estate->dtes_cc_v);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SETX);
ATF_TC_BODY(DIF_OP_SETX, tc)
{
	/*
	 * Test the SETX operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	uint64_t *inttab;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	inttab = calloc(0xFFFF, sizeof(uint64_t));
	inttab[100] = 0xD06E;
	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_inttab = (const uint64_t *) inttab;

	instr = DIF_INSTR_SETX(100, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SETS);
ATF_TC_BODY(DIF_OP_SETS, tc)
{
	/*
	 * Test the SETS operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	char *strtab;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	strtab = calloc(0xFFFF, sizeof(char));
	estate->dtes_strtab = (const char *) strtab;
	strtab += 100;
	strcpy(strtab, "testing");
	estate->dtes_regs[DIF_REG_R0] = 0;

	instr = DIF_INSTR_SETS(100, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("testing", ((char *)estate->dtes_regs[3]));

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_LDTA);
ATF_TC_BODY(DIF_OP_LDTA, tc)
{
	/*
	 * Test the SETS operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;

	instr = DIF_INSTR_FMT(DIF_OP_LDTA, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	atf_tc_expect_fail("This opcode is currently not implemented"
	    "and is reserved for future work.");

	ATF_CHECK_EQ(0, err);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SRA);
ATF_TC_BODY(DIF_OP_SRA, tc)
{
	/*
	 * Test the SRA operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xFF00;
	estate->dtes_regs[2] = 8;
	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_FMT(DIF_OP_SRA, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xFF, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_PUSHTR);
ATF_TC_BODY(DIF_OP_PUSHTR, tc)
{
	/*
	 * Test the PUSHTR operation of the DTrace machine.
	 *
	 * XXX: This is a very bad test due to the fact that we are literally
	 * pushing it onto the stack and never verifying whether or not it's
	 * actually been put there.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	char str[] = "hello world!";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xFF00;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = (uintptr_t) str;

	instr = DIF_INSTR_FMT(DIF_OP_PUSHTR, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_PUSHTV);
ATF_TC_BODY(DIF_OP_PUSHTV, tc)
{
	/*
	 * Test the PUSHTV operation of the DTrace machine.
	 *
	 * XXX: This is a very bad test due to the fact that we are literally
	 * pushing it onto the stack and never verifying whether or not it's
	 * actually been put there.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	int x = 3;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[3] = x;

	instr = DIF_INSTR_FMT(DIF_OP_PUSHTV, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_POPTS);
ATF_TC_BODY(DIF_OP_POPTS, tc)
{
	/*
	 * Test the POPTS operation of the DTrace machine.
	 *
	 * XXX: This is a very bad test due to the fact that we are literally
	 * pushing it onto the stack and never verifying whether or not it's
	 * actually been put there.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	char str[] = "hello world!";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xFF00;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = (uintptr_t) str;

	instr = DIF_INSTR_FMT(DIF_OP_PUSHTR, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);

	instr = DIF_INSTR_FMT(DIF_OP_POPTS, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);

	instr = DIF_INSTR_FMT(DIF_OP_POPTS, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_FLUSHTS);
ATF_TC_BODY(DIF_OP_FLUSHTS, tc)
{
	/*
	 * Test the FLUSHTS operation of the DTrace machine.
	 *
	 * XXX: This is a very bad test due to the fact that we are literally
	 * pushing it onto the stack and never verifying whether or not it's
	 * actually been put there.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	char str[] = "hello world!";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xFF00;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = (uintptr_t) str;

	instr = DIF_INSTR_FMT(DIF_OP_PUSHTR, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);

	instr = DIF_INSTR_FMT(DIF_OP_FLUSHTS, 1, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

static uint64_t
test_getargval(void *arg, dtrace_id_t id, void *parg,
    int argno, int aframes)
{
	return (*((uint64_t *) parg));
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_ARGS);
ATF_TC_BODY(DIF_VAR_ARGS, tc)
{
	/*
	 * Test the ARGS variable access.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	uint64_t testval = 0xD06;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	err = dtrace_init();
	if (err != 0)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));


	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	ATF_CHECK_EQ(0, err);

	provider = (dtrace_provider_t *) id;
	provider->dtpv_pops.dtps_getargval = test_getargval;

	probeid = dtrace_probe_create(id, "test", "probe",
	    "foo", 0, NULL);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	mstate->dtms_probe = dtrace_getprobe(probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_id, probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_provider, provider);
	mstate->dtms_probe->dtpr_arg = &testval;
	mstate->dtms_present |= DTRACE_MSTATE_ARGS;
	mstate->dtms_arg[0] = 0xD06E;

	instr = DIF_INSTR_FMT(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, estate->dtes_regs[3]);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 6;
	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_FMT(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0xD06, estate->dtes_regs[3]);

	err = dtrace_unregister(id);
	ATF_CHECK_EQ(0, err);

	err = dtrace_deinit();
	if (err)
		atf_tc_fail("DTrace not properly deinitialized: %s", strerror(err));

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_ARGS_ASSERT_FAIL);
ATF_TC_BODY(DIF_VAR_ARGS_ASSERT_FAIL, tc)
{
	/*
	 * Test the ARGS variable access with a failed assertion.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	uint64_t testval = 0xD06;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	err = dtrace_init();
	if (err != 0)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));


	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	ATF_CHECK_EQ(0, err);

	provider = (dtrace_provider_t *) id;
	provider->dtpv_pops.dtps_getargval = test_getargval;

	probeid = dtrace_probe_create(id, "test", "probe",
	    "foo", 0, NULL);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	mstate->dtms_probe = dtrace_getprobe(probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_id, probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_provider, provider);
	mstate->dtms_probe->dtpr_arg = &testval;
	mstate->dtms_present &= ~DTRACE_MSTATE_ARGS;
	mstate->dtms_arg[0] = 0xD06E;

	atf_tc_expect_death("Assertion death. DTRACE_MSTATE_ARGS is not set");

	instr = DIF_INSTR_FMT(DIF_OP_LDGA, DIF_VAR_ARGS, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	err = dtrace_unregister(id);
	ATF_CHECK_EQ(0, err);

	err = dtrace_deinit();
	if (err)
		atf_tc_fail("DTrace not properly deinitialized: %s", strerror(err));

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_EPID);
ATF_TC_BODY(DIF_VAR_EPID, tc)
{
	/*
	 * Test the EPID variable access.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	int err;
	uint64_t testval = 0xD06;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	mstate->dtms_present |= DTRACE_MSTATE_EPID;
	mstate->dtms_epid = 123;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;


	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_EPID, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(123, mstate->dtms_epid);
	ATF_CHECK_EQ(123, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_ID);
ATF_TC_BODY(DIF_VAR_ID, tc)
{
	/*
	 * Test the ID variable access.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	err = dtrace_init();
	if (err != 0)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));


	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	ATF_CHECK_EQ(0, err);

	provider = (dtrace_provider_t *) id;
	probeid = dtrace_probe_create(id, "test", "probe",
	    "foo", 0, NULL);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	mstate->dtms_probe = dtrace_getprobe(probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_id, probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_provider, provider);
	mstate->dtms_present |= DTRACE_MSTATE_PROBE;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ID, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(probeid, estate->dtes_regs[3]);

	err = dtrace_unregister(id);
	ATF_CHECK_EQ(0, err);

	err = dtrace_deinit();
	if (err)
		atf_tc_fail("DTrace not properly deinitialized: %s", strerror(err));

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_PROBEPROV);
ATF_TC_BODY(DIF_VAR_PROBEPROV, tc)
{
	/*
	 * Test the PROBEPROV variable access.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	err = dtrace_init();
	if (err != 0)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));

	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	ATF_CHECK_EQ(0, err);

	provider = (dtrace_provider_t *) id;
	probeid = dtrace_probe_create(id, "test", "probe",
	    "foo", 0, NULL);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	mstate->dtms_probe = dtrace_getprobe(probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_id, probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_provider, provider);
	mstate->dtms_present |= DTRACE_MSTATE_PROBE;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_PROBEPROV, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK(0 != estate->dtes_regs[3]);
	ATF_CHECK_STREQ("test_provider", (char *)estate->dtes_regs[3]);

	err = dtrace_unregister(id);
	ATF_CHECK_EQ(0, err);

	err = dtrace_deinit();
	if (err)
		atf_tc_fail("DTrace not properly deinitialized: %s", strerror(err));

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_PROBEMOD);
ATF_TC_BODY(DIF_VAR_PROBEMOD, tc)
{
	/*
	 * Test the PROBMOD variable access.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	err = dtrace_init();
	if (err != 0)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));

	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	ATF_CHECK_EQ(0, err);

	provider = (dtrace_provider_t *) id;
	probeid = dtrace_probe_create(id, "test", "probe",
	    "foo", 0, NULL);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	mstate->dtms_probe = dtrace_getprobe(probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_id, probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_provider, provider);
	mstate->dtms_present |= DTRACE_MSTATE_PROBE;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_PROBEMOD, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK(0 != estate->dtes_regs[3]);
	ATF_CHECK_STREQ("test", (char *)estate->dtes_regs[3]);

	err = dtrace_unregister(id);
	ATF_CHECK_EQ(0, err);

	err = dtrace_deinit();
	if (err)
		atf_tc_fail("DTrace not properly deinitialized: %s", strerror(err));

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_PROBEFUNC);
ATF_TC_BODY(DIF_VAR_PROBEFUNC, tc)
{
	/*
	 * Test the PROBFUNC variable access.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	err = dtrace_init();
	if (err != 0)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));

	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	ATF_CHECK_EQ(0, err);

	provider = (dtrace_provider_t *) id;
	probeid = dtrace_probe_create(id, "test", "probe",
	    "foo", 0, NULL);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	mstate->dtms_probe = dtrace_getprobe(probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_id, probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_provider, provider);
	mstate->dtms_present |= DTRACE_MSTATE_PROBE;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_PROBEFUNC, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK(0 != estate->dtes_regs[3]);
	ATF_CHECK_STREQ("probe", (char *)estate->dtes_regs[3]);

	err = dtrace_unregister(id);
	ATF_CHECK_EQ(0, err);

	err = dtrace_deinit();
	if (err)
		atf_tc_fail("DTrace not properly deinitialized: %s", strerror(err));

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_PROBENAME);
ATF_TC_BODY(DIF_VAR_PROBENAME, tc)
{
	/*
	 * Test the PROBENAME variable access.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	err = dtrace_init();
	if (err != 0)
		atf_tc_fail("DTrace not properly initialized: %s", strerror(err));

	err = dtrace_register("test_provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	ATF_CHECK_EQ(0, err);

	provider = (dtrace_provider_t *) id;
	probeid = dtrace_probe_create(id, "test", "probe",
	    "foo", 0, NULL);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	mstate->dtms_probe = dtrace_getprobe(probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_id, probeid);
	ATF_CHECK_EQ(mstate->dtms_probe->dtpr_provider, provider);
	mstate->dtms_present |= DTRACE_MSTATE_PROBE;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_PROBENAME, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK(0 != estate->dtes_regs[3]);
	ATF_CHECK_STREQ("foo", (char *)estate->dtes_regs[3]);

	err = dtrace_unregister(id);
	ATF_CHECK_EQ(0, err);

	err = dtrace_deinit();
	if (err)
		atf_tc_fail("DTrace not properly deinitialized: %s", strerror(err));

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_PID);
ATF_TC_BODY(DIF_VAR_PID, tc)
{
	/*
	 * Test the PID variable access.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_cred.dcr_action |= DTRACE_CRA_PROC;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_PID, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(getpid(), estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_PPID);
ATF_TC_BODY(DIF_VAR_PPID, tc)
{
	/*
	 * Test the PPID variable access.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_cred.dcr_action |= DTRACE_CRA_PROC;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_PPID, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(getppid(), estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_TID);
ATF_TC_BODY(DIF_VAR_TID, tc)
{
	/*
	 * Test the TID variable access.
	 *
	 * XXX: This can't be tested properly as we are running only on one
	 * thread. This should be addressed in the future, perhaps through SMP
	 * emulation or a different architecture all together...
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_cred.dcr_action |= DTRACE_CRA_PROC;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_TID, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(1, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_EXECNAME);
ATF_TC_BODY(DIF_VAR_EXECNAME, tc)
{
	/*
	 * Test the EXECNAME variable access.
	 *
	 * XXX: This can't be tested properly because we don't have access to
	 * the process' execname, we don't own the traced process.
	 *
	 * Temporarily, we use setprogname() and getprogname()
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_cred.dcr_action |= DTRACE_CRA_PROC;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	setprogname("Test Program");

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_EXECNAME, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("Test Program", (char *)estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_ZONENAME);
ATF_TC_BODY(DIF_VAR_ZONENAME, tc)
{
	/*
	 * Test the ZONENAME variable access.
	 *
	 * This doesn't even work on FreeBSD, let alone in userspace, but the
	 * test is here just for future additions to DTrace.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_cred.dcr_action |= DTRACE_CRA_PROC;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ZONENAME, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	atf_tc_expect_fail("ZONENAME is not implemented.");
	ATF_CHECK(estate->dtes_regs[3] != 0);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_UID);
ATF_TC_BODY(DIF_VAR_UID, tc)
{
	/*
	 * Test the UID variable access.
	 *
	 * XXX: This also can't be tested properly because we are just getting
	 * our own UID.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_cred.dcr_action |= DTRACE_CRA_PROC;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_UID, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(getuid(), estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_GID);
ATF_TC_BODY(DIF_VAR_GID, tc)
{
	/*
	 * Test the GID variable access.
	 *
	 * XXX: This also can't be tested properly because we are just getting
	 * our own GID.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_cred.dcr_action |= DTRACE_CRA_PROC;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_GID, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(getgid(), estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_ERRNO);
ATF_TC_BODY(DIF_VAR_ERRNO, tc)
{
	/*
	 * Test the ERRNO variable access.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_cred.dcr_action |= DTRACE_CRA_PROC;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_ERRNO, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(errno, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_VAR_UNKNOWN);
ATF_TC_BODY(DIF_VAR_UNKNOWN, tc)
{
	/*
	 * Test variable access given an unknown variable.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_cred.dcr_action |= DTRACE_CRA_PROC;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 0;
	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_LDV(DIF_OP_LDGS, DIF_VAR_OTHER_UBASE - 1, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(EOPNOTSUPP, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRLEN_EXPECTED);
ATF_TC_BODY(DIF_SUBR_STRLEN_EXPECTED, tc)
{
	/*
	 * Test the strlen() subroutine given an expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	const char *string = "test";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) string;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(1, estate->dtes_ttop);
	ATF_CHECK_STREQ("test", (char *)estate->dtes_tupregs[0].dttk_value);

	instr = DIF_INSTR_CALL(DIF_SUBR_STRLEN, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(strlen(string), estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_BCOPY);
ATF_TC_BODY(DIF_SUBR_BCOPY, tc)
{
	/*
	 * Test the bcopy() subroutine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	const char *string = "hello";
	char *dst;
	size_t string_len;

	string_len = strlen(string);
	dst = malloc(string_len);

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	mstate->dtms_scratch_base = 0;
	mstate->dtms_scratch_ptr = 100000000000000;

	state->dts_options[DTRACEOPT_STRSIZE] = string_len;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = string_len;
	estate->dtes_regs[3] = (uint64_t) string;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(1, estate->dtes_ttop);

	estate->dtes_regs[3] = (uint64_t) dst;
	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2, estate->dtes_ttop);

	estate->dtes_regs[2] = sizeof(size_t);
	/*
	 * strlen + 1 because we want to copy '\0'
	 */
	estate->dtes_regs[3] = string_len + 1;
	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, 0, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(3, estate->dtes_ttop);

	instr = DIF_INSTR_CALL(DIF_SUBR_BCOPY, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(string_len, strlen(dst));
	ATF_CHECK_STREQ(string, dst);

	free(dst);
	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRLEN_NULL);
ATF_TC_BODY(DIF_SUBR_STRLEN_NULL, tc)
{
	/*
	 * Test the strlen() subroutine given a NULL string as input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *string = NULL;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) string;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(1, estate->dtes_ttop);

	instr = DIF_INSTR_CALL(DIF_SUBR_STRLEN, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRLEN_NOT_TERMINATED);
ATF_TC_BODY(DIF_SUBR_STRLEN_NOT_TERMINATED, tc)
{
	/*
	 * Test the strlen() subroutine given a non-null terminated string as an
	 * input to the function.
	 *
	 * This acts a little bit like strnlen(), in that it returns either the
	 * last value before \0 or DTRACEOPT_STRSIZE. However, as seen on this
	 * test, the value that is going to be read isn't entirely
	 * predictable...
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *string = malloc(4);
	strncpy(string, "test", 4);

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) string;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(1, estate->dtes_ttop);
	ATF_CHECK_STREQ("test", (char *)estate->dtes_tupregs[0].dttk_value);

	instr = DIF_INSTR_CALL(DIF_SUBR_STRLEN, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	atf_tc_expect_fail("It is unbounded, DTrace keeps reading to DTRACEOPT_STRSIZE, length is: %zu", estate->dtes_regs[3]);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(4, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRLEN_TOO_LONG);
ATF_TC_BODY(DIF_SUBR_STRLEN_TOO_LONG, tc)
{
	/*
	 * Test the strlen() subroutine given a string that's too long.
	 *
	 * Expected output is the DTRACEOPT_STRSIZE boundary.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *string = malloc(300);
	strncpy(string, "testiuwhaufiwehfewhdiewuihfeiwhidhewfuewhdiehfiwaehiufewhiufewuuwhiuewfieduiwehfiuwehdihweifhwehdieuwhfiewdiwuehfiwehfuewi", 300);

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) string;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(1, estate->dtes_ttop);

	instr = DIF_INSTR_CALL(DIF_SUBR_STRLEN, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(100, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRLEN_NEGATIVE_LENGTH);
ATF_TC_BODY(DIF_SUBR_STRLEN_NEGATIVE_LENGTH, tc)
{
	/*
	 * Test the strlen() subroutine given a regular string and negative
	 * size.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *string = "hello";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = -100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) string;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(1, estate->dtes_ttop);

	instr = DIF_INSTR_CALL(DIF_SUBR_STRLEN, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(5, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRLEN_GARBAGE_PTR);
ATF_TC_BODY(DIF_SUBR_STRLEN_GARBAGE_PTR, tc)
{
	/*
	 * Test strlen() by giving a garbage pointer. Breaks in userspace, is
	 * fine in the kernel.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *string = "hello";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) 123;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	/*
	 * This does not happen in the kernel due to the toxic range mechanism
	 * that DTrace implements, however, in userspace, it's not as obvious as
	 * to how to do that.
	 */
	atf_tc_expect_death("Accessing garbage");
	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(1, estate->dtes_ttop);

	instr = DIF_INSTR_CALL(DIF_SUBR_STRLEN, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	atf_tc_expect_fail("Garbage pointer sent in: %zu", estate->dtes_regs[3]);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRCHR_EXPECTED);
ATF_TC_BODY(DIF_SUBR_STRCHR_EXPECTED, tc)
{
	/*
	 * Test the strchr() subroutine given expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	const char *string = "hello world";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) string;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 'l';

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 0, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2, estate->dtes_ttop);

	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRCHR, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2, estate->dtes_regs[3] - (uintptr_t) string);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRCHR_NON_NULL_TERMINATED);
ATF_TC_BODY(DIF_SUBR_STRCHR_NON_NULL_TERMINATED, tc)
{
	/*
	 * Test the strchr() subroutine given a non-NULL terminated string.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char string[11] = "hello world";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	string[10] = '0';
	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) string;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 'x';

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 0, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2, estate->dtes_ttop);

	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRCHR, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	/*
	 * For whatever reason, this is 0, but when we check against 0, it isn't
	 * 0. ?????????????????????????????????????
	 */
	atf_tc_fail("estate->dtes_regs[3] = %lu", estate->dtes_regs[3]);
	ATF_CHECK_EQ(0, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRRCHR_EXPECTED);
ATF_TC_BODY(DIF_SUBR_STRRCHR_EXPECTED, tc)
{
	/*
	 * Test the strrchr() subroutine given expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	const char *string = "hello world";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) string;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 'r';

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 0, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2, estate->dtes_ttop);

	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRRCHR, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(8, estate->dtes_regs[3] - (uintptr_t) string);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRRCHR_NON_NULL_TERM);
ATF_TC_BODY(DIF_SUBR_STRRCHR_NON_NULL_TERM, tc)
{
	/*
	 * Test the strrchr() subroutine given a non-NULL terminated string.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char string[11] = "hello world";

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	string[10] = '0';

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) string;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 'x';

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 0, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2, estate->dtes_ttop);

	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRRCHR, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRSTR);
ATF_TC_BODY(DIF_SUBR_STRSTR, tc)
{
	/*
	 * Test the strstr() subroutine given an expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char big[11];
	char little[6];

	strcpy(big, "hello world");
	strcpy(little, "world");

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) big;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) little;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2, estate->dtes_ttop);

	estate->dtes_regs[3] = 0xBAAAAAAAD;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRSTR, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ((uint64_t) big + sizeof("hello"), estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRTOK);
ATF_TC_BODY(DIF_SUBR_STRTOK, tc)
{
	/*
	 * Test the strtok() subroutine given an expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *scratch = NULL;
	const char *str = "hello-world";
	const char *tokenby = "-";

	scratch = malloc(100);

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 20;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) str;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;
	mstate->dtms_scratch_base = (uintptr_t) scratch;
	mstate->dtms_scratch_ptr = (uintptr_t) scratch;
	mstate->dtms_scratch_size = 100;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) tokenby;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2, estate->dtes_ttop);

	estate->dtes_regs[3] = 0xBAAAAAAAD;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRTOK, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("hello", (const char *)estate->dtes_regs[3]);
	ATF_CHECK_EQ((uintptr_t)scratch + state->dts_options[DTRACEOPT_STRSIZE], mstate->dtms_scratch_ptr);
	ATF_CHECK_EQ((uintptr_t)str + sizeof("hell"), mstate->dtms_strtok);

	estate->dtes_tupregs[0].dttk_value = 0;
	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRTOK, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("world", (const char *)estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
	free(scratch);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_SUBSTR);
ATF_TC_BODY(DIF_SUBR_SUBSTR, tc)
{
	/*
	 * Test the substr() subroutine given an expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *scratch = NULL;
	const char *str = "hello world";

	scratch = malloc(100);

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 20;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) str;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;
	mstate->dtms_scratch_base = (uintptr_t) scratch;
	mstate->dtms_scratch_ptr = (uintptr_t) scratch;
	mstate->dtms_scratch_size = 100;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 0;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2, estate->dtes_ttop);

	estate->dtes_regs[3] = sizeof("hello") - 1;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(3, estate->dtes_ttop);

	estate->dtes_regs[3] = 0xBAAAAAAAD;

	instr = DIF_INSTR_CALL(DIF_SUBR_SUBSTR, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("hello", (const char *)estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
	free(scratch);
}

/*
 * TODO: We need a proper way to test dtrace_json()
 */

ATF_TC_WITHOUT_HEAD(DIF_SUBR_TOUPPER);
ATF_TC_BODY(DIF_SUBR_TOUPPER, tc)
{
	/*
	 * Test the toupper() subroutine given an expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *scratch = NULL;
	const char *str = "hello WOrld";

	scratch = malloc(100);

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 20;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) str;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;
	mstate->dtms_scratch_base = (uintptr_t) scratch;
	mstate->dtms_scratch_ptr = (uintptr_t) scratch;
	mstate->dtms_scratch_size = 100;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 0xBAAAAAAAD;

	instr = DIF_INSTR_CALL(DIF_SUBR_TOUPPER, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("HELLO WORLD", (const char *)estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
	free(scratch);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_TOLOWER);
ATF_TC_BODY(DIF_SUBR_TOLOWER, tc)
{
	/*
	 * Test the tolower() subroutine given an expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *scratch = NULL;
	const char *str = "heLLO WORld";

	scratch = malloc(100);

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 20;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[2] = 100;
	estate->dtes_regs[3] = (uint64_t) str;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;
	mstate->dtms_scratch_base = (uintptr_t) scratch;
	mstate->dtms_scratch_ptr = (uintptr_t) scratch;
	mstate->dtms_scratch_size = 100;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 0xBAAAAAAAD;

	instr = DIF_INSTR_CALL(DIF_SUBR_TOLOWER, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("hello world", (const char *)estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
	free(scratch);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRJOIN);
ATF_TC_BODY(DIF_SUBR_STRJOIN, tc)
{
	/*
	 * Test the strjoin() subroutine given an expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *scratch = NULL;
	const char *first = "hello ";
	const char *second = "world";

	scratch = malloc(100);

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 20;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[3] = (uint64_t) first;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;
	mstate->dtms_scratch_base = (uintptr_t) scratch;
	mstate->dtms_scratch_ptr = (uintptr_t) scratch;
	mstate->dtms_scratch_size = 100;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[3] = (uint64_t) second;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2, estate->dtes_ttop);

	estate->dtes_regs[3] = 0xBAAAAAAAD;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRJOIN, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("hello world", (const char *)estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
	free(scratch);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRTOLL);
ATF_TC_BODY(DIF_SUBR_STRTOLL, tc)
{
	/*
	 * Test the strtoll() subroutine given an expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *scratch = NULL;
	const char *strnum = "4213";
	const char *strnonnum = "abc";
	const char *leadzero = "00000001";

	scratch = malloc(100);

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 20;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[3] = (uint64_t) strnum;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;
	mstate->dtms_scratch_base = (uintptr_t) scratch;
	mstate->dtms_scratch_ptr = (uintptr_t) scratch;
	mstate->dtms_scratch_size = 100;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTR, DIF_TYPE_STRING, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 0xBAAAAAAAD;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRTOLL, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(4213, estate->dtes_regs[3]);

	estate->dtes_tupregs[0].dttk_value = (uint64_t) strnonnum;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRTOLL, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, estate->dtes_regs[3]);

	estate->dtes_tupregs[0].dttk_value = (uint64_t) leadzero;

	instr = DIF_INSTR_CALL(DIF_SUBR_STRTOLL, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(1, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
	free(scratch);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_LLTOSTR);
ATF_TC_BODY(DIF_SUBR_LLTOSTR, tc)
{
	/*
	 * Test the lltostr() subroutine given an expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *scratch = NULL;
	long long num = 12423000;

	scratch = malloc(100);

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[3] = num;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;
	mstate->dtms_scratch_base = (uintptr_t) scratch;
	mstate->dtms_scratch_ptr = (uintptr_t) scratch;
	mstate->dtms_scratch_size = 100;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 0xBAAAAAAAD;

	instr = DIF_INSTR_CALL(DIF_SUBR_LLTOSTR, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("12423000", (const char *)estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
	free(scratch);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_HTONS);
ATF_TC_BODY(DIF_SUBR_HTONS, tc)
{
	/*
	 * Test the htons() subroutine given an expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *scratch = NULL;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint64_t host = 0x1234;
#else
	uint64_t host = 0x3412;
#endif

	scratch = malloc(100);

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[3] = host;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 0xBAAAAAAAD;

	instr = DIF_INSTR_CALL(DIF_SUBR_HTONS, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0x3412, estate->dtes_regs[3]);

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
	free(scratch);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_NTOHS);
ATF_TC_BODY(DIF_SUBR_NTOHS, tc)
{
	/*
	 * Test the ntohs() subroutine given an expected input.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;
	dtrace_id_t probeid;
	dtrace_provider_id_t id;
	dtrace_provider_t *provider;
	int err;
	char *scratch = NULL;
	uint64_t network = 0x1234;

	scratch = malloc(100);

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	state->dts_options[DTRACEOPT_STRSIZE] = 100;

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[3] = network;
	mstate->dtms_access |= DTRACE_ACCESS_KERNEL;

	instr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV, 0, 2, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	estate->dtes_regs[3] = 0xBAAAAAAAD;

	instr = DIF_INSTR_CALL(DIF_SUBR_NTOHS, 3);
	err = dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0, err);
#if BYTE_ORDER == LITTLE_ENDIAN
	ATF_CHECK_EQ(0x3412, estate->dtes_regs[3]);
#else
	ATF_CHECK_EQ(0x1234, estate->dtes_regs[3]);
#endif

	free(mstate);
	free(vstate);
	free(state);
	free(estate);
	free(scratch);
}

#endif

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, dtrace_init);
	ATF_TP_ADD_TC(tp, dtrace_deinit);
	ATF_TP_ADD_TC(tp, dtrace_providers);
	ATF_TP_ADD_TC(tp, dtrace_register);
	ATF_TP_ADD_TC(tp, dtrace_probe_create);
	ATF_TP_ADD_TC(tp, dtrace_probe_lookup);
	ATF_TP_ADD_TC(tp, dtrace_probe);

#ifdef _DTRACE_TESTS
	/*
	 * TODO: For all of these tests, we should also add tests for boundary
	 * conditions, such as hitting the limit of integers, overflowing them,
	 * expecting them to fail and so on...
	 *
	 * XXX: We don't really want to test UDLS* instructions as they are
	 * no-faulting and there is no concept of "no faulting" in userspace.
	 * The best that can be done is simulating their successful execution,
	 * which may or may not be useful in any sense.
	 */
	ATF_TP_ADD_TC(tp, DIF_OP_NOP);
	ATF_TP_ADD_TC(tp, DIF_OP_RET);
	ATF_TP_ADD_TC(tp, DIF_OP_OR);
	ATF_TP_ADD_TC(tp, DIF_OP_XOR);
	ATF_TP_ADD_TC(tp, DIF_OP_AND);
	ATF_TP_ADD_TC(tp, DIF_OP_SLL);
	ATF_TP_ADD_TC(tp, DIF_OP_SRL);
	ATF_TP_ADD_TC(tp, DIF_OP_SUB);
	ATF_TP_ADD_TC(tp, DIF_OP_ADD);
	ATF_TP_ADD_TC(tp, DIF_OP_MUL);
	ATF_TP_ADD_TC(tp, DIF_OP_SDIV);
	ATF_TP_ADD_TC(tp, DIF_OP_UDIV);
	ATF_TP_ADD_TC(tp, DIF_OP_SREM);
	ATF_TP_ADD_TC(tp, DIF_OP_UREM);
	ATF_TP_ADD_TC(tp, DIF_OP_NOT);
	ATF_TP_ADD_TC(tp, DIF_OP_MOV);
	ATF_TP_ADD_TC(tp, DIF_OP_CMP_R1_GT_R2);
	ATF_TP_ADD_TC(tp, DIF_OP_CMP_R1_EQ_R2);
	ATF_TP_ADD_TC(tp, DIF_OP_CMP_R1_LT_R2);
	ATF_TP_ADD_TC(tp, DIF_OP_TST);
	ATF_TP_ADD_TC(tp, DIF_OP_BA);
	ATF_TP_ADD_TC(tp, DIF_OP_BE);
	ATF_TP_ADD_TC(tp, DIF_OP_BNE);
	ATF_TP_ADD_TC(tp, DIF_OP_BG_SUCCESS_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_BG_FAIL_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_BG_SUCCESS_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_BG_FAIL_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_BGU_SUCCESS);
	ATF_TP_ADD_TC(tp, DIF_OP_BGU_FAIL);
	ATF_TP_ADD_TC(tp, DIF_OP_BGE_SUCCESS_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_BGE_SUCCESS_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_BGE_FAIL_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_BGE_FAIL_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_BGEU_SUCCESS);
	ATF_TP_ADD_TC(tp, DIF_OP_BGEU_FAIL);
	ATF_TP_ADD_TC(tp, DIF_OP_BL_SUCCESS_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_BL_SUCCESS_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_BL_FAIL_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_BL_FAIL_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_BLU_SUCCESS);
	ATF_TP_ADD_TC(tp, DIF_OP_BLU_FAIL);
	ATF_TP_ADD_TC(tp, DIF_OP_BLE_SUCCESS_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_BLE_SUCCESS_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_BLE_FAIL_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_BLE_FAIL_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_BLEU_SUCCESS);
	ATF_TP_ADD_TC(tp, DIF_OP_BLEU_FAIL);
	ATF_TP_ADD_TC(tp, DIF_OP_LDSB_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_LDSB_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_LDSH_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_LDSH_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_LDSW_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_LDSW_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_LDX);
	ATF_TP_ADD_TC(tp, DIF_OP_LDUB);
	ATF_TP_ADD_TC(tp, DIF_OP_LDUH);
	ATF_TP_ADD_TC(tp, DIF_OP_LDUW);
	ATF_TP_ADD_TC(tp, DIF_OP_RLDSB_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_RLDSB_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_RLDSH_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_RLDSH_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_RLDSW_NEG);
	ATF_TP_ADD_TC(tp, DIF_OP_RLDSW_POS);
	ATF_TP_ADD_TC(tp, DIF_OP_RLDX);
	ATF_TP_ADD_TC(tp, DIF_OP_RLDUB);
	ATF_TP_ADD_TC(tp, DIF_OP_RLDUH);
	ATF_TP_ADD_TC(tp, DIF_OP_RLDUW);
	ATF_TP_ADD_TC(tp, DIF_OP_SCMP_EQ);
	ATF_TP_ADD_TC(tp, DIF_OP_SCMP_STR1_GT_STR2);
	ATF_TP_ADD_TC(tp, DIF_OP_SCMP_STR1_LT_STR2);
	ATF_TP_ADD_TC(tp, DIF_OP_SCMP_FAIL);
	ATF_TP_ADD_TC(tp, DIF_OP_SETX);
	ATF_TP_ADD_TC(tp, DIF_OP_SETS);
	ATF_TP_ADD_TC(tp, DIF_OP_LDTA);
	ATF_TP_ADD_TC(tp, DIF_OP_SRA);
	ATF_TP_ADD_TC(tp, DIF_OP_PUSHTR);
	ATF_TP_ADD_TC(tp, DIF_OP_PUSHTV);
	ATF_TP_ADD_TC(tp, DIF_OP_POPTS);
	ATF_TP_ADD_TC(tp, DIF_OP_FLUSHTS);
	ATF_TP_ADD_TC(tp, DIF_VAR_ARGS);
	ATF_TP_ADD_TC(tp, DIF_VAR_ARGS_ASSERT_FAIL);
	ATF_TP_ADD_TC(tp, DIF_VAR_EPID);
	ATF_TP_ADD_TC(tp, DIF_VAR_ID);
	ATF_TP_ADD_TC(tp, DIF_VAR_PROBEPROV);
	ATF_TP_ADD_TC(tp, DIF_VAR_PROBEMOD);
	ATF_TP_ADD_TC(tp, DIF_VAR_PROBEFUNC);
	ATF_TP_ADD_TC(tp, DIF_VAR_PROBENAME);
	ATF_TP_ADD_TC(tp, DIF_VAR_PID);
	ATF_TP_ADD_TC(tp, DIF_VAR_PPID);
	ATF_TP_ADD_TC(tp, DIF_VAR_TID);
	ATF_TP_ADD_TC(tp, DIF_VAR_EXECNAME);
	ATF_TP_ADD_TC(tp, DIF_VAR_ZONENAME);
	ATF_TP_ADD_TC(tp, DIF_VAR_UID);
	ATF_TP_ADD_TC(tp, DIF_VAR_GID);
	ATF_TP_ADD_TC(tp, DIF_VAR_ERRNO);
	ATF_TP_ADD_TC(tp, DIF_VAR_UNKNOWN);
	ATF_TP_ADD_TC(tp, DIF_SUBR_BCOPY);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRLEN_EXPECTED);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRLEN_NULL);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRLEN_NOT_TERMINATED);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRLEN_TOO_LONG);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRLEN_NEGATIVE_LENGTH);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRLEN_GARBAGE_PTR);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRCHR_EXPECTED);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRCHR_NON_NULL_TERMINATED);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRRCHR_EXPECTED);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRRCHR_NON_NULL_TERM);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRSTR);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRTOK);
	ATF_TP_ADD_TC(tp, DIF_SUBR_SUBSTR);
	ATF_TP_ADD_TC(tp, DIF_SUBR_TOUPPER);
	ATF_TP_ADD_TC(tp, DIF_SUBR_TOLOWER);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRJOIN);
	ATF_TP_ADD_TC(tp, DIF_SUBR_STRTOLL);
	ATF_TP_ADD_TC(tp, DIF_SUBR_LLTOSTR);
	ATF_TP_ADD_TC(tp, DIF_SUBR_HTONS);
	ATF_TP_ADD_TC(tp, DIF_SUBR_NTOHS);
#endif

	return (atf_no_error());
}
