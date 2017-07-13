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
(uint64_t (*)(void *, dtrace_id_t, void *, int, int))dtrace_nullop,
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
#endif

	return (atf_no_error());
}
