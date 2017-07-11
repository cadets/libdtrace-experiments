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

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xD00000D;
	estate->dtes_regs[2] = 0x006F000;

	instr = DIF_INSTR_FMT(DIF_OP_OR, 1, 2, 3);
	dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0xD06F00D, estate->dtes_regs[3]);

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

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xEF90FC5;
	estate->dtes_regs[2] = 0x3FFFFC8;

	instr = DIF_INSTR_FMT(DIF_OP_XOR, 1, 2, 3);
	dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0xD06F00D, estate->dtes_regs[3]);

}

ATF_TC_WITHOUT_HEAD(DIF_OP_AND);
ATF_TC_BODY(DIF_OP_AND, tc)
{
	/*
	 * Test the XOR operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xD06F00D;
	estate->dtes_regs[2] = 0xD00000D;

	instr = DIF_INSTR_FMT(DIF_OP_AND, 1, 2, 3);
	dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0xD00000D, estate->dtes_regs[3]);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SLL);
ATF_TC_BODY(DIF_OP_SLL, tc)
{
	/*
	 * Test the XOR operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xD06; /* 0xD0G << 20 == 0xD0600000 */
	estate->dtes_regs[2] = 20;

	instr = DIF_INSTR_FMT(DIF_OP_SLL, 1, 2, 3);
	dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0xD0600000, estate->dtes_regs[3]);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SRL);
ATF_TC_BODY(DIF_OP_SRL, tc)
{
	/*
	 * Test the XOR operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 0xD0600000; /* 0xD0G00000 >> 20 == 0xD0G */
	estate->dtes_regs[2] = 20;

	instr = DIF_INSTR_FMT(DIF_OP_SRL, 1, 2, 3);
	dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0xD06, estate->dtes_regs[3]);
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

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 3344;
	estate->dtes_regs[2] = 10;

	instr = DIF_INSTR_FMT(DIF_OP_SUB, 1, 2, 3);
	dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0xD06, estate->dtes_regs[3]);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_ADD);
ATF_TC_BODY(DIF_OP_ADD, tc)
{
	/*
	 * Test the XOR operation of the DTrace machine.
	 */
	dtrace_mstate_t *mstate;
	dtrace_vstate_t *vstate;
	dtrace_state_t *state;
	dtrace_estate_t *estate;
	dif_instr_t instr;

	mstate = calloc(1, sizeof (dtrace_mstate_t));
	vstate = calloc(1, sizeof (dtrace_vstate_t));
	state = calloc(1, sizeof (dtrace_state_t));
	estate = calloc(1, sizeof (dtrace_estate_t));

	estate->dtes_regs[DIF_REG_R0] = 0;
	estate->dtes_regs[1] = 3324;
	estate->dtes_regs[2] = 10;

	instr = DIF_INSTR_FMT(DIF_OP_ADD, 1, 2, 3);
	dtrace_emul_instruction(instr, estate, mstate, vstate, state);

	ATF_CHECK_EQ(0xD06, estate->dtes_regs[3]);
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
	ATF_TP_ADD_TC(tp, DIF_OP_OR);
	ATF_TP_ADD_TC(tp, DIF_OP_XOR);
	ATF_TP_ADD_TC(tp, DIF_OP_AND);
	ATF_TP_ADD_TC(tp, DIF_OP_SLL);
	ATF_TP_ADD_TC(tp, DIF_OP_SRL);
	ATF_TP_ADD_TC(tp, DIF_OP_SUB);
	ATF_TP_ADD_TC(tp, DIF_OP_ADD);
#endif

	return (atf_no_error());
}
