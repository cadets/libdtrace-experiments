#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <atf-c.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"
#include "../test-api/dtrace_api.h"

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
	dtapi_conf_t *dtapi_conf;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_nop(dtapi_conf, &err);
	ATF_CHECK_EQ(0, err);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_RET);
ATF_TC_BODY(DIF_OP_RET, tc)
{
	/*
	 * Test the OR operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint_t pc;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_set_textlen(dtapi_conf, 1000);
	pc = dtapi_op_ret(dtapi_conf, &err);
	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(1000, pc);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_OR);
ATF_TC_BODY(DIF_OP_OR, tc)
{
	/*
	 * Test the OR operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t r1, r2, rd;
	int err;

	r1 = 0xD00000D;
	r2 = 0x006F000;
	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_or(dtapi_conf, r1, r2, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06F00D, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_XOR);
ATF_TC_BODY(DIF_OP_XOR, tc)
{
	/*
	 * Test the XOR operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t r1, r2, rd;
	int err;

	r1 = 0xEF90FC5;
	r2 = 0x3FFFFC8;
	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_xor(dtapi_conf, r1, r2, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06F00D, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_AND);
ATF_TC_BODY(DIF_OP_AND, tc)
{
	/*
	 * Test the AND operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t r1, r2, rd;
	int err;

	r1 = 0xD06F00D;
	r2 = 0xD00000D;
	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_and(dtapi_conf, r1, r2, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD00000D, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SLL);
ATF_TC_BODY(DIF_OP_SLL, tc)
{
	/*
	 * Test the SLL operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t r1, r2, rd;
	int err;

	r1 = 0xD06; /* 0xD0G << 20 == 0xD0600000 */
	r2 = 20;
	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_sll(dtapi_conf, r1, r2, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD0600000, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SRL);
ATF_TC_BODY(DIF_OP_SRL, tc)
{
	/*
	 * Test the SRL operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t r1, r2, rd;
	int err;

	r1 = 0xD0600000; /* 0xD0G00000 >> 20 == 0xD0G */
	r2 = 20;
	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_srl(dtapi_conf, r1, r2, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SUB);
ATF_TC_BODY(DIF_OP_SUB, tc)
{
	/*
	 * Test the SUB operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_sub(dtapi_conf, 0xD06E, 0xC368, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_ADD);
ATF_TC_BODY(DIF_OP_ADD, tc)
{
	/*
	 * Test the ADD operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_add(dtapi_conf, 0xD06, 0xC368, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_MUL);
ATF_TC_BODY(DIF_OP_MUL, tc)
{
	/*
	 * Test the MUL operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_mul(dtapi_conf, 1024, 2, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2048, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SDIV);
ATF_TC_BODY(DIF_OP_SDIV, tc)
{
	/*
	 * Test the SDIV operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_sdiv(dtapi_conf, 1024, -2, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(-512, rd);

	rd = dtapi_op_sdiv(dtapi_conf, -1024, 2, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(-512, rd);

	rd = dtapi_op_sdiv(dtapi_conf, 1024, 2, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(512, rd);

	rd = dtapi_op_sdiv(dtapi_conf, -1024, -2, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(512, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_UDIV);
ATF_TC_BODY(DIF_OP_UDIV, tc)
{
	/*
	 * Test the UDIV operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_udiv(dtapi_conf, 1024, 2, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(512, rd);

	rd = dtapi_op_udiv(dtapi_conf, 1024, 0, &err);

	ATF_CHECK_EQ(EINVAL, err);
	ATF_CHECK_EQ(0, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SREM);
ATF_TC_BODY(DIF_OP_SREM, tc)
{
	/*
	 * Test the SREM operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_srem(dtapi_conf, 1024, 513, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(511, rd);

	rd = dtapi_op_srem(dtapi_conf, 1024, -513, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(511, rd);

	rd = dtapi_op_srem(dtapi_conf, -1024, 513, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(-511, rd);

	rd = dtapi_op_srem(dtapi_conf, -1024, -513, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(-511, rd);

	rd = dtapi_op_srem(dtapi_conf, 1024, 0, &err);

	ATF_CHECK_EQ(EINVAL, err);
	ATF_CHECK_EQ(0, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_UREM);
ATF_TC_BODY(DIF_OP_UREM, tc)
{
	/*
	 * Test the UREM operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_urem(dtapi_conf, 1024, 513, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(511, rd);

	rd = dtapi_op_urem(dtapi_conf, 1024, 0, &err);

	ATF_CHECK_EQ(EINVAL, err);
	ATF_CHECK_EQ(0, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_NOT);
ATF_TC_BODY(DIF_OP_NOT, tc)
{
	/*
	 * Test the NOT operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_not(dtapi_conf, 0, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xFFFFFFFFFFFFFFFF, rd);

	rd = dtapi_op_not(dtapi_conf, 0xD06ED00D, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xFFFFFFFF2F912FF2, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_MOV);
ATF_TC_BODY(DIF_OP_MOV, tc)
{
	/*
	 * Test the MOV operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	uint64_t rd;
	int err;

	rd = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	rd = dtapi_op_mov(dtapi_conf, 1234, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(1234, rd);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_CMP_R1_GT_R2);
ATF_TC_BODY(DIF_OP_CMP_R1_GT_R2, tc)
{
	/*
	 * Test the CMP operation of the DTrace machine when r1 is greater than
	 * r2.
	 */
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_cmp(dtapi_conf, 20, 5, &err);

	dtapi_state = dtapi_getstate(dtapi_conf);
	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(15, dtapi_state->cc_r);
	ATF_CHECK_EQ(0, dtapi_state->cc_n);
	ATF_CHECK_EQ(0, dtapi_state->cc_z);
	ATF_CHECK_EQ(0, dtapi_state->cc_v);
	ATF_CHECK_EQ(0, dtapi_state->cc_c);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_CMP_R1_EQ_R2);
ATF_TC_BODY(DIF_OP_CMP_R1_EQ_R2, tc)
{
	/*
	 * Test the CMP operation of the DTrace machine when r1 is equal to r2.
	 */
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_cmp(dtapi_conf, 20, 20, &err);

	dtapi_state = dtapi_getstate(dtapi_conf);
	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, dtapi_state->cc_r);
	ATF_CHECK_EQ(0, dtapi_state->cc_n);
	ATF_CHECK_EQ(1, dtapi_state->cc_z);
	ATF_CHECK_EQ(0, dtapi_state->cc_v);
	ATF_CHECK_EQ(0, dtapi_state->cc_c);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_CMP_R1_LT_R2);
ATF_TC_BODY(DIF_OP_CMP_R1_LT_R2, tc)
{
	/*
	 * Test the CMP operation of the DTrace machine when r1 is lesser than
	 * r2.
	 */
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_cmp(dtapi_conf, 10, 20, &err);

	dtapi_state = dtapi_getstate(dtapi_conf);
	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(-10, dtapi_state->cc_r);
	ATF_CHECK_EQ(1, dtapi_state->cc_n);
	ATF_CHECK_EQ(0, dtapi_state->cc_z);
	ATF_CHECK_EQ(0, dtapi_state->cc_v);
	ATF_CHECK_EQ(1, dtapi_state->cc_c);

	dtapi_deinit(dtapi_conf);
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
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_tst(dtapi_conf, 1, &err);

	dtapi_state = dtapi_getstate(dtapi_conf);
	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, dtapi_state->cc_n);
	ATF_CHECK_EQ(0, dtapi_state->cc_z);
	ATF_CHECK_EQ(0, dtapi_state->cc_v);
	ATF_CHECK_EQ(0, dtapi_state->cc_c);

	dtapi_op_tst(dtapi_conf, 0, &err);

	dtapi_state = dtapi_getstate(dtapi_conf);
	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, dtapi_state->cc_n);
	ATF_CHECK_EQ(1, dtapi_state->cc_z);
	ATF_CHECK_EQ(0, dtapi_state->cc_v);
	ATF_CHECK_EQ(0, dtapi_state->cc_c);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BA);
ATF_TC_BODY(DIF_OP_BA, tc)
{
	/*
	 * Test the BA operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	uint_t pc;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	pc = dtapi_op_ba(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, pc);

	dtapi_deinit(dtapi_conf);
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
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	uint_t pc;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_cmp(dtapi_conf, 7, 7, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_be(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, pc);

	dtapi_op_cmp(dtapi_conf, 7, 8, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_be(dtapi_conf, 0, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, pc);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BNE);
ATF_TC_BODY(DIF_OP_BNE, tc)
{
	/*
	 * Test the BNE operation of the DTrace machine.
	 */
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	uint_t pc;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_cmp(dtapi_conf, 7, 7, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bne(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, pc);

	dtapi_op_cmp(dtapi_conf, 7, 8, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bne(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, pc);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BG);
ATF_TC_BODY(DIF_OP_BG, tc)
{
	/*
	 * Test the BG operation of the DTrace machine when it branches.
	 */
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	uint_t pc;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_cmp(dtapi_conf, 7, 8, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bg(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, pc);

	dtapi_op_cmp(dtapi_conf, 8, 7, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bg(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, pc);

	dtapi_op_cmp(dtapi_conf, 7, 7, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bg(dtapi_conf, 0, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, pc);

	dtapi_op_cmp(dtapi_conf, -7, 7, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bg(dtapi_conf, 0, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, pc);

	dtapi_op_cmp(dtapi_conf, 7, -7, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bg(dtapi_conf, 0, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, pc);

	dtapi_op_cmp(dtapi_conf, -7, -7, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bg(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, pc);

	dtapi_op_cmp(dtapi_conf, -7, -10, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bg(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, pc);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_BGU);
ATF_TC_BODY(DIF_OP_BGU, tc)
{
	/*
	 * Test the BGU operation of the DTrace machine when it branches.
	 */
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	uint_t pc;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_cmp(dtapi_conf, 7, 8, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bgu(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, pc);

	dtapi_op_cmp(dtapi_conf, 8, 7, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bgu(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, pc);

	dtapi_op_cmp(dtapi_conf, 7, 7, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bgu(dtapi_conf, 0, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, pc);

	dtapi_op_cmp(dtapi_conf, -7, 7, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bgu(dtapi_conf, 0, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, pc);

	dtapi_op_cmp(dtapi_conf, 7, -7, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bgu(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, pc);

	dtapi_op_cmp(dtapi_conf, -7, -7, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bgu(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, pc);

	dtapi_op_cmp(dtapi_conf, -7, -10, &err);
	ATF_CHECK_EQ(0, err);
	pc = dtapi_op_bgu(dtapi_conf, 0xD06E, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0xD06E, pc);

	dtapi_deinit(dtapi_conf);
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
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	const char *str1 = "foo";
	const char *str2 = "foo";
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_scmp(dtapi_conf, (uintptr_t) str1, (uintptr_t) str2, &err);

	dtapi_state = dtapi_getstate(dtapi_conf);
	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, dtapi_state->cc_r);
	ATF_CHECK_EQ(0, dtapi_state->cc_n);
	ATF_CHECK_EQ(1, dtapi_state->cc_z);
	ATF_CHECK_EQ(0, dtapi_state->cc_v);
	ATF_CHECK_EQ(0, dtapi_state->cc_c);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SCMP_STR1_GT_STR2);
ATF_TC_BODY(DIF_OP_SCMP_STR1_GT_STR2, tc)
{
	/*
	 * Test the SCMP operation of the DTrace machine when the the first
	 * string has a letter that is greater in ASCII value than the second
	 * string.
	 */
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	const char *str1 = "foo";
	const char *str2 = "eoo";
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_scmp(dtapi_conf, (uintptr_t) str1, (uintptr_t) str2, &err);

	dtapi_state = dtapi_getstate(dtapi_conf);
	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(('f' - 'e'), dtapi_state->cc_r);
	ATF_CHECK_EQ(('f' - 'e') < 0, dtapi_state->cc_n);
	ATF_CHECK_EQ(('f' - 'e') == 0, dtapi_state->cc_z);
	ATF_CHECK_EQ(0, dtapi_state->cc_v);
	ATF_CHECK_EQ(0, dtapi_state->cc_c);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_OP_SCMP_STR1_LT_STR2);
ATF_TC_BODY(DIF_OP_SCMP_STR1_LT_STR2, tc)
{
	/*
	 * Test the SCMP operation of the DTrace machine when the the first
	 * string has a letter that is lesser in ASCII value than the second
	 * string.
	 */
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	const char *str1 = "eoo";
	const char *str2 = "foo";
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dtapi_op_scmp(dtapi_conf, (uintptr_t) str1, (uintptr_t) str2, &err);

	dtapi_state = dtapi_getstate(dtapi_conf);
	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(('e' - 'f'), dtapi_state->cc_r);
	ATF_CHECK_EQ(('e' - 'f') < 0, dtapi_state->cc_n);
	ATF_CHECK_EQ(('e' - 'f') == 0, dtapi_state->cc_z);
	ATF_CHECK_EQ(0, dtapi_state->cc_v);
	ATF_CHECK_EQ(0, dtapi_state->cc_c);

	dtapi_deinit(dtapi_conf);
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
	dtapi_conf_t *dtapi_conf;
	dtapi_state_t *dtapi_state;
	const char *str1 = "foooooooooooooooo";
	const char *str2 = "foooobaaaaaaaaaar";
	int err;

	dtapi_conf = dtapi_init(100, 5, DTRACE_ACCESS_KERNEL);
	dtapi_op_scmp(dtapi_conf, (uintptr_t) str1, (uintptr_t) str2, &err);

	dtapi_state = dtapi_getstate(dtapi_conf);
	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, dtapi_state->cc_r);
	ATF_CHECK_EQ(0, dtapi_state->cc_n);
	ATF_CHECK_EQ(1, dtapi_state->cc_z);
	ATF_CHECK_EQ(0, dtapi_state->cc_v);
	ATF_CHECK_EQ(0, dtapi_state->cc_c);

	dtapi_deinit(dtapi_conf);
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
	dtapi_conf_t *dtapi_conf;
	const char *s = "test";
	size_t s_size;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	s_size = 0;
	s_size = dtapi_strlen(dtapi_conf, s, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(4, s_size);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_BCOPY);
ATF_TC_BODY(DIF_SUBR_BCOPY, tc)
{
	/*
	 * Test the bcopy() subroutine.
	 */
	dtapi_conf_t *dtapi_conf;
	dif_instr_t instr;
	int err;
	const char *string = "hello";
	char *dst;
	size_t string_len;

	string_len = strlen(string);
	err = 0;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	dst = dtapi_bcopy(dtapi_conf, string, string_len + 1, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK(dst != NULL);
	if (dst) {
		ATF_CHECK_EQ(string_len, strlen(dst));
		ATF_CHECK_STREQ(string, dst);
	}

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRLEN_NULL);
ATF_TC_BODY(DIF_SUBR_STRLEN_NULL, tc)
{
	/*
	 * Test the strlen() subroutine given a NULL pointer.
	 */
	dtapi_conf_t *dtapi_conf;
	size_t s_size;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	s_size = 0;
	s_size = dtapi_strlen(dtapi_conf, NULL, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, s_size);

	dtapi_deinit(dtapi_conf);
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
	dtapi_conf_t *dtapi_conf;
	char *string = malloc(4);
	strncpy(string, "test", 4);
	size_t s_size;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	s_size = 0;
	s_size = dtapi_strlen(dtapi_conf, string, &err);

	atf_tc_expect_fail("It is unbounded, DTrace keeps reading to DTRACEOPT_STRSIZE, length is: %zu", s_size);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(4, s_size);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRLEN_TOO_LONG);
ATF_TC_BODY(DIF_SUBR_STRLEN_TOO_LONG, tc)
{
	/*
	 * Test the strlen() subroutine given a string that's too long.
	 *
	 * Expected output is the DTRACEOPT_STRSIZE boundary.
	 */
	dtapi_conf_t *dtapi_conf;
	size_t s_size;
	int err;
	char *string = malloc(300);

	strncpy(string, "testiuwhaufiwehfewhdiewuihfeiwhidhewfuewhdiehfiwaehiufewhiufewuuwhiuewfieduiwehfiuwehdihweifhwehdieuwhfiewdiwuehfiwehfuewi", 300);

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	s_size = 0;
	s_size = dtapi_strlen(dtapi_conf, string, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(20, s_size);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRLEN_NEGATIVE_LENGTH);
ATF_TC_BODY(DIF_SUBR_STRLEN_NEGATIVE_LENGTH, tc)
{
	/*
	 * Test the strlen() subroutine given a regular string and negative
	 * size.
	 */
	dtapi_conf_t *dtapi_conf;
	const char *s = "hello";
	size_t s_size;
	int err;

	dtapi_conf = dtapi_init(100, -20, DTRACE_ACCESS_KERNEL);
	s_size = 0;
	s_size = dtapi_strlen(dtapi_conf, s, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(5, s_size);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRLEN_GARBAGE_PTR);
ATF_TC_BODY(DIF_SUBR_STRLEN_GARBAGE_PTR, tc)
{
	/*
	 * Test strlen() by giving a garbage pointer. Breaks in userspace, is
	 * fine in the kernel.
	 */
	dtapi_conf_t *dtapi_conf;
	size_t s_size;
	int err;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	s_size = 0;

	atf_tc_expect_death("Accessing garbage");
	s_size = dtapi_strlen(dtapi_conf, (char *) 123, &err);
	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRCHR_EXPECTED);
ATF_TC_BODY(DIF_SUBR_STRCHR_EXPECTED, tc)
{
	/*
	 * Test the strchr() subroutine given expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *string = "hello world";
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_strchr(dtapi_conf, string, 'l', &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(2, (uintptr_t) retstr - (uintptr_t) string);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRCHR_NON_NULL_TERMINATED);
ATF_TC_BODY(DIF_SUBR_STRCHR_NON_NULL_TERMINATED, tc)
{
	/*
	 * Test the strchr() subroutine given a non-NULL terminated string.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	char string[11] = "hello world";
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_strchr(dtapi_conf, string, 'x', &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(NULL, retstr);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRRCHR_EXPECTED);
ATF_TC_BODY(DIF_SUBR_STRRCHR_EXPECTED, tc)
{
	/*
	 * Test the strrchr() subroutine given expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *string = "hello world";
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_strrchr(dtapi_conf, string, 'r', &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(8, (uintptr_t) retstr - (uintptr_t) string);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRRCHR_NON_NULL_TERM);
ATF_TC_BODY(DIF_SUBR_STRRCHR_NON_NULL_TERM, tc)
{
	/*
	 * Test the strrchr() subroutine given a non-NULL terminated string.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *string = "hello world";
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_strrchr(dtapi_conf, string, 'x', &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(NULL, retstr);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRSTR);
ATF_TC_BODY(DIF_SUBR_STRSTR, tc)
{
	/*
	 * Test the strstr() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *big = "hello world";
	const char *little = "world";
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_strstr(dtapi_conf, big, little, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ((uintptr_t) big + sizeof("hello ") - 1, (uintptr_t) retstr);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRTOK);
ATF_TC_BODY(DIF_SUBR_STRTOK, tc)
{
	/*
	 * Test the strtok() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	char *str = "hello-world";
	const char *tokenby = "-";
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_strtok(dtapi_conf, str, tokenby, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("world", retstr);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_SUBSTR);
ATF_TC_BODY(DIF_SUBR_SUBSTR, tc)
{
	/*
	 * Test the substr() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *str = "hello world";
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_substr(dtapi_conf, str, 0, sizeof("hello") - 1, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("hello", retstr);

	dtapi_deinit(dtapi_conf);
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
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *str = "HEllO WoRlD";
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_toupper(dtapi_conf, str, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("HELLO WORLD", retstr);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_TOLOWER);
ATF_TC_BODY(DIF_SUBR_TOLOWER, tc)
{
	/*
	 * Test the tolower() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *str = "HEllO WoRlD";
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_tolower(dtapi_conf, str, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("hello world", retstr);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRJOIN);
ATF_TC_BODY(DIF_SUBR_STRJOIN, tc)
{
	/*
	 * Test the strjoin() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *first = "hello ";
	const char *second = "world";
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_strjoin(dtapi_conf, first, second, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("hello world", retstr);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_STRTOLL);
ATF_TC_BODY(DIF_SUBR_STRTOLL, tc)
{
	/*
	 * Test the strtoll() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *strnum = "4213";
	const char *strnonnum = "abc";
	const char *leadzero = "00000001";
	int64_t retnum;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retnum = dtapi_strtoll(dtapi_conf, strnum, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(4213, retnum);

	retnum = dtapi_strtoll(dtapi_conf, strnonnum, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0, retnum);

	retnum = dtapi_strtoll(dtapi_conf, leadzero, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(1, retnum);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_LLTOSTR);
ATF_TC_BODY(DIF_SUBR_LLTOSTR, tc)
{
	/*
	 * Test the lltostr() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	long long num = 12423000;
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_lltostr(dtapi_conf, num, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("12423000", retstr);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_HTONS);
ATF_TC_BODY(DIF_SUBR_HTONS, tc)
{
	/*
	 * Test the htons() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint16_t host = 0x1234;
#else
	uint16_t host = 0x3412;
#endif
	uint16_t retnum;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retnum = dtapi_htons(dtapi_conf, host, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0x3412, retnum);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_HTONL);
ATF_TC_BODY(DIF_SUBR_HTONL, tc)
{
	/*
	 * Test the htonl() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint32_t host = 0x3456789A;
#else
	uint32_t host = 0x9A785634;
#endif
	uint32_t retnum;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retnum = dtapi_htonl(dtapi_conf, host, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0x9A785634, retnum);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_HTONLL);
ATF_TC_BODY(DIF_SUBR_HTONLL, tc)
{
	/*
	 * Test the htonll() subroutine given an expected input.
	 */

	dtapi_conf_t *dtapi_conf;
	int err;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint64_t host = 0x123456789A;
#else
	uint64_t host = 0x9A78563412000000;
#endif
	uint64_t retnum;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retnum = dtapi_htonll(dtapi_conf, host, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(0x9A78563412000000, retnum);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_NTOHS);
ATF_TC_BODY(DIF_SUBR_NTOHS, tc)
{
	/*
	 * Test the ntohs() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	uint64_t network = 0x1234;
	uint64_t retnum;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retnum = dtapi_ntohs(dtapi_conf, network, &err);

#if BYTE_ORDER == LITTLE_ENDIAN
	ATF_CHECK_EQ(0x3412, retnum);
#else
	ATF_CHECK_EQ(0x1234, retnum);
#endif

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_NTOHL);
ATF_TC_BODY(DIF_SUBR_NTOHL, tc)
{
	/*
	 * Test the ntohl() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	uint64_t network = 0x12345600;
	uint64_t retnum;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retnum = dtapi_ntohl(dtapi_conf, network, &err);

#if BYTE_ORDER == LITTLE_ENDIAN
	ATF_CHECK_EQ(0x563412, retnum);
#else
	ATF_CHECK_EQ(0x12345600, retnum);
#endif

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_NTOHLL);
ATF_TC_BODY(DIF_SUBR_NTOHLL, tc)
{
	/*
	 * Test the ntohll() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	uint64_t network = 0x123456789A000000;
	uint64_t retnum;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retnum = dtapi_ntohll(dtapi_conf, network, &err);

#if BYTE_ORDER == LITTLE_ENDIAN
	ATF_CHECK_EQ(0x9A78563412, retnum);
#else
	ATF_CHECK_EQ(0x123456789A000000, retnum);
#endif

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_DIRNAME);
ATF_TC_BODY(DIF_SUBR_DIRNAME, tc)
{
	/*
	 * Test the dirname() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *str = "test/foo/bar/baz";
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_dirname(dtapi_conf, str, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("test/foo/bar", retstr);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_BASENAME);
ATF_TC_BODY(DIF_SUBR_BASENAME, tc)
{
	/*
	 * Test the basename() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *str = "test/foo/bar/baz";
	char *retstr;

	dtapi_conf = dtapi_init(100, 20, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_basename(dtapi_conf, str, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("baz", retstr);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_CLEANPATH);
ATF_TC_BODY(DIF_SUBR_CLEANPATH, tc)
{
	/*
	 * Test the cleanpath() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *str = "////test///foo//bar//baz";
	char *retstr;

	dtapi_conf = dtapi_init(100, 100, DTRACE_ACCESS_KERNEL);
	retstr = dtapi_cleanpath(dtapi_conf, str, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_STREQ("/test/foo/bar/baz", retstr);

	dtapi_deinit(dtapi_conf);
}

ATF_TC_WITHOUT_HEAD(DIF_SUBR_MEMREF);
ATF_TC_BODY(DIF_SUBR_MEMREF, tc)
{
	/*
	 * Test the memref() subroutine given an expected input.
	 */
	dtapi_conf_t *dtapi_conf;
	int err;
	const char *str = "hello world";
	size_t str_len;
	uintptr_t *memref;

	str_len = strlen(str);

	dtapi_conf = dtapi_init(100, 100, DTRACE_ACCESS_KERNEL);
	memref = dtapi_memref(dtapi_conf, (uintptr_t) str, str_len, &err);

	ATF_CHECK_EQ(0, err);
	ATF_CHECK_EQ(memref[0], (uintptr_t) str);
	ATF_CHECK_EQ(memref[1], str_len);

	dtapi_deinit(dtapi_conf);
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
	ATF_TP_ADD_TC(tp, DIF_OP_BG);
	ATF_TP_ADD_TC(tp, DIF_OP_BGU);
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
	ATF_TP_ADD_TC(tp, DIF_SUBR_HTONL);
	ATF_TP_ADD_TC(tp, DIF_SUBR_HTONLL);
	ATF_TP_ADD_TC(tp, DIF_SUBR_NTOHS);
	ATF_TP_ADD_TC(tp, DIF_SUBR_NTOHL);
	ATF_TP_ADD_TC(tp, DIF_SUBR_NTOHLL);
	ATF_TP_ADD_TC(tp, DIF_SUBR_DIRNAME);
	ATF_TP_ADD_TC(tp, DIF_SUBR_BASENAME);
	ATF_TP_ADD_TC(tp, DIF_SUBR_CLEANPATH);
	ATF_TP_ADD_TC(tp, DIF_SUBR_MEMREF);
#endif

	return (atf_no_error());
}
