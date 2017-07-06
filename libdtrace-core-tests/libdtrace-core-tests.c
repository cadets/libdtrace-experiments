#include <stdio.h>

#include <check.h>

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"

static void
dtrace_nullop(void)
{}

START_TEST(test_dtrace_init)
{
	/*
	 * Tests the initialization of the library
	 */
	int err;

	err = dtrace_init();
	ck_assert_int_eq(err, 0);
}
END_TEST

START_TEST(test_dtrace_deinit)
{
	int err;
	/*
	 * Initializes the library and tests it's de-initialization
	 */

	err = dtrace_init();
	if (err != 0)
		ck_abort_msg("DTrace not properly initialized");

	err = dtrace_deinit();

	ck_assert_int_eq(err, 0);
}
END_TEST

START_TEST(test_dtrace_providers)
{
	char *provs;
	size_t sz;
	int err;
	/*
	 * Test the dtrace_providers() function
	 */

	err = dtrace_init();
	if (err != 0)
		ck_abort_msg("DTrace not properly initialized");

	provs = dtrace_providers(&sz);

	ck_assert_int_eq(sz, 1);
	ck_assert_str_eq(provs, "dtrace");

	err = dtrace_deinit();
	if (err != 0)
		ck_abort_msg("DTrace not properly deinitialized");
}
END_TEST

START_TEST(test_dtrace_register)
{
	dtrace_provider_id_t id;
	int err;
	size_t sz;
	char (*provs)[DTRACE_PROVNAMELEN];

	static dtrace_pops_t test_provider_ops = {
		(void (*)(void *, dtrace_probedesc_t *))dtrace_nullop,
		(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
		(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
		(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
		(void (*)(void *, dtrace_id_t, void *))dtrace_nullop,
		NULL,
		NULL,
		NULL,
		(void (*)(void *, dtrace_id_t, void *))dtrace_nullop
	};

	static dtrace_pattr_t test_provider_attr = {
	{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
	{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
	{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
	{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
	{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
	};
	/*
	 * Test the provider registration
	 */

	err = dtrace_init();
	if (err)
		ck_abort_msg("DTrace not properly initialized");

	err = dtrace_register("test provider", &test_provider_attr,
	    DTRACE_PRIV_NONE, 0, &test_provider_ops, NULL, &id);
	ck_assert_int_eq(err, 0);

	provs = (char (*)[DTRACE_PROVNAMELEN]) dtrace_providers(&sz);
	ck_assert_int_eq(sz, 2);
	ck_assert_str_eq("dtrace", provs[0]);
	ck_assert_str_eq("test provider", provs[1]);

	err = dtrace_deinit();
	if (err)
		ck_abort_msg("DTrace not properly deinitialized");
}
END_TEST

START_TEST(test_dtrace_probe_create)
{
	/*
	 * Test probe creation
	 */

}
END_TEST

static Suite *
create_dtrace_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("DTrace test suite");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_dtrace_init);
	tcase_add_test(tc_core, test_dtrace_deinit);
	tcase_add_test(tc_core, test_dtrace_providers);
	tcase_add_test(tc_core, test_dtrace_register);
	tcase_add_test(tc_core, test_dtrace_probe_create);

	suite_add_tcase(s, tc_core);

	return (s);
}

int
main(void)
{
	Suite *dt_suite;
	SRunner *dt_sr;
	int n_failed;

	dt_suite = create_dtrace_suite();
	dt_sr = srunner_create(dt_suite);

	srunner_run_all(dt_sr, CK_NORMAL);
	n_failed = srunner_ntests_failed(dt_sr);

	srunner_free(dt_sr);

	return ((n_failed > 0) ? 1 : 0);
}

