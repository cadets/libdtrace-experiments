#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtrace.h"
#include "dtrace_impl.h"

#define	WPRINTF(...) (printf("Warning: " __VA_ARGS__))
#define	DTRACE_ISALPHA(c)	\
	(((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z'))
#define	DTRACE_DYNHASH_FREE	0
#define	DTRACE_DYNHASH_SINK	1
#define	DTRACE_DYNHASH_VALID	2

#define	DTRACE_MATCH_NEXT	0
#define	DTRACE_MATCH_DONE	1
#define	DTRACE_ANCHORED(probe)	((probe)->dtpr_func[0] != '\0')
#define	DTRACE_STATE_ALIGN	64

dtrace_provider_t *dtrace_provider;
static dtrace_enabling_t *dtrace_retained;
static dtrace_genid_t	dtrace_retained_gen;	/* current retained enab gen */
static dtrace_genid_t	dtrace_probegen;	/* current probe generation */

static size_t dtrace_strlen(const char *, size_t);
static dtrace_probe_t *dtrace_probe_lookup_id(dtrace_id_t id);
static void dtrace_enabling_provide(dtrace_provider_t *);
static int dtrace_enabling_match(dtrace_enabling_t *, int *);
static void dtrace_enabling_matchall(void);
static void dtrace_enabling_reap(void);
static dtrace_state_t *dtrace_anon_grab(void);
static void dtrace_buffer_drop(dtrace_buffer_t *);
static int dtrace_buffer_consumed(dtrace_buffer_t *, hrtime_t when);
static intptr_t dtrace_buffer_reserve(dtrace_buffer_t *, size_t, size_t,
    dtrace_state_t *, dtrace_mstate_t *);
static int dtrace_state_option(dtrace_state_t *, dtrace_optid_t,
    dtrace_optval_t);
static int dtrace_ecb_create_enable(dtrace_probe_t *, void *);
uint16_t dtrace_load16(uintptr_t);
uint32_t dtrace_load32(uintptr_t);
uint64_t dtrace_load64(uintptr_t);
uint8_t dtrace_load8(uintptr_t);
void dtrace_dynvar_clean(dtrace_dstate_t *);
dtrace_dynvar_t *dtrace_dynvar(dtrace_dstate_t *, uint_t, dtrace_key_t *,
    size_t, dtrace_dynvar_op_t, dtrace_mstate_t *, dtrace_vstate_t *);
uintptr_t dtrace_dif_varstr(uintptr_t, dtrace_state_t *, dtrace_mstate_t *);
static int dtrace_priv_proc(dtrace_state_t *);
static void dtrace_getf_barrier(void);
static int dtrace_canload_remains(uint64_t, size_t, size_t *,
    dtrace_mstate_t *, dtrace_vstate_t *);
static int dtrace_canstore_remains(uint64_t, size_t, size_t *,
    dtrace_mstate_t *, dtrace_vstate_t *);

static void dtrace_nullop(void) {}

static dtrace_ecb_t *
dtrace_ecb_create(dtrace_state_t *state, dtrace_probe_t *probe,
    dtrace_enabling_t *enab)
{
#if 0
	dtrace_ecb_t *ecb;
	dtrace_predicate_t *pred;
	dtrace_actdesc_t *act;
	dtrace_provider_t *prov;
	dtrace_ecbdesc_t *desc = enab->dten_current;

	ASSERT(state != NULL);

	ecb = dtrace_ecb_add(state, probe);
	ecb->dte_uarg = desc->dted_uarg;

	if ((pred = desc->dted_pred.dtpdd_predicate) != NULL) {
		dtrace_predicate_hold(pred);
		ecb->dte_predicate = pred;
	}

	if (probe != NULL) {
		/*
		 * If the provider shows more leg than the consumer is old
		 * enough to see, we need to enable the appropriate implicit
		 * predicate bits to prevent the ecb from activating at
		 * revealing times.
		 *
		 * Providers specifying DTRACE_PRIV_USER at register time
		 * are stating that they need the /proc-style privilege
		 * model to be enforced, and this is what DTRACE_COND_OWNER
		 * and DTRACE_COND_ZONEOWNER will then do at probe time.
		 */
		prov = probe->dtpr_provider;
		if (!(state->dts_cred.dcr_visible & DTRACE_CRV_ALLPROC) &&
		    (prov->dtpv_priv.dtpp_flags & DTRACE_PRIV_USER))
			ecb->dte_cond |= DTRACE_COND_OWNER;

		if (!(state->dts_cred.dcr_visible & DTRACE_CRV_ALLZONE) &&
		    (prov->dtpv_priv.dtpp_flags & DTRACE_PRIV_USER))
			ecb->dte_cond |= DTRACE_COND_ZONEOWNER;

		/*
		 * If the provider shows us kernel innards and the user
		 * is lacking sufficient privilege, enable the
		 * DTRACE_COND_USERMODE implicit predicate.
		 */
		if (!(state->dts_cred.dcr_visible & DTRACE_CRV_KERNEL) &&
		    (prov->dtpv_priv.dtpp_flags & DTRACE_PRIV_KERNEL))
			ecb->dte_cond |= DTRACE_COND_USERMODE;
	}

	if (dtrace_ecb_create_cache != NULL) {
		/*
		 * If we have a cached ecb, we'll use its action list instead
		 * of creating our own (saving both time and space).
		 */
		dtrace_ecb_t *cached = dtrace_ecb_create_cache;
		dtrace_action_t *act = cached->dte_action;

		if (act != NULL) {
			ASSERT(act->dta_refcnt > 0);
			act->dta_refcnt++;
			ecb->dte_action = act;
			ecb->dte_action_last = cached->dte_action_last;
			ecb->dte_needed = cached->dte_needed;
			ecb->dte_size = cached->dte_size;
			ecb->dte_alignment = cached->dte_alignment;
		}

		return (ecb);
	}

	for (act = desc->dted_action; act != NULL; act = act->dtad_next) {
		if ((enab->dten_error = dtrace_ecb_action_add(ecb, act)) != 0) {
			dtrace_ecb_destroy(ecb);
			return (NULL);
		}
	}

	if ((enab->dten_error = dtrace_ecb_resize(ecb)) != 0) {
		dtrace_ecb_destroy(ecb);
		return (NULL);
	}

	return (dtrace_ecb_create_cache = ecb);
#endif
	return (NULL);
}
static void
dtrace_ecb_enable(dtrace_ecb_t *ecb)
{
	dtrace_probe_t *probe = ecb->dte_probe;

	ASSERT(ecb->dte_next == NULL);

	if (probe == NULL) {
		/*
		 * This is the NULL probe -- there's nothing to do.
		 */
		return;
	}

	if (probe->dtpr_ecb == NULL) {
		dtrace_provider_t *prov = probe->dtpr_provider;

		/*
		 * We're the first ECB on this probe.
		 */
		probe->dtpr_ecb = probe->dtpr_ecb_last = ecb;

		if (ecb->dte_predicate != NULL)
			probe->dtpr_predcache = ecb->dte_predicate->dtp_cacheid;

		prov->dtpv_pops.dtps_enable(prov->dtpv_arg,
		    probe->dtpr_id, probe->dtpr_arg);
	} else {
		/*
		 * This probe is already active.  Swing the last pointer to
		 * point to the new ECB, and issue a dtrace_sync() to assure
		 * that all CPUs have seen the change.
		 */
		ASSERT(probe->dtpr_ecb_last != NULL);
		probe->dtpr_ecb_last->dte_next = ecb;
		probe->dtpr_ecb_last = ecb;
		probe->dtpr_predcache = 0;
	}
}

static int
dtrace_match_glob(const char *s, const char *p, int depth)
{
	const char *olds;
	char s1, c;
	int gs;

	if (depth > DTRACE_PROBEKEY_MAXDEPTH)
		return (-1);

	if (s == NULL)
		s = ""; /* treat NULL as empty string */

top:
	olds = s;
	s1 = *s++;

	if (p == NULL)
		return (0);

	if ((c = *p++) == '\0')
		return (s1 == '\0');

	switch (c) {
	case '[': {
		int ok = 0, notflag = 0;
		char lc = '\0';

		if (s1 == '\0')
			return (0);

		if (*p == '!') {
			notflag = 1;
			p++;
		}

		if ((c = *p++) == '\0')
			return (0);

		do {
			if (c == '-' && lc != '\0' && *p != ']') {
				if ((c = *p++) == '\0')
					return (0);
				if (c == '\\' && (c = *p++) == '\0')
					return (0);

				if (notflag) {
					if (s1 < lc || s1 > c)
						ok++;
					else
						return (0);
				} else if (lc <= s1 && s1 <= c)
					ok++;

			} else if (c == '\\' && (c = *p++) == '\0')
				return (0);

			lc = c; /* save left-hand 'c' for next iteration */

			if (notflag) {
				if (s1 != c)
					ok++;
				else
					return (0);
			} else if (s1 == c)
				ok++;

			if ((c = *p++) == '\0')
				return (0);

		} while (c != ']');

		if (ok)
			goto top;

		return (0);
	}

	case '\\':
		if ((c = *p++) == '\0')
			return (0);
		/*FALLTHRU*/

	default:
		if (c != s1)
			return (0);
		/*FALLTHRU*/

	case '?':
		if (s1 != '\0')
			goto top;
		return (0);

	case '*':
		while (*p == '*')
			p++; /* consecutive *'s are identical to a single one */

		if (*p == '\0')
			return (1);

		for (s = olds; *s != '\0'; s++) {
			if ((gs = dtrace_match_glob(s, p, depth + 1)) != 0)
				return (gs);
		}

		return (0);
	}
}


static int
dtrace_match_string(const char *s, const char *p, int depth)
{
	return (s != NULL && strcmp(s, p) == 0);
}

/*ARGSUSED*/
static int
dtrace_match_nul(const char *s, const char *p, int depth)
{
	return (1); /* always match the empty pattern */
}

static int
dtrace_match_nonzero(const char *s, const char *p, int depth)
{
	return (s != NULL && s[0] != '\0');
}

static dtrace_probekey_f *
dtrace_probekey_func(const char *p)
{
	char c;

	if (p == NULL || *p == '\0')
		return (&dtrace_match_nul);

	while ((c = *p++) != '\0') {
		if (c == '[' || c == '?' || c == '*' || c == '\\')
			return (&dtrace_match_glob);
	}

	return (&dtrace_match_string);
}

static int
dtrace_ecb_create_enable(dtrace_probe_t *probe, void *arg)
{
	dtrace_ecb_t *ecb;
	dtrace_enabling_t *enab = arg;
	dtrace_state_t *state = enab->dten_vstate->dtvs_state;

	ASSERT(state != NULL);

	if (probe != NULL && probe->dtpr_gen < enab->dten_probegen) {
		/*
		 * This probe was created in a generation for which this
		 * enabling has previously created ECBs; we don't want to
		 * enable it again, so just kick out.
		 */
		return (DTRACE_MATCH_NEXT);
	}

	if ((ecb = dtrace_ecb_create(state, probe, enab)) == NULL)
		return (DTRACE_MATCH_DONE);

	dtrace_ecb_enable(ecb);
	return (DTRACE_MATCH_NEXT);
}

static int
dtrace_probe_enable(dtrace_probedesc_t *desc, dtrace_enabling_t *enab)
{
#if 0
	dtrace_probekey_t pkey;
	uint32_t priv;
	uid_t uid;
	zoneid_t zoneid;

	dtrace_ecb_create_cache = NULL;

	if (desc == NULL) {
		/*
		 * If we're passed a NULL description, we're being asked to
		 * create an ECB with a NULL probe.
		 */
		(void) dtrace_ecb_create_enable(NULL, enab);
		return (0);
	}

	dtrace_probekey(desc, &pkey);
	dtrace_cred2priv(enab->dten_vstate->dtvs_state->dts_cred.dcr_cred,
	    &priv, &uid, &zoneid);

	return (dtrace_match(&pkey, priv, uid, zoneid, dtrace_ecb_create_enable,
	    enab));
#endif
	return (0);
}

static void
dtrace_probe_provide(dtrace_probedesc_t *desc, dtrace_provider_t *prv)
{
	int all = 0;

	if (prv == NULL) {
		all = 1;
		prv = dtrace_provider;
	}

	do {
		/*
		 * First, call the blanket provide operation.
		 */
		prv->dtpv_pops.dtps_provide(prv->dtpv_arg, desc);
	} while (all && (prv = prv->dtpv_next) != NULL);
}

static void
dtrace_enabling_provide(dtrace_provider_t *prv)
{
	int i, all = 0;
	dtrace_probedesc_t desc;
	dtrace_genid_t gen;

	if (prv == NULL) {
		all = 1;
		prv = dtrace_provider;
	}

	do {
		dtrace_enabling_t *enab;
		void *parg = prv->dtpv_arg;

retry:
		gen = dtrace_retained_gen;
		for (enab = dtrace_retained; enab != NULL;
		    enab = enab->dten_next) {
			for (i = 0; i < enab->dten_ndesc; i++) {
				desc = enab->dten_desc[i]->dted_probe;
				prv->dtpv_pops.dtps_provide(parg, &desc);
				/*
				 * Process the retained enablings again if
				 * they have changed while we weren't holding
				 * dtrace_lock.
				 */
				if (gen != dtrace_retained_gen)
					goto retry;
			}
		}
	} while (all && (prv = prv->dtpv_next) != NULL);

	dtrace_probe_provide(NULL, all ? NULL : prv);
}

static int
dtrace_enabling_match(dtrace_enabling_t *enab, int *nmatched)
{
	int i = 0;
	int matched = 0;

	for (i = 0; i < enab->dten_ndesc; i++) {
		dtrace_ecbdesc_t *ep = enab->dten_desc[i];

		enab->dten_current = ep;
		enab->dten_error = 0;

		matched += dtrace_probe_enable(&ep->dted_probe, enab);

		if (enab->dten_error != 0) {
			/*
			 * If we get an error half-way through enabling the
			 * probes, we kick out -- perhaps with some number of
			 * them enabled.  Leaving enabled probes enabled may
			 * be slightly confusing for user-level, but we expect
			 * that no one will attempt to actually drive on in
			 * the face of such errors.  If this is an anonymous
			 * enabling (indicated with a NULL nmatched pointer),
			 * we WPRINTF() a message.  We aren't expecting to
			 * get such an error -- such as it can exist at all,
			 * it would be a result of corrupted DOF in the driver
			 * properties.
			 */
			if (nmatched == NULL) {
				WPRINTF("dtrace_enabling_match() "
				    "error on %p: %d", (void *)ep,
				    enab->dten_error);
			}

			return (enab->dten_error);
		}
	}

	enab->dten_probegen = dtrace_probegen;
	if (nmatched != NULL)
		*nmatched = matched;

	return (0);
}


static void
dtrace_enabling_matchall(void)
{
	dtrace_enabling_t *enab;

	/*
	 * Iterate over all retained enablings to see if any probes match
	 * against them.  We only perform this operation on enablings for which
	 * we have sufficient permissions by virtue of being in the global zone
	 * or in the same zone as the DTrace client.  Because we can be called
	 * after dtrace_detach() has been called, we cannot assert that there
	 * are retained enablings.  We can safely load from dtrace_retained,
	 * however:  the taskq_destroy() at the end of dtrace_detach() will
	 * block pending our completion.
	 */
	for (enab = dtrace_retained; enab != NULL; enab = enab->dten_next) {
			(void) dtrace_enabling_match(enab, NULL);
	}
}

static int
dtrace_badattr(const dtrace_attribute_t *a)
{
	return (a->dtat_name > DTRACE_STABILITY_MAX ||
	    a->dtat_data > DTRACE_STABILITY_MAX ||
	    a->dtat_class > DTRACE_CLASS_MAX);
}

static int
dtrace_badname(const char *s)
{
	char c;

	if (s == NULL || (c = *s++) == '\0')
		return (0);

	if (!DTRACE_ISALPHA(c) && c != '-' && c != '_' && c != '.')
		return (1);

	while ((c = *s++) != '\0') {
		if (!DTRACE_ISALPHA(c) && (c < '0' || c > '9') &&
		    c != '-' && c != '_' && c != '.' && c != '`')
			return (1);
	}

	return (0);
}

static dtrace_pops_t	dtrace_provider_ops = {
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

int
dtrace_register(const char *name, const dtrace_pattr_t *pap, uint32_t priv,
    cred_t *cr, const dtrace_pops_t *pops, void *arg, dtrace_provider_id_t *idp)
{
	dtrace_provider_t *provider;

	if (name == NULL || pap == NULL || pops == NULL || idp == NULL) {
		WPRINTF("failed to register provider '%s': invalid "
		    "arguments", name ? name : "<NULL>");
		return (EINVAL);
	}

	if (name[0] == '\0' || dtrace_badname(name)) {
		WPRINTF("failed to register provider '%s': invalid "
		    "provider name", name);
		return (EINVAL);
	}

	if ((pops->dtps_provide == NULL) ||
	    pops->dtps_enable == NULL || pops->dtps_disable == NULL ||
	    pops->dtps_destroy == NULL ||
	    ((pops->dtps_resume == NULL) != (pops->dtps_suspend == NULL))) {
		WPRINTF("failed to register provider '%s': invalid "
		    "provider ops", name);
		return (EINVAL);
	}

	if (dtrace_badattr(&pap->dtpa_provider) ||
	    dtrace_badattr(&pap->dtpa_mod) ||
	    dtrace_badattr(&pap->dtpa_func) ||
	    dtrace_badattr(&pap->dtpa_name) ||
	    dtrace_badattr(&pap->dtpa_args)) {
		WPRINTF("failed to register provider '%s': invalid "
		    "provider attributes", name);
		return (EINVAL);
	}

	if (priv & ~DTRACE_PRIV_ALL) {
		WPRINTF("failed to register provider '%s': invalid "
		    "privilege attributes", name);
		return (EINVAL);
	}

	if ((priv & DTRACE_PRIV_KERNEL) &&
	    (priv & (DTRACE_PRIV_USER | DTRACE_PRIV_OWNER)) &&
	    pops->dtps_usermode == NULL) {
		WPRINTF("failed to register provider '%s': need "
		    "dtps_usermode() op for given privilege attributes", name);
		return (EINVAL);
	}

	provider = calloc(1, sizeof (dtrace_provider_t));
	if (provider == NULL)
		return (ENOMEM);

	provider->dtpv_name = malloc(strlen(name) + 1);
	if (provider->dtpv_name == NULL)
		return (ENOMEM);

	(void) strcpy(provider->dtpv_name, name);

	provider->dtpv_attr = *pap;
	provider->dtpv_priv.dtpp_flags = priv;
	if (cr != NULL) {
		provider->dtpv_priv.dtpp_uid = crgetuid(cr);
		provider->dtpv_priv.dtpp_zoneid = crgetzoneid(cr);
	}
	provider->dtpv_pops = *pops;

	if (pops->dtps_provide == NULL) {
		provider->dtpv_pops.dtps_provide =
		    (void (*)(void *, dtrace_probedesc_t *))dtrace_nullop;
	}

	if (pops->dtps_suspend == NULL) {
		ASSERT(pops->dtps_resume == NULL);
		provider->dtpv_pops.dtps_suspend =
		    (void (*)(void *, dtrace_id_t, void *))dtrace_nullop;
		provider->dtpv_pops.dtps_resume =
		    (void (*)(void *, dtrace_id_t, void *))dtrace_nullop;
	}

	provider->dtpv_arg = arg;
	*idp = (dtrace_provider_id_t)provider;

	if (pops == &dtrace_provider_ops) {
		ASSERT(dtrace_anon.dta_enabling == NULL);

		/*
		 * We make sure that the DTrace provider is at the head of
		 * the provider chain.
		 */
		provider->dtpv_next = dtrace_provider;
		dtrace_provider = provider;
		return (0);
	}


	/*
	 * If there is at least one provider registered, we'll add this
	 * provider after the first provider.
	 */
	if (dtrace_provider != NULL) {
		provider->dtpv_next = dtrace_provider->dtpv_next;
		dtrace_provider->dtpv_next = provider;
	} else {
		dtrace_provider = provider;
	}

	if (dtrace_retained != NULL) {
		dtrace_enabling_provide(provider);

		/*
		 * Now we need to call dtrace_enabling_matchall() -- which
		 * will acquire cpu_lock and dtrace_lock.  We therefore need
		 * to drop all of our locks before calling into it...
		 */
		dtrace_enabling_matchall();

		return (0);
	}

	return (0);
}
