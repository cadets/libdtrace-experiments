#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtrace.h"
#include "dtrace_impl.h"
#include "unr_shim.h"
#include "note_shim.h"

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
#define	DTRACE_AGGHASHSIZE_SLEW		17
#define	DTRACEACT_ISSTRING(act)						\
	((act)->dta_kind == DTRACEACT_DIFEXPR &&			\
	(act)->dta_difo->dtdo_rtype.dtdt_kind == DIF_TYPE_STRING)
#define	DT_MASK_LO 0x00000000FFFFFFFFULL
#define	P2ROUNDUP(x, align)		(-(-(x) & -(align)))
#define	P2PHASEUP(x, align, phase)	((phase) - (((phase) - (x)) & -(align)))
#define	IS_P2ALIGNED(v, a) ((((uintptr_t)(v)) & ((uintptr_t)(a) - 1)) == 0)
#define	DTRACE_STORE(type, tomax, offset, what) \
	*((type *)((uintptr_t)(tomax) + (uintptr_t)offset)) = (type)(what);
#define	isdigit(ch)	((ch) >= '0' && (ch) <= '9')
#define	isxdigit(ch)	(isdigit(ch) || ((ch) >= 'a' && (ch) <= 'f') || \
			((ch) >= 'A' && (ch) <= 'F'))
#define	isspace(ch)	(((ch) == ' ') || ((ch) == '\r') || ((ch) == '\n') || \
			((ch) == '\t') || ((ch) == '\f'))
#define	islower(ch)	((ch) >= 'a' && (ch) <= 'z')
#define	isupper(ch)	((ch) >= 'A' && (ch) <= 'Z')
#define	DIGIT(x)	\
	(isdigit(x) ? (x) - '0' : islower(x) ? (x) + 10 - 'a' : (x) + 10 - 'A')
#define	lisalnum(x)	\
	(isdigit(x) || ((x) >= 'a' && (x) <= 'z') || ((x) >= 'A' && (x) <= 'Z'))
#define	DTRACE_TLS_THRKEY(where) { \
	solaris_cpu_t *_c = &solaris_cpu[curcpu]; \
	uint_t intr = 0; \
	uint_t actv = _c->cpu_intr_actv; \
	for (; actv; actv >>= 1) \
		intr++; \
	ASSERT(intr < (1 << 3)); \
	(where) = ((curthread->td_tid + DIF_VARIABLE_MAX) & \
	    (((uint64_t)1 << 61) - 1)) | ((uint64_t)intr << 61); \
/*
 * Test whether alloc_sz bytes will fit in the scratch region.  We isolate
 * alloc_sz on the righthand side of the comparison in order to avoid overflow
 * or underflow in the comparison with it.  This is simpler than the INRANGE
 * check above, because we know that the dtms_scratch_ptr is valid in the
 * range.  Allocations of size zero are allowed.
 */
#define	DTRACE_INSCRATCH(mstate, alloc_sz) \
	((mstate)->dtms_scratch_base + (mstate)->dtms_scratch_size - \
	(mstate)->dtms_scratch_ptr >= (alloc_sz))
#define	DT_BSWAP_8(x)	((x) & 0xff)
#define	DT_BSWAP_16(x)	((DT_BSWAP_8(x) << 8) | DT_BSWAP_8((x) >> 8))
#define	DT_BSWAP_32(x)	((DT_BSWAP_16(x) << 16) | DT_BSWAP_16((x) >> 16))
#define	DT_BSWAP_64(x)	((DT_BSWAP_32(x) << 32) | DT_BSWAP_32((x) >> 32))

/*
 * Userspace shim...
 */
typedef int boolean_t;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef B_FALSE
#define	B_FALSE	FALSE
#endif
#ifndef B_TRUE
#define	B_TRUE	TRUE
#endif
/*
 * DTrace Macros and Constants
 *
 * These are various macros that are useful in various spots in the
 * implementation, along with a few random constants that have no meaning
 * outside of the implementation.  There is no real structure to this cpp
 * mishmash -- but is there ever?
 */
#define	DTRACE_HASHSTR(hash, probe)	\
	dtrace_hash_str(*((char **)((uintptr_t)(probe) + (hash)->dth_stroffs)))

#define	DTRACE_HASHNEXT(hash, probe)	\
	(dtrace_probe_t **)((uintptr_t)(probe) + (hash)->dth_nextoffs)

#define	DTRACE_HASHPREV(hash, probe)	\
	(dtrace_probe_t **)((uintptr_t)(probe) + (hash)->dth_prevoffs)

#define	DTRACE_HASHEQ(hash, lhs, rhs)	\
	(strcmp(*((char **)((uintptr_t)(lhs) + (hash)->dth_stroffs)), \
	    *((char **)((uintptr_t)(rhs) + (hash)->dth_stroffs))) == 0)
/*
 * Test whether a range of memory starting at testaddr of size testsz falls
 * within the range of memory described by addr, sz.  We take care to avoid
 * problems with overflow and underflow of the unsigned quantities, and
 * disallow all negative sizes.  Ranges of size 0 are allowed.
 */
#define	DTRACE_INRANGE(testaddr, testsz, baseaddr, basesz) \
	((testaddr) - (uintptr_t)(baseaddr) < (basesz) && \
	(testaddr) + (testsz) - (uintptr_t)(baseaddr) <= (basesz) && \
	(testaddr) + (testsz) >= (testaddr))

#define	DTRACE_RANGE_REMAIN(remp, addr, baseaddr, basesz)		\
do {									\
	if ((remp) != NULL) {						\
		*(remp) = (uintptr_t)(baseaddr) + (basesz) - (addr);	\
	}								\
_NOTE(CONSTCOND) } while (0)

/*
 * Here we define the userspace compat shim regarding the CPU_* macros that are
 * necessary. We don't actually use them as intended, but we can make use of a
 * few of them in order to keep DTrace behaviour as close as possible to the
 * original, assuming we have no SMP.
 */
#define	CPU_DTRACE_NOFAULT	0x0001	/* Don't fault */
#define	CPU_DTRACE_DROP		0x0002	/* Drop this ECB */
#define	CPU_DTRACE_BADADDR	0x0004	/* DTrace fault: bad address */
#define	CPU_DTRACE_BADALIGN	0x0008	/* DTrace fault: bad alignment */
#define	CPU_DTRACE_DIVZERO	0x0010	/* DTrace fault: divide by zero */
#define	CPU_DTRACE_ILLOP	0x0020	/* DTrace fault: illegal operation */
#define	CPU_DTRACE_NOSCRATCH	0x0040	/* DTrace fault: out of scratch */
#define	CPU_DTRACE_KPRIV	0x0080	/* DTrace fault: bad kernel access */
#define	CPU_DTRACE_UPRIV	0x0100	/* DTrace fault: bad user access */
#define	CPU_DTRACE_TUPOFLOW	0x0200	/* DTrace fault: tuple stack overflow */
#if defined(__sparc)
#define	CPU_DTRACE_FAKERESTORE	0x0400	/* pid provider hint to getreg */
#endif
#define	CPU_DTRACE_ENTRY	0x0800	/* pid provider hint to ustack() */
#define	CPU_DTRACE_BADSTACK	0x1000	/* DTrace fault: bad stack */

#define	CPU_DTRACE_FAULT	(CPU_DTRACE_BADADDR | CPU_DTRACE_BADALIGN | \
				CPU_DTRACE_DIVZERO | CPU_DTRACE_ILLOP | \
				CPU_DTRACE_NOSCRATCH | CPU_DTRACE_KPRIV | \
				CPU_DTRACE_UPRIV | CPU_DTRACE_TUPOFLOW | \
				CPU_DTRACE_BADSTACK)
#define	CPU_DTRACE_ERROR	(CPU_DTRACE_FAULT | CPU_DTRACE_DROP)

#define ASSERT3U(...) (0)

int		dtrace_destructive_disallow = 0;
dtrace_provider_t *dtrace_provider;
static dtrace_enabling_t *dtrace_retained;
static dtrace_genid_t	dtrace_retained_gen;	/* current retained enab gen */
static dtrace_genid_t	dtrace_probegen;	/* current probe generation */
static dtrace_ecb_t	*dtrace_ecb_create_cache; /* cached created ECB */
static uint64_t		dtrace_vtime_references; /* number of vtimestamp refs */
size_t		dtrace_strsize_default = 256;
static dtrace_hash_t	*dtrace_bymod;		/* probes hashed by module */
static dtrace_hash_t	*dtrace_byfunc;		/* probes hashed by function */
static dtrace_hash_t	*dtrace_byname;		/* probes hashed by name */
static dtrace_probe_t	**dtrace_probes;	/* array of all probes */
static int		dtrace_nprobes;		/* number of probes */
static int		dtrace_nprovs;		/* number of providers */
static struct unrhdr	*dtrace_arena;		/* Probe ID number.     */
static struct mtx	dtrace_unr_mtx;
static int		dtrace_dynvar_failclean; /* dynvars failed to clean */
static dtrace_toxrange_t *dtrace_toxrange;	/* toxic range array */
static int		dtrace_toxranges;	/* number of toxic ranges */
static int		dtrace_toxranges_max;	/* size of toxic range array */
/*
 * FIXME: This is so not necessary.
 */
static int		curcpu = 1;		/* We are not in SMP, 1 CPU atm */
static int		predcache = 0;		/* There's no multithreaded kind-of-thing going on */
size_t		dtrace_statvar_maxsize = (16 * 1024);

volatile uint16_t cpuc_dtrace_flags = 0;	/* userspace shim */
volatile uintptr_t cpuc_dtrace_illval = 0;	/* userspace shim */

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

typedef int processorid_t; /* we need this to in order to compile */

/*
 * This is not a bug
 */
static void
dtrace_nullop(void)
{}

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

static dtrace_id_t	dtrace_probeid_begin;	/* special BEGIN probe */
static dtrace_id_t	dtrace_probeid_end;	/* special END probe */
dtrace_id_t		dtrace_probeid_error;	/* special ERROR probe */

static dtrace_pattr_t	dtrace_provider_attr = {
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
};

/*
 * XXX: This may or may not be needed (the kernel can provide this)
 */
static void
dtrace_vtime_enable(void)
{}

static void
dtrace_vtime_disable(void)
{}

void
dtrace_membar_producer(void)
{}

/*
 * Return a duplicate copy of a string.  If the specified string is NULL,
 * this function returns a zero-length string.
 */
static char *
dtrace_strdup(const char *str)
{
	char *new = calloc(1, (str != NULL ? strlen(str) : 0) + 1);

	if (str != NULL)
		(void) strcpy(new, str);

	return (new);
}

static int
dtrace_inscratch(uintptr_t dest, size_t size, dtrace_mstate_t *mstate)
{
	if (dest < mstate->dtms_scratch_base)
		return (0);

	if (dest + size < dest)
		return (0);

	if (dest + size > mstate->dtms_scratch_ptr)
		return (0);

	return (1);
}

static int
dtrace_canstore_statvar(uint64_t addr, size_t sz, size_t *remain,
    dtrace_statvar_t **svars, int nsvars)
{
	int i;
	size_t maxglobalsize, maxlocalsize;

	if (nsvars == 0)
		return (0);

	maxglobalsize = dtrace_statvar_maxsize + sizeof (uint64_t);
	maxlocalsize = maxglobalsize * NCPU;

	for (i = 0; i < nsvars; i++) {
		dtrace_statvar_t *svar = svars[i];
		uint8_t scope;
		size_t size;

		if (svar == NULL || (size = svar->dtsv_size) == 0)
			continue;

		scope = svar->dtsv_var.dtdv_scope;

		/*
		 * We verify that our size is valid in the spirit of providing
		 * defense in depth:  we want to prevent attackers from using
		 * DTrace to escalate an orthogonal kernel heap corruption bug
		 * into the ability to store to arbitrary locations in memory.
		 */
		VERIFY((scope == DIFV_SCOPE_GLOBAL && size <= maxglobalsize) ||
		    (scope == DIFV_SCOPE_LOCAL && size <= maxlocalsize));

		if (DTRACE_INRANGE(addr, sz, svar->dtsv_data,
		    svar->dtsv_size)) {
			DTRACE_RANGE_REMAIN(remain, addr, svar->dtsv_data,
			    svar->dtsv_size);
			return (1);
		}
	}

	return (0);
}

/*
 * Check to see if the address is within a memory region to which a store may
 * be issued.  This includes the DTrace scratch areas, and any DTrace variable
 * region.  The caller of dtrace_canstore() is responsible for performing any
 * alignment checks that are needed before stores are actually executed.
 */
static int
dtrace_canstore(uint64_t addr, size_t sz, dtrace_mstate_t *mstate,
    dtrace_vstate_t *vstate)
{
	return (dtrace_canstore_remains(addr, sz, NULL, mstate, vstate));
}

/*
 * Implementation of dtrace_canstore which communicates the upper bound of the
 * allowed memory region.
 */
static int
dtrace_canstore_remains(uint64_t addr, size_t sz, size_t *remain,
    dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
	/*
	 * First, check to see if the address is in scratch space...
	 */
	if (DTRACE_INRANGE(addr, sz, mstate->dtms_scratch_base,
	    mstate->dtms_scratch_size)) {
		DTRACE_RANGE_REMAIN(remain, addr, mstate->dtms_scratch_base,
		    mstate->dtms_scratch_size);
		return (1);
	}

	/*
	 * Now check to see if it's a dynamic variable.  This check will pick
	 * up both thread-local variables and any global dynamically-allocated
	 * variables.
	 */
	if (DTRACE_INRANGE(addr, sz, vstate->dtvs_dynvars.dtds_base,
	    vstate->dtvs_dynvars.dtds_size)) {
		dtrace_dstate_t *dstate = &vstate->dtvs_dynvars;
		uintptr_t base = (uintptr_t)dstate->dtds_base +
		    (dstate->dtds_hashsize * sizeof (dtrace_dynhash_t));
		uintptr_t chunkoffs;
		dtrace_dynvar_t *dvar;

		/*
		 * Before we assume that we can store here, we need to make
		 * sure that it isn't in our metadata -- storing to our
		 * dynamic variable metadata would corrupt our state.  For
		 * the range to not include any dynamic variable metadata,
		 * it must:
		 *
		 *	(1) Start above the hash table that is at the base of
		 *	the dynamic variable space
		 *
		 *	(2) Have a starting chunk offset that is beyond the
		 *	dtrace_dynvar_t that is at the base of every chunk
		 *
		 *	(3) Not span a chunk boundary
		 *
		 *	(4) Not be in the tuple space of a dynamic variable
		 *
		 */
		if (addr < base)
			return (0);

		chunkoffs = (addr - base) % dstate->dtds_chunksize;

		if (chunkoffs < sizeof (dtrace_dynvar_t))
			return (0);

		if (chunkoffs + sz > dstate->dtds_chunksize)
			return (0);

		dvar = (dtrace_dynvar_t *)((uintptr_t)addr - chunkoffs);

		if (dvar->dtdv_hashval == DTRACE_DYNHASH_FREE)
			return (0);

		if (chunkoffs < sizeof (dtrace_dynvar_t) +
		    ((dvar->dtdv_tuple.dtt_nkeys - 1) * sizeof (dtrace_key_t)))
			return (0);

		DTRACE_RANGE_REMAIN(remain, addr, dvar, dstate->dtds_chunksize);
		return (1);
	}

	/*
	 * Finally, check the static local and global variables.  These checks
	 * take the longest, so we perform them last.
	 */
	if (dtrace_canstore_statvar(addr, sz, remain,
	    vstate->dtvs_locals, vstate->dtvs_nlocals))
		return (1);

	if (dtrace_canstore_statvar(addr, sz, remain,
	    vstate->dtvs_globals, vstate->dtvs_nglobals))
		return (1);

	return (0);
}


/*
 * Convenience routine to check to see if the address is within a memory
 * region in which a load may be issued given the user's privilege level;
 * if not, it sets the appropriate error flags and loads 'addr' into the
 * illegal value slot.
 *
 * DTrace subroutines (DIF_SUBR_*) should use this helper to implement
 * appropriate memory access protection.
 */
static int
dtrace_canload(uint64_t addr, size_t sz, dtrace_mstate_t *mstate,
    dtrace_vstate_t *vstate)
{
	return (dtrace_canload_remains(addr, sz, NULL, mstate, vstate));
}

/*
 * Implementation of dtrace_canload which communicates the uppoer bound of the
 * allowed memory region.
 */
static int
dtrace_canload_remains(uint64_t addr, size_t sz, size_t *remain,
    dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
	volatile uintptr_t *illval = &cpuc_dtrace_illval;

	/*
	 * TODO: For the time being, we can read everything. This should
	 * definitely be addressed though.
	*/
	/*
	 * If we hold the privilege to read from kernel memory, then
	 * everything is readable.
	 */
	/*
	if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) != 0) {
	*/
	if (1) {
		DTRACE_RANGE_REMAIN(remain, addr, addr, sz);
		return (1);
	}

#if 0
	/*
	 * You can obviously read that which you can store.
	 */
	if (dtrace_canstore_remains(addr, sz, remain, mstate, vstate))
		return (1);

	/*
	 * We're allowed to read from our own string table.
	 */
	if (DTRACE_INRANGE(addr, sz, mstate->dtms_difo->dtdo_strtab,
	    mstate->dtms_difo->dtdo_strlen)) {
		DTRACE_RANGE_REMAIN(remain, addr,
		    mstate->dtms_difo->dtdo_strtab,
		    mstate->dtms_difo->dtdo_strlen);
		return (1);
	}

	if (vstate->dtvs_state != NULL &&
	    dtrace_priv_proc(vstate->dtvs_state)) {
		proc_t *p;

		/*
		 * When we have privileges to the current process, there are
		 * several context-related kernel structures that are safe to
		 * read, even absent the privilege to read from kernel memory.
		 * These reads are safe because these structures contain only
		 * state that (1) we're permitted to read, (2) is harmless or
		 * (3) contains pointers to additional kernel state that we're
		 * not permitted to read (and as such, do not present an
		 * opportunity for privilege escalation).  Finally (and
		 * critically), because of the nature of their relation with
		 * the current thread context, the memory associated with these
		 * structures cannot change over the duration of probe context,
		 * and it is therefore impossible for this memory to be
		 * deallocated and reallocated as something else while it's
		 * being operated upon.
		 */
		if (DTRACE_INRANGE(addr, sz, curthread, sizeof (kthread_t))) {
			DTRACE_RANGE_REMAIN(remain, addr, curthread,
			    sizeof (kthread_t));
			return (1);
		}

		if ((p = curthread->t_procp) != NULL && DTRACE_INRANGE(addr,
		    sz, curthread->t_procp, sizeof (proc_t))) {
			DTRACE_RANGE_REMAIN(remain, addr, curthread->t_procp,
			    sizeof (proc_t));
			return (1);
		}

		if (curthread->t_cred != NULL && DTRACE_INRANGE(addr, sz,
		    curthread->t_cred, sizeof (cred_t))) {
			DTRACE_RANGE_REMAIN(remain, addr, curthread->t_cred,
			    sizeof (cred_t));
			return (1);
		}

#ifdef illumos
		if (p != NULL && p->p_pidp != NULL && DTRACE_INRANGE(addr, sz,
		    &(p->p_pidp->pid_id), sizeof (pid_t))) {
			DTRACE_RANGE_REMAIN(remain, addr, &(p->p_pidp->pid_id),
			    sizeof (pid_t));
			return (1);
		}

		if (curthread->t_cpu != NULL && DTRACE_INRANGE(addr, sz,
		    curthread->t_cpu, offsetof(cpu_t, cpu_pause_thread))) {
			DTRACE_RANGE_REMAIN(remain, addr, curthread->t_cpu,
			    offsetof(cpu_t, cpu_pause_thread));
			return (1);
		}
#endif
	}

	if ((fp = mstate->dtms_getf) != NULL) {
		uintptr_t psz = sizeof (void *);
		vnode_t *vp;
		vnodeops_t *op;

		/*
		 * When getf() returns a file_t, the enabling is implicitly
		 * granted the (transient) right to read the returned file_t
		 * as well as the v_path and v_op->vnop_name of the underlying
		 * vnode.  These accesses are allowed after a successful
		 * getf() because the members that they refer to cannot change
		 * once set -- and the barrier logic in the kernel's closef()
		 * path assures that the file_t and its referenced vode_t
		 * cannot themselves be stale (that is, it impossible for
		 * either dtms_getf itself or its f_vnode member to reference
		 * freed memory).
		 */
		if (DTRACE_INRANGE(addr, sz, fp, sizeof (file_t))) {
			DTRACE_RANGE_REMAIN(remain, addr, fp, sizeof (file_t));
			return (1);
		}

		if ((vp = fp->f_vnode) != NULL) {
			size_t slen;
#ifdef illumos
			if (DTRACE_INRANGE(addr, sz, &vp->v_path, psz)) {
				DTRACE_RANGE_REMAIN(remain, addr, &vp->v_path,
				    psz);
				return (1);
			}
			slen = strlen(vp->v_path) + 1;
			if (DTRACE_INRANGE(addr, sz, vp->v_path, slen)) {
				DTRACE_RANGE_REMAIN(remain, addr, vp->v_path,
				    slen);
				return (1);
			}
#endif

			if (DTRACE_INRANGE(addr, sz, &vp->v_op, psz)) {
				DTRACE_RANGE_REMAIN(remain, addr, &vp->v_op,
				    psz);
				return (1);
			}

#ifdef illumos
			if ((op = vp->v_op) != NULL &&
			    DTRACE_INRANGE(addr, sz, &op->vnop_name, psz)) {
				DTRACE_RANGE_REMAIN(remain, addr,
				    &op->vnop_name, psz);
				return (1);
			}

			if (op != NULL && op->vnop_name != NULL &&
			    DTRACE_INRANGE(addr, sz, op->vnop_name,
			    (slen = strlen(op->vnop_name) + 1))) {
				DTRACE_RANGE_REMAIN(remain, addr,
				    op->vnop_name, slen);
				return (1);
			}
#endif
		}
	}
#endif
	DTRACE_CPUFLAG_SET(CPU_DTRACE_KPRIV);
	*illval = addr;
	return (0);
}

/*
 * Atomically increment a specified error counter from probe context.
 */
static void
dtrace_error(uint32_t *counter)
{
	/*
	 * Most counters stored to in probe context are per-CPU counters.
	 * However, there are some error conditions that are sufficiently
	 * arcane that they don't merit per-CPU storage.  If these counters
	 * are incremented concurrently on different CPUs, scalability will be
	 * adversely affected -- but we don't expect them to be white-hot in a
	 * correctly constructed enabling...
	 */
	uint32_t oval, nval;

	do {
		oval = *counter;

		if ((nval = oval + 1) == 0) {
			/*
			 * If the counter would wrap, set it to 1 -- assuring
			 * that the counter is never zero when we have seen
			 * errors.  (The counter must be 32-bits because we
			 * aren't guaranteed a 64-bit compare&swap operation.)
			 * To save this code both the infamy of being fingered
			 * by a priggish news story and the indignity of being
			 * the target of a neo-puritan witch trial, we're
			 * carefully avoiding any colorful description of the
			 * likelihood of this condition -- but suffice it to
			 * say that it is only slightly more likely than the
			 * overflow of predicate cache IDs, as discussed in
			 * dtrace_predicate_create().
			 */
			nval = 1;
		}
	} while (dtrace_cas32(counter, oval, nval) != oval);
}

/*
 * Convenience routine to check to see if a given string is within a memory
 * region in which a load may be issued given the user's privilege level;
 * this exists so that we don't need to issue unnecessary dtrace_strlen()
 * calls in the event that the user has all privileges.
 */
static int
dtrace_strcanload(uint64_t addr, size_t sz, size_t *remain,
    dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
	size_t rsize;

	/*
	 * If we hold the privilege to read from kernel memory, then
	 * everything is readable.
	 */
	if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) != 0) {
		DTRACE_RANGE_REMAIN(remain, addr, addr, sz);
		return (1);
	}

	/*
	 * Even if the caller is uninterested in querying the remaining valid
	 * range, it is required to ensure that the access is allowed.
	 */
	if (remain == NULL) {
		remain = &rsize;
	}
	if (dtrace_canload_remains(addr, 0, remain, mstate, vstate)) {
		size_t strsz;
		/*
		 * Perform the strlen after determining the length of the
		 * memory region which is accessible.  This prevents timing
		 * information from being used to find NULs in memory which is
		 * not accessible to the caller.
		 */
		strsz = 1 + dtrace_strlen((char *)(uintptr_t)addr,
		    MIN(sz, *remain));
		if (strsz <= *remain) {
			return (1);
		}
	}

	return (0);
}

/*
 * Convenience routine to check to see if a given variable is within a memory
 * region in which a load may be issued given the user's privilege level.
 */
static int
dtrace_vcanload(void *src, dtrace_diftype_t *type, size_t *remain,
    dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
	size_t sz;
	assert(type->dtdt_flags & DIF_TF_BYREF);

	/*
	 * Calculate the max size before performing any checks since even
	 * DTRACE_ACCESS_KERNEL-credentialed callers expect that this function
	 * return the max length via 'remain'.
	 */
	if (type->dtdt_kind == DIF_TYPE_STRING) {
		dtrace_state_t *state = vstate->dtvs_state;

		if (state != NULL) {
			sz = state->dts_options[DTRACEOPT_STRSIZE];
		} else {
			/*
			 * In helper context, we have a NULL state; fall back
			 * to using the system-wide default for the string size
			 * in this case.
			 */
			sz = dtrace_strsize_default;
		}
	} else {
		sz = type->dtdt_size;
	}

	/*
	 * If we hold the privilege to read from kernel memory, then
	 * everything is readable.
	 */
	if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) != 0) {
		DTRACE_RANGE_REMAIN(remain, (uintptr_t)src, src, sz);
		return (1);
	}

	if (type->dtdt_kind == DIF_TYPE_STRING) {
		return (dtrace_strcanload((uintptr_t)src, sz, remain, mstate,
		    vstate));
	}
	return (dtrace_canload_remains((uintptr_t)src, sz, remain, mstate,
	    vstate));
}

/*
 * Convert a string to a signed integer using safe loads.
 *
 * NOTE: This function uses various macros from strtolctype.h to manipulate
 * digit values, etc -- these have all been checked to ensure they make
 * no additional function calls.
 */
static int64_t
dtrace_strtoll(char *input, int base, size_t limit)
{
	uintptr_t pos = (uintptr_t)input;
	int64_t val = 0;
	int x;
	boolean_t neg = B_FALSE;
	char c, cc, ccc;
	uintptr_t end = pos + limit;

	/*
	 * Consume any whitespace preceding digits.
	 */
	while ((c = dtrace_load8(pos)) == ' ' || c == '\t')
		pos++;

	/*
	 * Handle an explicit sign if one is present.
	 */
	if (c == '-' || c == '+') {
		if (c == '-')
			neg = B_TRUE;
		c = dtrace_load8(++pos);
	}

	/*
	 * Check for an explicit hexadecimal prefix ("0x" or "0X") and skip it
	 * if present.
	 */
	if (base == 16 && c == '0' && ((cc = dtrace_load8(pos + 1)) == 'x' ||
	    cc == 'X') && isxdigit(ccc = dtrace_load8(pos + 2))) {
		pos += 2;
		c = ccc;
	}

	/*
	 * Read in contiguous digits until the first non-digit character.
	 */
	for (; pos < end && c != '\0' && lisalnum(c) && (x = DIGIT(c)) < base;
	    c = dtrace_load8(++pos))
		val = val * base + x;

	return (neg ? -val : val);
}

/*
 * Compare two strings using safe loads.
 */
static int
dtrace_strncmp(char *s1, char *s2, size_t limit)
{
	uint8_t c1, c2;
	volatile uint16_t *flags;

	if (s1 == s2 || limit == 0)
		return (0);

	flags = (volatile uint16_t *)&cpuc_dtrace_flags;

	do {
		if (s1 == NULL) {
			c1 = '\0';
		} else {
			c1 = dtrace_load8((uintptr_t)s1++);
		}

		if (s2 == NULL) {
			c2 = '\0';
		} else {
			c2 = dtrace_load8((uintptr_t)s2++);
		}

		if (c1 != c2)
			return (c1 - c2);
	} while (--limit && c1 != '\0' && !(*flags & CPU_DTRACE_FAULT));

	return (0);
}

/*
 * Compute strlen(s) for a string using safe memory accesses.  The additional
 * len parameter is used to specify a maximum length to ensure completion.
 */
static size_t
dtrace_strlen(const char *s, size_t lim)
{
	uint_t len;

	for (len = 0; len != lim; len++) {
		if (dtrace_load8((uintptr_t)s++) == '\0')
			break;
	}

	return (len);
}

/*
 * Check if an address falls within a toxic region.
 */
static int
dtrace_istoxic(uintptr_t kaddr, size_t size)
{
	uintptr_t taddr, tsize;
	int i;

	for (i = 0; i < dtrace_toxranges; i++) {
		taddr = dtrace_toxrange[i].dtt_base;
		tsize = dtrace_toxrange[i].dtt_limit - taddr;

		if (kaddr - taddr < tsize) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpuc_dtrace_illval = kaddr;
			return (1);
		}

		if (taddr - kaddr < size) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpuc_dtrace_illval = taddr;
			return (1);
		}
	}

	return (0);
}

/*
 * Copy src to dst using safe memory accesses.  The src is assumed to be unsafe
 * memory specified by the DIF program.  The dst is assumed to be safe memory
 * that we can store to directly because it is managed by DTrace.  As with
 * standard bcopy, overlapping copies are handled properly.
 */
static void
dtrace_bcopy(const void *src, void *dst, size_t len)
{
	if (len != 0) {
		uint8_t *s1 = dst;
		const uint8_t *s2 = src;

		if (s1 <= s2) {
			do {
				*s1++ = dtrace_load8((uintptr_t)s2++);
			} while (--len != 0);
		} else {
			s2 += len;
			s1 += len;

			do {
				*--s1 = dtrace_load8((uintptr_t)--s2);
			} while (--len != 0);
		}
	}
}

/*
 * Copy src to dst using safe memory accesses, up to either the specified
 * length, or the point that a nul byte is encountered.  The src is assumed to
 * be unsafe memory specified by the DIF program.  The dst is assumed to be
 * safe memory that we can store to directly because it is managed by DTrace.
 * Unlike dtrace_bcopy(), overlapping regions are not handled.
 */
static void
dtrace_strcpy(const void *src, void *dst, size_t len)
{
	if (len != 0) {
		uint8_t *s1 = dst, c;
		const uint8_t *s2 = src;

		do {
			*s1++ = c = dtrace_load8((uintptr_t)s2++);
		} while (--len != 0 && c != '\0');
	}
}

/*
 * Copy src to dst, deriving the size and type from the specified (BYREF)
 * variable type.  The src is assumed to be unsafe memory specified by the DIF
 * program.  The dst is assumed to be DTrace variable memory that is of the
 * specified type; we assume that we can store to directly.
 */
static void
dtrace_vcopy(void *src, void *dst, dtrace_diftype_t *type, size_t limit)
{
	ASSERT(type->dtdt_flags & DIF_TF_BYREF);

	if (type->dtdt_kind == DIF_TYPE_STRING) {
		dtrace_strcpy(src, dst, MIN(type->dtdt_size, limit));
	} else {
		dtrace_bcopy(src, dst, MIN(type->dtdt_size, limit));
	}
}

/*
 * Compare s1 to s2 using safe memory accesses.  The s1 data is assumed to be
 * unsafe memory specified by the DIF program.  The s2 data is assumed to be
 * safe memory that we can access directly because it is managed by DTrace.
 */
static int
dtrace_bcmp(const void *s1, const void *s2, size_t len)
{
	volatile uint16_t *flags;

	flags = (volatile uint16_t *)&cpuc_dtrace_flags;

	if (s1 == s2)
		return (0);

	if (s1 == NULL || s2 == NULL)
		return (1);

	if (s1 != s2 && len != 0) {
		const uint8_t *ps1 = s1;
		const uint8_t *ps2 = s2;

		do {
			if (dtrace_load8((uintptr_t)ps1++) != *ps2++)
				return (1);
		} while (--len != 0 && !(*flags & CPU_DTRACE_FAULT));
	}
	return (0);
}

/*
 * Zero the specified region using a simple byte-by-byte loop.  Note that this
 * is for safe DTrace-managed memory only.
 */
static void
dtrace_bzero(void *dst, size_t len)
{
	uchar_t *cp;

	for (cp = dst; len != 0; len--)
		*cp++ = 0;
}

static void
dtrace_predicate_hold(dtrace_predicate_t *pred)
{
	assert(pred->dtp_difo != NULL && pred->dtp_difo->dtdo_refcnt != 0);
	assert(pred->dtp_refcnt > 0);

	pred->dtp_refcnt++;
}

/*
 * Note:  called from probe context.  This function is called to reserve space
 * in a buffer.  If mstate is non-NULL, sets the scratch base and size in the
 * mstate.  Returns the new offset in the buffer, or a negative value if an
 * error has occurred.
 */
static intptr_t
dtrace_buffer_reserve(dtrace_buffer_t *buf, size_t needed, size_t align,
    dtrace_state_t *state, dtrace_mstate_t *mstate)
{
	intptr_t offs = buf->dtb_offset, soffs;
	intptr_t woffs;
	caddr_t tomax;
	size_t total;

	if (buf->dtb_flags & DTRACEBUF_INACTIVE)
		return (-1);

	if ((tomax = buf->dtb_tomax) == NULL) {
		dtrace_buffer_drop(buf);
		return (-1);
	}

	if (!(buf->dtb_flags & (DTRACEBUF_RING | DTRACEBUF_FILL))) {
		while (offs & (align - 1)) {
			/*
			 * Assert that our alignment is off by a number which
			 * is itself sizeof (uint32_t) aligned.
			 */
			assert(!((align - (offs & (align - 1))) &
			    (sizeof (uint32_t) - 1)));
			DTRACE_STORE(uint32_t, tomax, offs, DTRACE_EPIDNONE);
			offs += sizeof (uint32_t);
		}

		if ((soffs = offs + needed) > buf->dtb_size) {
			dtrace_buffer_drop(buf);
			return (-1);
		}

		if (mstate == NULL)
			return (offs);

		mstate->dtms_scratch_base = (uintptr_t)tomax + soffs;
		mstate->dtms_scratch_size = buf->dtb_size - soffs;
		mstate->dtms_scratch_ptr = mstate->dtms_scratch_base;

		return (offs);
	}

	if (buf->dtb_flags & DTRACEBUF_FILL) {
		if (state->dts_activity != DTRACE_ACTIVITY_COOLDOWN &&
		    (buf->dtb_flags & DTRACEBUF_FULL))
			return (-1);
		goto out;
	}

	total = needed + (offs & (align - 1));

	/*
	 * For a ring buffer, life is quite a bit more complicated.  Before
	 * we can store any padding, we need to adjust our wrapping offset.
	 * (If we've never before wrapped or we're not about to, no adjustment
	 * is required.)
	 */
	if ((buf->dtb_flags & DTRACEBUF_WRAPPED) ||
	    offs + total > buf->dtb_size) {
		woffs = buf->dtb_xamot_offset;

		if (offs + total > buf->dtb_size) {
			/*
			 * We can't fit in the end of the buffer.  First, a
			 * sanity check that we can fit in the buffer at all.
			 */
			if (total > buf->dtb_size) {
				dtrace_buffer_drop(buf);
				return (-1);
			}

			/*
			 * We're going to be storing at the top of the buffer,
			 * so now we need to deal with the wrapped offset.  We
			 * only reset our wrapped offset to 0 if it is
			 * currently greater than the current offset.  If it
			 * is less than the current offset, it is because a
			 * previous allocation induced a wrap -- but the
			 * allocation didn't subsequently take the space due
			 * to an error or false predicate evaluation.  In this
			 * case, we'll just leave the wrapped offset alone: if
			 * the wrapped offset hasn't been advanced far enough
			 * for this allocation, it will be adjusted in the
			 * lower loop.
			 */
			if (buf->dtb_flags & DTRACEBUF_WRAPPED) {
				if (woffs >= offs)
					woffs = 0;
			} else {
				woffs = 0;
			}

			/*
			 * Now we know that we're going to be storing to the
			 * top of the buffer and that there is room for us
			 * there.  We need to clear the buffer from the current
			 * offset to the end (there may be old gunk there).
			 */
			while (offs < buf->dtb_size)
				tomax[offs++] = 0;

			/*
			 * We need to set our offset to zero.  And because we
			 * are wrapping, we need to set the bit indicating as
			 * much.  We can also adjust our needed space back
			 * down to the space required by the ECB -- we know
			 * that the top of the buffer is aligned.
			 */
			offs = 0;
			total = needed;
			buf->dtb_flags |= DTRACEBUF_WRAPPED;
		} else {
			/*
			 * There is room for us in the buffer, so we simply
			 * need to check the wrapped offset.
			 */
			if (woffs < offs) {
				/*
				 * The wrapped offset is less than the offset.
				 * This can happen if we allocated buffer space
				 * that induced a wrap, but then we didn't
				 * subsequently take the space due to an error
				 * or false predicate evaluation.  This is
				 * okay; we know that _this_ allocation isn't
				 * going to induce a wrap.  We still can't
				 * reset the wrapped offset to be zero,
				 * however: the space may have been trashed in
				 * the previous failed probe attempt.  But at
				 * least the wrapped offset doesn't need to
				 * be adjusted at all...
				 */
				goto out;
			}
		}

		while (offs + total > woffs) {
			dtrace_epid_t epid = *(uint32_t *)(tomax + woffs);
			size_t size;

			if (epid == DTRACE_EPIDNONE) {
				size = sizeof (uint32_t);
			} else {
				ASSERT3U(epid, <=, state->dts_necbs);
				assert(state->dts_ecbs[epid - 1] != NULL);

				size = state->dts_ecbs[epid - 1]->dte_size;
			}

			assert(woffs + size <= buf->dtb_size);
			assert(size != 0);

			if (woffs + size == buf->dtb_size) {
				/*
				 * We've reached the end of the buffer; we want
				 * to set the wrapped offset to 0 and break
				 * out.  However, if the offs is 0, then we're
				 * in a strange edge-condition:  the amount of
				 * space that we want to reserve plus the size
				 * of the record that we're overwriting is
				 * greater than the size of the buffer.  This
				 * is problematic because if we reserve the
				 * space but subsequently don't consume it (due
				 * to a failed predicate or error) the wrapped
				 * offset will be 0 -- yet the EPID at offset 0
				 * will not be committed.  This situation is
				 * relatively easy to deal with:  if we're in
				 * this case, the buffer is indistinguishable
				 * from one that hasn't wrapped; we need only
				 * finish the job by clearing the wrapped bit,
				 * explicitly setting the offset to be 0, and
				 * zero'ing out the old data in the buffer.
				 */
				if (offs == 0) {
					buf->dtb_flags &= ~DTRACEBUF_WRAPPED;
					buf->dtb_offset = 0;
					woffs = total;

					while (woffs < buf->dtb_size)
						tomax[woffs++] = 0;
				}

				woffs = 0;
				break;
			}

			woffs += size;
		}

		/*
		 * We have a wrapped offset.  It may be that the wrapped offset
		 * has become zero -- that's okay.
		 */
		buf->dtb_xamot_offset = woffs;
	}

out:
	/*
	 * Now we can plow the buffer with any necessary padding.
	 */
	while (offs & (align - 1)) {
		/*
		 * Assert that our alignment is off by a number which
		 * is itself sizeof (uint32_t) aligned.
		 */
		assert(!((align - (offs & (align - 1))) &
		    (sizeof (uint32_t) - 1)));
		DTRACE_STORE(uint32_t, tomax, offs, DTRACE_EPIDNONE);
		offs += sizeof (uint32_t);
	}

	if (buf->dtb_flags & DTRACEBUF_FILL) {
		if (offs + needed > buf->dtb_size - state->dts_reserve) {
			buf->dtb_flags |= DTRACEBUF_FULL;
			return (-1);
		}
	}

	if (mstate == NULL)
		return (offs);

	/*
	 * For ring buffers and fill buffers, the scratch space is always
	 * the inactive buffer.
	 */
	mstate->dtms_scratch_base = (uintptr_t)buf->dtb_xamot;
	mstate->dtms_scratch_size = buf->dtb_size;
	mstate->dtms_scratch_ptr = mstate->dtms_scratch_base;

	return (offs);
}

static void
dtrace_action_breakpoint(dtrace_ecb_t *ecb)
{
	/*
	 * TODO: This might be doable with the use of the debug.kdb.enter sysctl
	 * in the case of the kernel and lldb when talking about different
	 * processes.
	 */
#if 0
	dtrace_probe_t *probe = ecb->dte_probe;
	dtrace_provider_t *prov = probe->dtpr_provider;
	char c[DTRACE_FULLNAMELEN + 80], *str;
	char *msg = "dtrace: breakpoint action at probe ";
	char *ecbmsg = " (ecb ";
	uintptr_t mask = (0xf << (sizeof (uintptr_t) * NBBY / 4));
	uintptr_t val = (uintptr_t)ecb;
	int shift = (sizeof (uintptr_t) * NBBY) - 4, i = 0;

	if (dtrace_destructive_disallow)
		return;

	/*
	 * It's impossible to be taking action on the NULL probe.
	 */
	ASSERT(probe != NULL);

	/*
	 * This is a poor man's (destitute man's?) sprintf():  we want to
	 * print the provider name, module name, function name and name of
	 * the probe, along with the hex address of the ECB with the breakpoint
	 * action -- all of which we must place in the character buffer by
	 * hand.
	 */
	while (*msg != '\0')
		c[i++] = *msg++;

	for (str = prov->dtpv_name; *str != '\0'; str++)
		c[i++] = *str;
	c[i++] = ':';

	for (str = probe->dtpr_mod; *str != '\0'; str++)
		c[i++] = *str;
	c[i++] = ':';

	for (str = probe->dtpr_func; *str != '\0'; str++)
		c[i++] = *str;
	c[i++] = ':';

	for (str = probe->dtpr_name; *str != '\0'; str++)
		c[i++] = *str;

	while (*ecbmsg != '\0')
		c[i++] = *ecbmsg++;

	while (shift >= 0) {
		mask = (uintptr_t)0xf << shift;

		if (val >= ((uintptr_t)1 << shift))
			c[i++] = "0123456789abcdef"[(val & mask) >> shift];
		shift -= 4;
	}

	c[i++] = ')';
	c[i] = '\0';

#ifdef illumos
	debug_enter(c);
#else
	kdb_enter(KDB_WHY_DTRACE, "breakpoint action");
#endif
#endif
}

static void
dtrace_action_panic(dtrace_ecb_t *ecb)
{
	/*
	 * There is no actual reason to panic. We will just exit(1) for now, but
	 * we should spawn a debugger.
	 */
#if 0
	dtrace_probe_t *probe = ecb->dte_probe;

	/*
	 * It's impossible to be taking action on the NULL probe.
	 */
	ASSERT(probe != NULL);

	if (dtrace_destructive_disallow)
		return;

	if (dtrace_panicked != NULL)
		return;

	if (dtrace_casptr(&dtrace_panicked, NULL, curthread) != NULL)
		return;

	/*
	 * We won the right to panic.  (We want to be sure that only one
	 * thread calls panic() from dtrace_probe(), and that panic() is
	 * called exactly once.)
	 */
	dtrace_panic("dtrace: panic action at probe %s:%s:%s:%s (ecb %p)",
	    probe->dtpr_provider->dtpv_name, probe->dtpr_mod,
	    probe->dtpr_func, probe->dtpr_name, (void *)ecb);
#endif
	exit(1);
}

static void
dtrace_action_raise(uint64_t sig)
{
	/*
	 * FIXME: This is not the current process, we actually want to know the
	 * PID of this process eventually, but for now, we just call getpid().
	 */
	kill(getpid(), sig);
#if 0
	if (dtrace_destructive_disallow)
		return;

	if (sig >= NSIG) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return;
	}

#ifdef illumos
	/*
	 * raise() has a queue depth of 1 -- we ignore all subsequent
	 * invocations of the raise() action.
	 */
	if (curthread->t_dtrace_sig == 0)
		curthread->t_dtrace_sig = (uint8_t)sig;

	curthread->t_sig_check = 1;
	aston(curthread);
#else
	struct proc *p = curproc;
	PROC_LOCK(p);
	kern_psignal(p, sig);
	PROC_UNLOCK(p);
#endif
#endif
}

static void
dtrace_action_stop(void)
{
	/*
	 * FIXME: Much like sending an arbitrary signal, here we also want to
	 * figure out which PID we should send this to. For now, we just stop
	 * the main tracing process (BAD BAD BAD)
	 */
	exit(0);
#if 0
	if (dtrace_destructive_disallow)
		return;

#ifdef illumos
	if (!curthread->t_dtrace_stop) {
		curthread->t_dtrace_stop = 1;
		curthread->t_sig_check = 1;
		aston(curthread);
	}
#else
	struct proc *p = curproc;
	PROC_LOCK(p);
	kern_psignal(p, SIGSTOP);
	PROC_UNLOCK(p);
#endif
#endif
}

static void
dtrace_action_chill(dtrace_mstate_t *mstate, hrtime_t val)
{
	/*
	 * XXX: Is this... sufficient?
	 */
	sleep(val);
#if 0
	hrtime_t now;
	volatile uint16_t *flags;
#ifdef illumos
	cpu_t *cpu = CPU;
#else
	cpu_t *cpu = &solaris_cpu[curcpu];
#endif

	if (dtrace_destructive_disallow)
		return;

	flags = (volatile uint16_t *)&cpu_core[curcpu].cpuc_dtrace_flags;

	now = dtrace_gethrtime();

	if (now - cpu->cpu_dtrace_chillmark > dtrace_chill_interval) {
		/*
		 * We need to advance the mark to the current time.
		 */
		cpu->cpu_dtrace_chillmark = now;
		cpu->cpu_dtrace_chilled = 0;
	}

	/*
	 * Now check to see if the requested chill time would take us over
	 * the maximum amount of time allowed in the chill interval.  (Or
	 * worse, if the calculation itself induces overflow.)
	 */
	if (cpu->cpu_dtrace_chilled + val > dtrace_chill_max ||
	    cpu->cpu_dtrace_chilled + val < cpu->cpu_dtrace_chilled) {
		*flags |= CPU_DTRACE_ILLOP;
		return;
	}

	while (dtrace_gethrtime() - now < val)
		continue;

	/*
	 * Normally, we assure that the value of the variable "timestamp" does
	 * not change within an ECB.  The presence of chill() represents an
	 * exception to this rule, however.
	 */
	mstate->dtms_present &= ~DTRACE_MSTATE_TIMESTAMP;
	cpu->cpu_dtrace_chilled += val;
#endif
}

static void
dtrace_action_ustack(dtrace_mstate_t *mstate, dtrace_state_t *state,
    uint64_t *buf, uint64_t arg)
{
	/*
	 * TODO: Here we probably want to make use of the CTF data, keep some
	 * state or even a debugger!
	 */
#if 0
	int nframes = DTRACE_USTACK_NFRAMES(arg);
	int strsize = DTRACE_USTACK_STRSIZE(arg);
	uint64_t *pcs = &buf[1], *fps;
	char *str = (char *)&pcs[nframes];
	int size, offs = 0, i, j;
	size_t rem;
	uintptr_t old = mstate->dtms_scratch_ptr, saved;
	uint16_t *flags = &cpu_core[curcpu].cpuc_dtrace_flags;
	char *sym;

	/*
	 * Should be taking a faster path if string space has not been
	 * allocated.
	 */
	ASSERT(strsize != 0);

	/*
	 * We will first allocate some temporary space for the frame pointers.
	 */
	fps = (uint64_t *)P2ROUNDUP(mstate->dtms_scratch_ptr, 8);
	size = (uintptr_t)fps - mstate->dtms_scratch_ptr +
	    (nframes * sizeof (uint64_t));

	if (!DTRACE_INSCRATCH(mstate, size)) {
		/*
		 * Not enough room for our frame pointers -- need to indicate
		 * that we ran out of scratch space.
		 */
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
		return;
	}

	mstate->dtms_scratch_ptr += size;
	saved = mstate->dtms_scratch_ptr;

	/*
	 * Now get a stack with both program counters and frame pointers.
	 */
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	dtrace_getufpstack(buf, fps, nframes + 1);
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	/*
	 * If that faulted, we're cooked.
	 */
	if (*flags & CPU_DTRACE_FAULT)
		goto out;

	/*
	 * Now we want to walk up the stack, calling the USTACK helper.  For
	 * each iteration, we restore the scratch pointer.
	 */
	for (i = 0; i < nframes; i++) {
		mstate->dtms_scratch_ptr = saved;

		if (offs >= strsize)
			break;

		sym = (char *)(uintptr_t)dtrace_helper(
		    DTRACE_HELPER_ACTION_USTACK,
		    mstate, state, pcs[i], fps[i]);

		/*
		 * If we faulted while running the helper, we're going to
		 * clear the fault and null out the corresponding string.
		 */
		if (*flags & CPU_DTRACE_FAULT) {
			*flags &= ~CPU_DTRACE_FAULT;
			str[offs++] = '\0';
			continue;
		}

		if (sym == NULL) {
			str[offs++] = '\0';
			continue;
		}

		if (!dtrace_strcanload((uintptr_t)sym, strsize, &rem, mstate,
		    &(state->dts_vstate))) {
			str[offs++] = '\0';
			continue;
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);

		/*
		 * Now copy in the string that the helper returned to us.
		 */
		for (j = 0; offs + j < strsize && j < rem; j++) {
			if ((str[offs + j] = sym[j]) == '\0')
				break;
		}

		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

		offs += j + 1;
	}

	if (offs >= strsize) {
		/*
		 * If we didn't have room for all of the strings, we don't
		 * abort processing -- this needn't be a fatal error -- but we
		 * still want to increment a counter (dts_stkstroverflows) to
		 * allow this condition to be warned about.  (If this is from
		 * a jstack() action, it is easily tuned via jstackstrsize.)
		 */
		dtrace_error(&state->dts_stkstroverflows);
	}

	while (offs < strsize)
		str[offs++] = '\0';

out:
	mstate->dtms_scratch_ptr = old;
#endif
}

/*
 * DTrace Probe Hashing Functions
 *
 * The functions in this section (and indeed, the functions in remaining
 * sections) are not _called_ from probe context.  (Any exceptions to this are
 * marked with a "Note:".)  Rather, they are called from elsewhere in the
 * DTrace framework to look-up probes in, add probes to and remove probes from
 * the DTrace probe hashes.  (Each probe is hashed by each element of the
 * probe tuple -- allowing for fast lookups, regardless of what was
 * specified.)
 */
static uint_t
dtrace_hash_str(const char *p)
{
	unsigned int g;
	uint_t hval = 0;

	while (*p) {
		hval = (hval << 4) + *p++;
		if ((g = (hval & 0xf0000000)) != 0)
			hval ^= g >> 24;
		hval &= ~g;
	}
	return (hval);
}

static dtrace_hash_t *
dtrace_hash_create(uintptr_t stroffs, uintptr_t nextoffs, uintptr_t prevoffs)
{
	dtrace_hash_t *hash = calloc(1, sizeof (dtrace_hash_t));

	if (hash == NULL)
		return (NULL);

	hash->dth_stroffs = stroffs;
	hash->dth_nextoffs = nextoffs;
	hash->dth_prevoffs = prevoffs;

	hash->dth_size = 1;
	hash->dth_mask = hash->dth_size - 1;

	hash->dth_tab = calloc(hash->dth_size, sizeof (dtrace_hashbucket_t *));
	assert(hash->dth_tab != NULL);

	return (hash);
}

static void
dtrace_hash_destroy(dtrace_hash_t *hash)
{
#ifdef DEBUG
	int i;

	for (i = 0; i < hash->dth_size; i++)
		assert(hash->dth_tab[i] == NULL);
#endif

	free(hash->dth_tab);
	free(hash);
}

static void
dtrace_hash_resize(dtrace_hash_t *hash)
{
	int size = hash->dth_size, i, ndx;
	int new_size = hash->dth_size << 1;
	int new_mask = new_size - 1;
	dtrace_hashbucket_t **new_tab, *bucket, *next;

	assert((new_size & new_mask) == 0);

	new_tab = calloc(1, new_size * sizeof (void *));
	assert(new_tab != NULL);

	for (i = 0; i < size; i++) {
		for (bucket = hash->dth_tab[i]; bucket != NULL; bucket = next) {
			dtrace_probe_t *probe = bucket->dthb_chain;

			assert(probe != NULL);
			ndx = DTRACE_HASHSTR(hash, probe) & new_mask;

			next = bucket->dthb_next;
			bucket->dthb_next = new_tab[ndx];
			new_tab[ndx] = bucket;
		}
	}

	free(hash->dth_tab);
	hash->dth_tab = new_tab;
	hash->dth_size = new_size;
	hash->dth_mask = new_mask;
}

static void
dtrace_hash_add(dtrace_hash_t *hash, dtrace_probe_t *new)
{
	int hashval = DTRACE_HASHSTR(hash, new);
	int ndx = hashval & hash->dth_mask;
	dtrace_hashbucket_t *bucket = hash->dth_tab[ndx];
	dtrace_probe_t **nextp, **prevp;

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, new))
			goto add;
	}

	if ((hash->dth_nbuckets >> 1) > hash->dth_size) {
		dtrace_hash_resize(hash);
		dtrace_hash_add(hash, new);
		return;
	}

	bucket = calloc(1, sizeof (dtrace_hashbucket_t));
	bucket->dthb_next = hash->dth_tab[ndx];
	hash->dth_tab[ndx] = bucket;
	hash->dth_nbuckets++;

add:
	nextp = DTRACE_HASHNEXT(hash, new);
	assert(*nextp == NULL && *(DTRACE_HASHPREV(hash, new)) == NULL);
	*nextp = bucket->dthb_chain;

	if (bucket->dthb_chain != NULL) {
		prevp = DTRACE_HASHPREV(hash, bucket->dthb_chain);
		assert(*prevp == NULL);
		*prevp = new;
	}

	bucket->dthb_chain = new;
	bucket->dthb_len++;
}

static dtrace_probe_t *
dtrace_hash_lookup(dtrace_hash_t *hash, dtrace_probe_t *template)
{
	int hashval = DTRACE_HASHSTR(hash, template);
	int ndx = hashval & hash->dth_mask;
	dtrace_hashbucket_t *bucket = hash->dth_tab[ndx];

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, template))
			return (bucket->dthb_chain);
	}

	return (NULL);
}

static int
dtrace_hash_collisions(dtrace_hash_t *hash, dtrace_probe_t *template)
{
	int hashval = DTRACE_HASHSTR(hash, template);
	int ndx = hashval & hash->dth_mask;
	dtrace_hashbucket_t *bucket = hash->dth_tab[ndx];

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, template))
			return (bucket->dthb_len);
	}

	return (0);
}

static void
dtrace_hash_remove(dtrace_hash_t *hash, dtrace_probe_t *probe)
{
	int ndx = DTRACE_HASHSTR(hash, probe) & hash->dth_mask;
	dtrace_hashbucket_t *bucket = hash->dth_tab[ndx];

	dtrace_probe_t **prevp = DTRACE_HASHPREV(hash, probe);
	dtrace_probe_t **nextp = DTRACE_HASHNEXT(hash, probe);

	/*
	 * Find the bucket that we're removing this probe from.
	 */
	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, probe))
			break;
	}

	assert(bucket != NULL);

	if (*prevp == NULL) {
		if (*nextp == NULL) {
			/*
			 * The removed probe was the only probe on this
			 * bucket; we need to remove the bucket.
			 */
			dtrace_hashbucket_t *b = hash->dth_tab[ndx];

			assert(bucket->dthb_chain == probe);
			assert(b != NULL);

			if (b == bucket) {
				hash->dth_tab[ndx] = bucket->dthb_next;
			} else {
				while (b->dthb_next != bucket)
					b = b->dthb_next;
				b->dthb_next = bucket->dthb_next;
			}

			assert(hash->dth_nbuckets > 0);
			hash->dth_nbuckets--;
			free(bucket);
			return;
		}

		bucket->dthb_chain = *nextp;
	} else {
		*(DTRACE_HASHNEXT(hash, *prevp)) = *nextp;
	}

	if (*nextp != NULL)
		*(DTRACE_HASHPREV(hash, *nextp)) = *prevp;
}

static void
dtrace_cred2priv(cred_t *cr, uint32_t *privp, uid_t *uidp, zoneid_t *zoneidp)
{
	uint32_t priv;

	priv = DTRACE_PRIV_ALL;
	*privp = priv;
}

static void
dtrace_difo_destroy(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	int i;

	assert(dp->dtdo_refcnt == 0);

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i];
		dtrace_statvar_t *svar, **svarp = NULL;
		uint_t id;
		uint8_t scope = v->dtdv_scope;
		int *np = NULL;

		switch (scope) {
		case DIFV_SCOPE_THREAD:
			continue;

		case DIFV_SCOPE_LOCAL:
			np = &vstate->dtvs_nlocals;
			svarp = vstate->dtvs_locals;
			break;

		case DIFV_SCOPE_GLOBAL:
			np = &vstate->dtvs_nglobals;
			svarp = vstate->dtvs_globals;
			break;

		default:
			assert(0);
		}

		if ((id = v->dtdv_id) < DIF_VAR_OTHER_UBASE)
			continue;

		id -= DIF_VAR_OTHER_UBASE;
		assert(id < *np);

		svar = svarp[id];
		assert(svar != NULL);
		assert(svar->dtsv_refcnt > 0);

		if (--svar->dtsv_refcnt > 0)
			continue;

		if (svar->dtsv_size != 0) {
			assert(svar->dtsv_data != 0);
			free((void *)(uintptr_t)svar->dtsv_data);
		}

		free(svar);
		svarp[id] = NULL;
	}

	if (dp->dtdo_buf != NULL)
		free(dp->dtdo_buf);
	if (dp->dtdo_inttab != NULL)
		free(dp->dtdo_inttab);
	if (dp->dtdo_strtab != NULL)
		free(dp->dtdo_strtab);
	if (dp->dtdo_vartab != NULL)
		free(dp->dtdo_vartab);

	free(dp);
}

static void
dtrace_difo_release(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	int i;

	assert(dp->dtdo_refcnt != 0);

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i];

		if (v->dtdv_id != DIF_VAR_VTIMESTAMP)
			continue;

		assert(dtrace_vtime_references > 0);
		if (--dtrace_vtime_references == 0)
			dtrace_vtime_disable();
	}

	if (--dp->dtdo_refcnt == 0)
		dtrace_difo_destroy(dp, vstate);
}

static void
dtrace_predicate_release(dtrace_predicate_t *pred, dtrace_vstate_t *vstate)
{
	dtrace_difo_t *dp = pred->dtp_difo;

	assert(dp != NULL && dp->dtdo_refcnt != 0);
	assert(pred->dtp_refcnt > 0);

	if (--pred->dtp_refcnt == 0) {
		dtrace_difo_release(pred->dtp_difo, vstate);
		free(pred);
	}
}

/*
 * Returns 1 if the expression in the DIF object can be cached on a per-thread
 * basis; 0 if not.
 */
static int
dtrace_difo_cacheable(dtrace_difo_t *dp)
{
	int i;

	if (dp == NULL)
		return (0);

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i];

		if (v->dtdv_scope != DIFV_SCOPE_GLOBAL)
			continue;

		switch (v->dtdv_id) {
		case DIF_VAR_CURTHREAD:
		case DIF_VAR_PID:
		case DIF_VAR_TID:
		case DIF_VAR_EXECARGS:
		case DIF_VAR_EXECNAME:
		case DIF_VAR_ZONENAME:
			break;

		default:
			return (0);
		}
	}

	/*
	 * This DIF object may be cacheable.  Now we need to look for any
	 * array loading instructions, any memory loading instructions, or
	 * any stores to thread-local variables.
	 */
	for (i = 0; i < dp->dtdo_len; i++) {
		uint_t op = DIF_INSTR_OP(dp->dtdo_buf[i]);

		if ((op >= DIF_OP_LDSB && op <= DIF_OP_LDX) ||
		    (op >= DIF_OP_ULDSB && op <= DIF_OP_ULDX) ||
		    (op >= DIF_OP_RLDSB && op <= DIF_OP_RLDX) ||
		    op == DIF_OP_LDGA || op == DIF_OP_STTS)
			return (0);
	}

	return (1);
}

static void
dtrace_difo_hold(dtrace_difo_t *dp)
{
	int i;

	dp->dtdo_refcnt++;
	assert(dp->dtdo_refcnt != 0);

	/*
	 * We need to check this DIF object for references to the variable
	 * DIF_VAR_VTIMESTAMP.
	 */
	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i];

		if (v->dtdv_id != DIF_VAR_VTIMESTAMP)
			continue;

		if (dtrace_vtime_references++ == 0)
			dtrace_vtime_enable();
	}
}

/*
 * This routine calculates the dynamic variable chunksize for a given DIF
 * object.  The calculation is not fool-proof, and can probably be tricked by
 * malicious DIF -- but it works for all compiler-generated DIF.  Because this
 * calculation is likely imperfect, dtrace_dynvar() is able to gracefully fail
 * if a dynamic variable size exceeds the chunksize.
 */
static void
dtrace_difo_chunksize(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	uint64_t sval = 0;
	dtrace_key_t tupregs[DIF_DTR_NREGS + 2]; /* +2 for thread and id */
	const dif_instr_t *text = dp->dtdo_buf;
	uint_t pc, srd = 0;
	uint_t ttop = 0;
	size_t size, ksize;
	uint_t id, i;

	for (pc = 0; pc < dp->dtdo_len; pc++) {
		dif_instr_t instr = text[pc];
		uint_t op = DIF_INSTR_OP(instr);
		uint_t rd = DIF_INSTR_RD(instr);
		uint_t r1 = DIF_INSTR_R1(instr);
		uint_t nkeys = 0;
		uchar_t scope = 0;

		dtrace_key_t *key = tupregs;

		switch (op) {
		case DIF_OP_SETX:
			sval = dp->dtdo_inttab[DIF_INSTR_INTEGER(instr)];
			srd = rd;
			continue;

		case DIF_OP_STTS:
			key = &tupregs[DIF_DTR_NREGS];
			key[0].dttk_size = 0;
			key[1].dttk_size = 0;
			nkeys = 2;
			scope = DIFV_SCOPE_THREAD;
			break;

		case DIF_OP_STGAA:
		case DIF_OP_STTAA:
			nkeys = ttop;

			if (DIF_INSTR_OP(instr) == DIF_OP_STTAA)
				key[nkeys++].dttk_size = 0;

			key[nkeys++].dttk_size = 0;

			if (op == DIF_OP_STTAA) {
				scope = DIFV_SCOPE_THREAD;
			} else {
				scope = DIFV_SCOPE_GLOBAL;
			}

			break;

		case DIF_OP_PUSHTR:
			if (ttop == DIF_DTR_NREGS)
				return;

			if ((srd == 0 || sval == 0) && r1 == DIF_TYPE_STRING) {
				/*
				 * If the register for the size of the "pushtr"
				 * is %r0 (or the value is 0) and the type is
				 * a string, we'll use the system-wide default
				 * string size.
				 */
				tupregs[ttop++].dttk_size =
				    dtrace_strsize_default;
			} else {
				if (srd == 0)
					return;

				if (sval > LONG_MAX)
					return;

				tupregs[ttop++].dttk_size = sval;
			}

			break;

		case DIF_OP_PUSHTV:
			if (ttop == DIF_DTR_NREGS)
				return;

			tupregs[ttop++].dttk_size = 0;
			break;

		case DIF_OP_FLUSHTS:
			ttop = 0;
			break;

		case DIF_OP_POPTS:
			if (ttop != 0)
				ttop--;
			break;
		}

		sval = 0;
		srd = 0;

		if (nkeys == 0)
			continue;

		/*
		 * We have a dynamic variable allocation; calculate its size.
		 */
		for (ksize = 0, i = 0; i < nkeys; i++)
			ksize += P2ROUNDUP(key[i].dttk_size, sizeof (uint64_t));

		size = sizeof (dtrace_dynvar_t);
		size += sizeof (dtrace_key_t) * (nkeys - 1);
		size += ksize;

		/*
		 * Now we need to determine the size of the stored data.
		 */
		id = DIF_INSTR_VAR(instr);

		for (i = 0; i < dp->dtdo_varlen; i++) {
			dtrace_difv_t *v = &dp->dtdo_vartab[i];

			if (v->dtdv_id == id && v->dtdv_scope == scope) {
				size += v->dtdv_type.dtdt_size;
				break;
			}
		}

		if (i == dp->dtdo_varlen)
			return;

		/*
		 * We have the size.  If this is larger than the chunk size
		 * for our dynamic variable state, reset the chunk size.
		 */
		size = P2ROUNDUP(size, sizeof (uint64_t));

		/*
		 * Before setting the chunk size, check that we're not going
		 * to set it to a negative value...
		 */
		if (size > LONG_MAX)
			return;

		/*
		 * ...and make certain that we didn't badly overflow.
		 */
		if (size < ksize || size < sizeof (dtrace_dynvar_t))
			return;

		if (size > vstate->dtvs_dynvars.dtds_chunksize)
			vstate->dtvs_dynvars.dtds_chunksize = size;
	}
}

static void
dtrace_difo_init(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	int i, oldsvars, osz, nsz, otlocals, ntlocals;
	uint_t id;

	assert(dp->dtdo_buf != NULL && dp->dtdo_len != 0);

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i];
		dtrace_statvar_t *svar, ***svarp = NULL;
		size_t dsize = 0;
		uint8_t scope = v->dtdv_scope;
		int *np = NULL;

		if ((id = v->dtdv_id) < DIF_VAR_OTHER_UBASE)
			continue;

		id -= DIF_VAR_OTHER_UBASE;

		switch (scope) {
		case DIFV_SCOPE_THREAD:
			while (id >= (otlocals = vstate->dtvs_ntlocals)) {
				dtrace_difv_t *tlocals;

				if ((ntlocals = (otlocals << 1)) == 0)
					ntlocals = 1;

				osz = otlocals * sizeof (dtrace_difv_t);
				nsz = ntlocals * sizeof (dtrace_difv_t);

				tlocals = calloc(1, nsz);
				if (tlocals == NULL)
					return;

				if (osz != 0) {
					bcopy(vstate->dtvs_tlocals,
					    tlocals, osz);
					free(vstate->dtvs_tlocals);
				}

				vstate->dtvs_tlocals = tlocals;
				vstate->dtvs_ntlocals = ntlocals;
			}

			vstate->dtvs_tlocals[id] = *v;
			continue;

		case DIFV_SCOPE_LOCAL:
			np = &vstate->dtvs_nlocals;
			svarp = &vstate->dtvs_locals;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF)
				dsize = NCPU * (v->dtdv_type.dtdt_size +
				    sizeof (uint64_t));
			else
				dsize = NCPU * sizeof (uint64_t);

			break;

		case DIFV_SCOPE_GLOBAL:
			np = &vstate->dtvs_nglobals;
			svarp = &vstate->dtvs_globals;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF)
				dsize = v->dtdv_type.dtdt_size +
				    sizeof (uint64_t);

			break;

		default:
			assert(0);
		}

		while (id >= (oldsvars = *np)) {
			dtrace_statvar_t **statics;
			int newsvars, oldsize, newsize;

			if ((newsvars = (oldsvars << 1)) == 0)
				newsvars = 1;

			oldsize = oldsvars * sizeof (dtrace_statvar_t *);
			newsize = newsvars * sizeof (dtrace_statvar_t *);

			statics = calloc(1, newsize);
			if (statics == NULL)
				return;

			if (oldsize != 0) {
				bcopy(*svarp, statics, oldsize);
				free(*svarp);
			}

			*svarp = statics;
			*np = newsvars;
		}

		if ((svar = (*svarp)[id]) == NULL) {
			svar = calloc(1, sizeof (dtrace_statvar_t));
			svar->dtsv_var = *v;

			if ((svar->dtsv_size = dsize) != 0) {
				svar->dtsv_data = (uint64_t)(uintptr_t)
				    calloc(1, dsize);
			}

			(*svarp)[id] = svar;
		}

		svar->dtsv_refcnt++;
	}

	dtrace_difo_chunksize(dp, vstate);
	dtrace_difo_hold(dp);
}

static dtrace_difo_t *
dtrace_difo_duplicate(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	dtrace_difo_t *new;
	size_t sz;

	assert(dp->dtdo_buf != NULL);
	assert(dp->dtdo_refcnt != 0);

	new = calloc(1, sizeof (dtrace_difo_t));

	assert(dp->dtdo_buf != NULL);
	sz = dp->dtdo_len * sizeof (dif_instr_t);
	new->dtdo_buf = malloc(sz);
	if (new->dtdo_buf == NULL)
		return (NULL);

	bcopy(dp->dtdo_buf, new->dtdo_buf, sz);
	new->dtdo_len = dp->dtdo_len;

	if (dp->dtdo_strtab != NULL) {
		assert(dp->dtdo_strlen != 0);
		new->dtdo_strtab = malloc(dp->dtdo_strlen);
		if (new->dtdo_strtab == NULL)
			return (NULL);

		bcopy(dp->dtdo_strtab, new->dtdo_strtab, dp->dtdo_strlen);
		new->dtdo_strlen = dp->dtdo_strlen;
	}

	if (dp->dtdo_inttab != NULL) {
		assert(dp->dtdo_intlen != 0);
		sz = dp->dtdo_intlen * sizeof (uint64_t);
		new->dtdo_inttab = malloc(sz);
		if (new->dtdo_inttab == NULL)
			return (NULL);

		bcopy(dp->dtdo_inttab, new->dtdo_inttab, sz);
		new->dtdo_intlen = dp->dtdo_intlen;
	}

	if (dp->dtdo_vartab != NULL) {
		assert(dp->dtdo_varlen != 0);
		sz = dp->dtdo_varlen * sizeof (dtrace_difv_t);
		new->dtdo_vartab = malloc(sz);
		if (new->dtdo_vartab == NULL)
			return (NULL);

		bcopy(dp->dtdo_vartab, new->dtdo_vartab, sz);
		new->dtdo_varlen = dp->dtdo_varlen;
	}

	dtrace_difo_init(new, vstate);
	return (new);
}

/*
 * DTrace Format Functions
 */
static uint16_t
dtrace_format_add(dtrace_state_t *state, char *str)
{
	char *fmt, **new;
	uint16_t ndx, len = strlen(str) + 1;

	fmt = calloc(1, len);
	assert(fmt != NULL);
	bcopy(str, fmt, len);

	for (ndx = 0; ndx < state->dts_nformats; ndx++) {
		if (state->dts_formats[ndx] == NULL) {
			state->dts_formats[ndx] = fmt;
			return (ndx + 1);
		}
	}

	if (state->dts_nformats == USHRT_MAX) {
		/*
		 * This is only likely if a denial-of-service attack is being
		 * attempted.  As such, it's okay to fail silently here.
		 */
		free(fmt);
		return (0);
	}

	/*
	 * For simplicity, we always resize the formats array to be exactly the
	 * number of formats.
	 */
	ndx = state->dts_nformats++;
	new = malloc((ndx + 1) * sizeof (char *));
	assert(new != NULL);

	if (state->dts_formats != NULL) {
		assert(ndx != 0);
		bcopy(state->dts_formats, new, ndx * sizeof (char *));
		free(state->dts_formats);
	}

	state->dts_formats = new;
	state->dts_formats[ndx] = fmt;

	return (ndx + 1);
}

static void
dtrace_format_remove(dtrace_state_t *state, uint16_t format)
{
	char *fmt;

	assert(state->dts_formats != NULL);
	assert(format <= state->dts_nformats);
	assert(state->dts_formats[format - 1] != NULL);

	fmt = state->dts_formats[format - 1];
	free(fmt);
	state->dts_formats[format - 1] = NULL;
}

static void
dtrace_format_destroy(dtrace_state_t *state)
{
	int i;

	if (state->dts_nformats == 0) {
		assert(state->dts_formats == NULL);
		return;
	}

	assert(state->dts_formats != NULL);

	for (i = 0; i < state->dts_nformats; i++) {
		char *fmt = state->dts_formats[i];

		if (fmt == NULL)
			continue;

		free(fmt);
	}

	free(state->dts_formats);
	state->dts_nformats = 0;
	state->dts_formats = NULL;
}

static void
dtrace_add_128(uint64_t *addend1, uint64_t *addend2, uint64_t *sum)
{
	uint64_t result[2];

	result[0] = addend1[0] + addend2[0];
	result[1] = addend1[1] + addend2[1] +
	    (result[0] < addend1[0] || result[0] < addend2[0] ? 1 : 0);

	sum[0] = result[0];
	sum[1] = result[1];
}

/*
 * Shift the 128-bit value in a by b. If b is positive, shift left.
 * If b is negative, shift right.
 */
static void
dtrace_shift_128(uint64_t *a, int b)
{
	uint64_t mask;

	if (b == 0)
		return;

	if (b < 0) {
		b = -b;
		if (b >= 64) {
			a[0] = a[1] >> (b - 64);
			a[1] = 0;
		} else {
			a[0] >>= b;
			mask = 1LL << (64 - b);
			mask -= 1;
			a[0] |= ((a[1] & mask) << (64 - b));
			a[1] >>= b;
		}
	} else {
		if (b >= 64) {
			a[1] = a[0] << (b - 64);
			a[0] = 0;
		} else {
			a[1] <<= b;
			mask = a[0] >> (64 - b);
			a[1] |= mask;
			a[0] <<= b;
		}
	}
}

static void
dtrace_multiply_128(uint64_t factor1, uint64_t factor2, uint64_t *product)
{
	uint64_t hi1, hi2, lo1, lo2;
	uint64_t tmp[2];

	hi1 = factor1 >> 32;
	hi2 = factor2 >> 32;

	lo1 = factor1 & DT_MASK_LO;
	lo2 = factor2 & DT_MASK_LO;

	product[0] = lo1 * lo2;
	product[1] = hi1 * hi2;

	tmp[0] = hi1 * lo2;
	tmp[1] = 0;
	dtrace_shift_128(tmp, 32);
	dtrace_add_128(product, tmp, product);

	tmp[0] = hi2 * lo1;
	tmp[1] = 0;
	dtrace_shift_128(tmp, 32);
	dtrace_add_128(product, tmp, product);
}

/*
 * This privilege check should be used by actions and subroutines to
 * verify that the user credentials of the process that enabled the
 * invoking ECB match the target credentials
 */
static int
dtrace_priv_proc_common_user(dtrace_state_t *state)
{
	/*
	 * FIXME: We have cred for everything
	 */
	return (1);
#if 0
	cred_t *cr, *s_cr = state->dts_cred.dcr_cred;

	/*
	 * We should always have a non-NULL state cred here, since if cred
	 * is null (anonymous tracing), we fast-path bypass this routine.
	 */
	assert(s_cr != NULL);

	if ((cr = CRED()) != NULL &&
	    s_cr->cr_uid == cr->cr_uid &&
	    s_cr->cr_uid == cr->cr_ruid &&
	    s_cr->cr_uid == cr->cr_suid &&
	    s_cr->cr_gid == cr->cr_gid &&
	    s_cr->cr_gid == cr->cr_rgid &&
	    s_cr->cr_gid == cr->cr_sgid)
		return (1);

	return (0);
#endif
}

/*
 * This privilege check should be used by actions and subroutines to
 * verify that the zone of the process that enabled the invoking ECB
 * matches the target credentials
 */
static int
dtrace_priv_proc_common_zone(dtrace_state_t *state)
{
#ifdef illumos
	cred_t *cr, *s_cr = state->dts_cred.dcr_cred;

	/*
	 * We should always have a non-NULL state cred here, since if cred
	 * is null (anonymous tracing), we fast-path bypass this routine.
	 */
	ASSERT(s_cr != NULL);

	if ((cr = CRED()) != NULL && s_cr->cr_zone == cr->cr_zone)
		return (1);

	return (0);
#else
	return (1);
#endif
}

/*
 * This privilege check should be used by actions and subroutines to
 * verify that the process has not setuid or changed credentials.
 */
static int
dtrace_priv_proc_common_nocd(void)
{
	return (1);
#if 0
	proc_t *proc;

	if ((proc = ttoproc(curthread)) != NULL &&
	    !(proc->p_flag & SNOCD))
		return (1);

	return (0);
#endif
}

static int
dtrace_priv_proc_destructive(dtrace_state_t *state)
{
	int action = state->dts_cred.dcr_action;

	if (((action & DTRACE_CRA_PROC_DESTRUCTIVE_ALLZONE) == 0) &&
	    dtrace_priv_proc_common_zone(state) == 0)
		goto bad;

	if (((action & DTRACE_CRA_PROC_DESTRUCTIVE_ALLUSER) == 0) &&
	    dtrace_priv_proc_common_user(state) == 0)
		goto bad;

	if (((action & DTRACE_CRA_PROC_DESTRUCTIVE_CREDCHG) == 0) &&
	    dtrace_priv_proc_common_nocd() == 0)
		goto bad;

	return (1);

bad:
	cpuc_dtrace_flags |= CPU_DTRACE_UPRIV;

	return (0);
}

static int
dtrace_priv_proc_control(dtrace_state_t *state)
{
	if (state->dts_cred.dcr_action & DTRACE_CRA_PROC_CONTROL)
		return (1);

	if (dtrace_priv_proc_common_zone(state) &&
	    dtrace_priv_proc_common_user(state) &&
	    dtrace_priv_proc_common_nocd())
		return (1);

	cpuc_dtrace_flags |= CPU_DTRACE_UPRIV;

	return (0);
}

static int
dtrace_priv_proc(dtrace_state_t *state)
{
	if (state->dts_cred.dcr_action & DTRACE_CRA_PROC)
		return (1);

	cpuc_dtrace_flags |= CPU_DTRACE_UPRIV;

	return (0);
}

static int
dtrace_priv_kernel(dtrace_state_t *state)
{
	if (state->dts_cred.dcr_action & DTRACE_CRA_KERNEL)
		return (1);

	cpuc_dtrace_flags |= CPU_DTRACE_KPRIV;

	return (0);
}

static int
dtrace_priv_kernel_destructive(dtrace_state_t *state)
{
	if (state->dts_cred.dcr_action & DTRACE_CRA_KERNEL_DESTRUCTIVE)
		return (1);

	cpuc_dtrace_flags |= CPU_DTRACE_KPRIV;

	return (0);
}

/*
 * Determine if the dte_cond of the specified ECB allows for processing of
 * the current probe to continue.  Note that this routine may allow continued
 * processing, but with access(es) stripped from the mstate's dtms_access
 * field.
 */
static int
dtrace_priv_probe(dtrace_state_t *state, dtrace_mstate_t *mstate,
    dtrace_ecb_t *ecb)
{
	dtrace_probe_t *probe = ecb->dte_probe;
	dtrace_provider_t *prov = probe->dtpr_provider;
	dtrace_pops_t *pops = &prov->dtpv_pops;
	int mode = DTRACE_MODE_NOPRIV_DROP;

	ASSERT(ecb->dte_cond);

#ifdef illumos
	if (pops->dtps_mode != NULL) {
		mode = pops->dtps_mode(prov->dtpv_arg,
		    probe->dtpr_id, probe->dtpr_arg);

		ASSERT((mode & DTRACE_MODE_USER) ||
		    (mode & DTRACE_MODE_KERNEL));
		ASSERT((mode & DTRACE_MODE_NOPRIV_RESTRICT) ||
		    (mode & DTRACE_MODE_NOPRIV_DROP));
	}

	/*
	 * If the dte_cond bits indicate that this consumer is only allowed to
	 * see user-mode firings of this probe, call the provider's dtps_mode()
	 * entry point to check that the probe was fired while in a user
	 * context.  If that's not the case, use the policy specified by the
	 * provider to determine if we drop the probe or merely restrict
	 * operation.
	 */
	if (ecb->dte_cond & DTRACE_COND_USERMODE) {
		ASSERT(mode != DTRACE_MODE_NOPRIV_DROP);

		if (!(mode & DTRACE_MODE_USER)) {
			if (mode & DTRACE_MODE_NOPRIV_DROP)
				return (0);

			mstate->dtms_access &= ~DTRACE_ACCESS_ARGS;
		}
	}
#endif

	/*
	 * FIXME: We don't care about this *right now*, but we do generally.
	 */
#if 0
	/*
	 * This is more subtle than it looks. We have to be absolutely certain
	 * that CRED() isn't going to change out from under us so it's only
	 * legit to examine that structure if we're in constrained situations.
	 * Currently, the only times we'll this check is if a non-super-user
	 * has enabled the profile or syscall providers -- providers that
	 * allow visibility of all processes. For the profile case, the check
	 * above will ensure that we're examining a user context.
	 */
	if (ecb->dte_cond & DTRACE_COND_OWNER) {
		cred_t *cr;
		cred_t *s_cr = state->dts_cred.dcr_cred;
		proc_t *proc;

		ASSERT(s_cr != NULL);

		if ((cr = CRED()) == NULL ||
		    s_cr->cr_uid != cr->cr_uid ||
		    s_cr->cr_uid != cr->cr_ruid ||
		    s_cr->cr_uid != cr->cr_suid ||
		    s_cr->cr_gid != cr->cr_gid ||
		    s_cr->cr_gid != cr->cr_rgid ||
		    s_cr->cr_gid != cr->cr_sgid ||
		    (proc = ttoproc(curthread)) == NULL ||
		    (proc->p_flag & SNOCD)) {
			if (mode & DTRACE_MODE_NOPRIV_DROP)
				return (0);

#ifdef illumos
			mstate->dtms_access &= ~DTRACE_ACCESS_PROC;
#endif
		}
	}
#endif

#ifdef illumos
	/*
	 * If our dte_cond is set to DTRACE_COND_ZONEOWNER and we are not
	 * in our zone, check to see if our mode policy is to restrict rather
	 * than to drop; if to restrict, strip away both DTRACE_ACCESS_PROC
	 * and DTRACE_ACCESS_ARGS
	 */
	if (ecb->dte_cond & DTRACE_COND_ZONEOWNER) {
		cred_t *cr;
		cred_t *s_cr = state->dts_cred.dcr_cred;

		ASSERT(s_cr != NULL);

		if ((cr = CRED()) == NULL ||
		    s_cr->cr_zone->zone_id != cr->cr_zone->zone_id) {
			if (mode & DTRACE_MODE_NOPRIV_DROP)
				return (0);

			mstate->dtms_access &=
			    ~(DTRACE_ACCESS_PROC | DTRACE_ACCESS_ARGS);
		}
	}
#endif

	return (1);
}

/*
 * Note:  not called from probe context.  This function is called
 * asynchronously (and at a regular interval) from outside of probe context to
 * clean the dirty dynamic variable lists on all CPUs.  Dynamic variable
 * cleaning is explained in detail in <sys/dtrace_impl.h>.
 */
void
dtrace_dynvar_clean(dtrace_dstate_t *dstate)
{
	dtrace_dynvar_t *dirty;
	dtrace_dstate_percpu_t *dcpu;
	dtrace_dynvar_t **rinsep;
	int i, j, work = 0;

	for (i = 0; i < NCPU; i++) {
		dcpu = &dstate->dtds_percpu[i];
		rinsep = &dcpu->dtdsc_rinsing;

		/*
		 * If the dirty list is NULL, there is no dirty work to do.
		 */
		if (dcpu->dtdsc_dirty == NULL)
			continue;

		if (dcpu->dtdsc_rinsing != NULL) {
			/*
			 * If the rinsing list is non-NULL, then it is because
			 * this CPU was selected to accept another CPU's
			 * dirty list -- and since that time, dirty buffers
			 * have accumulated.  This is a highly unlikely
			 * condition, but we choose to ignore the dirty
			 * buffers -- they'll be picked up a future cleanse.
			 */
			continue;
		}

		if (dcpu->dtdsc_clean != NULL) {
			/*
			 * If the clean list is non-NULL, then we're in a
			 * situation where a CPU has done deallocations (we
			 * have a non-NULL dirty list) but no allocations (we
			 * also have a non-NULL clean list).  We can't simply
			 * move the dirty list into the clean list on this
			 * CPU, yet we also don't want to allow this condition
			 * to persist, lest a short clean list prevent a
			 * massive dirty list from being cleaned (which in
			 * turn could lead to otherwise avoidable dynamic
			 * drops).  To deal with this, we look for some CPU
			 * with a NULL clean list, NULL dirty list, and NULL
			 * rinsing list -- and then we borrow this CPU to
			 * rinse our dirty list.
			 */
			for (j = 0; j < NCPU; j++) {
				dtrace_dstate_percpu_t *rinser;

				rinser = &dstate->dtds_percpu[j];

				if (rinser->dtdsc_rinsing != NULL)
					continue;

				if (rinser->dtdsc_dirty != NULL)
					continue;

				if (rinser->dtdsc_clean != NULL)
					continue;

				rinsep = &rinser->dtdsc_rinsing;
				break;
			}

			if (j == NCPU) {
				/*
				 * We were unable to find another CPU that
				 * could accept this dirty list -- we are
				 * therefore unable to clean it now.
				 */
				dtrace_dynvar_failclean++;
				continue;
			}
		}

		work = 1;

		/*
		 * Atomically move the dirty list aside.
		 */
		do {
			dirty = dcpu->dtdsc_dirty;

			/*
			 * Before we zap the dirty list, set the rinsing list.
			 * (This allows for a potential assertion in
			 * dtrace_dynvar():  if a free dynamic variable appears
			 * on a hash chain, either the dirty list or the
			 * rinsing list for some CPU must be non-NULL.)
			 */
			*rinsep = dirty;
			dtrace_membar_producer();
		} while (dtrace_casptr(&dcpu->dtdsc_dirty,
		    dirty, NULL) != dirty);
	}

	if (!work) {
		/*
		 * We have no work to do; we can simply return.
		 */
		return;
	}

#if 0
	dtrace_sync();
#endif

	for (i = 0; i < NCPU; i++) {
		dcpu = &dstate->dtds_percpu[i];

		if (dcpu->dtdsc_rinsing == NULL)
			continue;

		/*
		 * We are now guaranteed that no hash chain contains a pointer
		 * into this dirty list; we can make it clean.
		 */
		ASSERT(dcpu->dtdsc_clean == NULL);
		dcpu->dtdsc_clean = dcpu->dtdsc_rinsing;
		dcpu->dtdsc_rinsing = NULL;
	}

	/*
	 * Before we actually set the state to be DTRACE_DSTATE_CLEAN, make
	 * sure that all CPUs have seen all of the dtdsc_clean pointers.
	 * This prevents a race whereby a CPU incorrectly decides that
	 * the state should be something other than DTRACE_DSTATE_CLEAN
	 * after dtrace_dynvar_clean() has completed.
	 */
#if 0
	dtrace_sync();
#endif

	dstate->dtds_state = DTRACE_DSTATE_CLEAN;
}

/*
 * Depending on the value of the op parameter, this function looks-up,
 * allocates or deallocates an arbitrarily-keyed dynamic variable.  If an
 * allocation is requested, this function will return a pointer to a
 * dtrace_dynvar_t corresponding to the allocated variable -- or NULL if no
 * variable can be allocated.  If NULL is returned, the appropriate counter
 * will be incremented.
 */
dtrace_dynvar_t *
dtrace_dynvar(dtrace_dstate_t *dstate, uint_t nkeys,
    dtrace_key_t *key, size_t dsize, dtrace_dynvar_op_t op,
    dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
	uint64_t hashval = DTRACE_DYNHASH_VALID;
	dtrace_dynhash_t *hash = dstate->dtds_hash;
	dtrace_dynvar_t *free, *new_free, *next, *dvar, *start, *prev = NULL;
	processorid_t me = 1, cpu = me;
	dtrace_dstate_percpu_t *dcpu = &dstate->dtds_percpu[me];
	size_t bucket, ksize;
	size_t chunksize = dstate->dtds_chunksize;
	uintptr_t kdata, lock, nstate;
	uint_t i;

	ASSERT(nkeys != 0);

	/*
	 * Hash the key.  As with aggregations, we use Jenkins' "One-at-a-time"
	 * algorithm.  For the by-value portions, we perform the algorithm in
	 * 16-bit chunks (as opposed to 8-bit chunks).  This speeds things up a
	 * bit, and seems to have only a minute effect on distribution.  For
	 * the by-reference data, we perform "One-at-a-time" iterating (safely)
	 * over each referenced byte.  It's painful to do this, but it's much
	 * better than pathological hash distribution.  The efficacy of the
	 * hashing algorithm (and a comparison with other algorithms) may be
	 * found by running the ::dtrace_dynstat MDB dcmd.
	 */
	for (i = 0; i < nkeys; i++) {
		if (key[i].dttk_size == 0) {
			uint64_t val = key[i].dttk_value;

			hashval += (val >> 48) & 0xffff;
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);

			hashval += (val >> 32) & 0xffff;
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);

			hashval += (val >> 16) & 0xffff;
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);

			hashval += val & 0xffff;
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);
		} else {
			/*
			 * This is incredibly painful, but it beats the hell
			 * out of the alternative.
			 */
			uint64_t j, size = key[i].dttk_size;
			uintptr_t base = (uintptr_t)key[i].dttk_value;

			if (!dtrace_canload(base, size, mstate, vstate))
				break;

			for (j = 0; j < size; j++) {
				hashval += dtrace_load8(base + j);
				hashval += (hashval << 10);
				hashval ^= (hashval >> 6);
			}
		}
	}

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_FAULT))
		return (NULL);

	hashval += (hashval << 3);
	hashval ^= (hashval >> 11);
	hashval += (hashval << 15);

	/*
	 * There is a remote chance (ideally, 1 in 2^31) that our hashval
	 * comes out to be one of our two sentinel hash values.  If this
	 * actually happens, we set the hashval to be a value known to be a
	 * non-sentinel value.
	 */
	if (hashval == DTRACE_DYNHASH_FREE || hashval == DTRACE_DYNHASH_SINK)
		hashval = DTRACE_DYNHASH_VALID;

	/*
	 * Yes, it's painful to do a divide here.  If the cycle count becomes
	 * important here, tricks can be pulled to reduce it.  (However, it's
	 * critical that hash collisions be kept to an absolute minimum;
	 * they're much more painful than a divide.)  It's better to have a
	 * solution that generates few collisions and still keeps things
	 * relatively simple.
	 */
	bucket = hashval % dstate->dtds_hashsize;

	if (op == DTRACE_DYNVAR_DEALLOC) {
		volatile uintptr_t *lockp = &hash[bucket].dtdh_lock;

		for (;;) {
			while ((lock = *lockp) & 1)
				continue;

			if (dtrace_casptr((volatile void *)lockp,
			    (volatile void *)lock, (volatile void *)(lock + 1)) == (void *)lock)
				break;
		}

		dtrace_membar_producer();
	}

top:
	prev = NULL;
	lock = hash[bucket].dtdh_lock;

	dtrace_membar_consumer();

	start = hash[bucket].dtdh_chain;
	ASSERT(start != NULL && (start->dtdv_hashval == DTRACE_DYNHASH_SINK ||
	    start->dtdv_hashval != DTRACE_DYNHASH_FREE ||
	    op != DTRACE_DYNVAR_DEALLOC));

	for (dvar = start; dvar != NULL; dvar = dvar->dtdv_next) {
		dtrace_tuple_t *dtuple = &dvar->dtdv_tuple;
		dtrace_key_t *dkey = &dtuple->dtt_key[0];

		if (dvar->dtdv_hashval != hashval) {
			if (dvar->dtdv_hashval == DTRACE_DYNHASH_SINK) {
				/*
				 * We've reached the sink, and therefore the
				 * end of the hash chain; we can kick out of
				 * the loop knowing that we have seen a valid
				 * snapshot of state.
				 */
				ASSERT(dvar->dtdv_next == NULL);
				ASSERT(dvar == &dtrace_dynhash_sink);
				break;
			}

			if (dvar->dtdv_hashval == DTRACE_DYNHASH_FREE) {
				/*
				 * We've gone off the rails:  somewhere along
				 * the line, one of the members of this hash
				 * chain was deleted.  Note that we could also
				 * detect this by simply letting this loop run
				 * to completion, as we would eventually hit
				 * the end of the dirty list.  However, we
				 * want to avoid running the length of the
				 * dirty list unnecessarily (it might be quite
				 * long), so we catch this as early as
				 * possible by detecting the hash marker.  In
				 * this case, we simply set dvar to NULL and
				 * break; the conditional after the loop will
				 * send us back to top.
				 */
				dvar = NULL;
				break;
			}

			goto next;
		}

		if (dtuple->dtt_nkeys != nkeys)
			goto next;

		for (i = 0; i < nkeys; i++, dkey++) {
			if (dkey->dttk_size != key[i].dttk_size)
				goto next; /* size or type mismatch */

			if (dkey->dttk_size != 0) {
				if (dtrace_bcmp(
				    (void *)(uintptr_t)key[i].dttk_value,
				    (void *)(uintptr_t)dkey->dttk_value,
				    dkey->dttk_size))
					goto next;
			} else {
				if (dkey->dttk_value != key[i].dttk_value)
					goto next;
			}
		}

		if (op != DTRACE_DYNVAR_DEALLOC)
			return (dvar);

		ASSERT(dvar->dtdv_next == NULL ||
		    dvar->dtdv_next->dtdv_hashval != DTRACE_DYNHASH_FREE);

		if (prev != NULL) {
			ASSERT(hash[bucket].dtdh_chain != dvar);
			ASSERT(start != dvar);
			ASSERT(prev->dtdv_next == dvar);
			prev->dtdv_next = dvar->dtdv_next;
		} else {
			if (dtrace_casptr(&hash[bucket].dtdh_chain,
			    start, dvar->dtdv_next) != start) {
				/*
				 * We have failed to atomically swing the
				 * hash table head pointer, presumably because
				 * of a conflicting allocation on another CPU.
				 * We need to reread the hash chain and try
				 * again.
				 */
				goto top;
			}
		}

		dtrace_membar_producer();

		/*
		 * Now set the hash value to indicate that it's free.
		 */
		ASSERT(hash[bucket].dtdh_chain != dvar);
		dvar->dtdv_hashval = DTRACE_DYNHASH_FREE;

		dtrace_membar_producer();

		/*
		 * Set the next pointer to point at the dirty list, and
		 * atomically swing the dirty pointer to the newly freed dvar.
		 */
		do {
			next = dcpu->dtdsc_dirty;
			dvar->dtdv_next = next;
		} while (dtrace_casptr(&dcpu->dtdsc_dirty, next, dvar) != next);

		/*
		 * Finally, unlock this hash bucket.
		 */
		ASSERT(hash[bucket].dtdh_lock == lock);
		ASSERT(lock & 1);
		hash[bucket].dtdh_lock++;

		return (NULL);
next:
		prev = dvar;
		continue;
	}

	if (dvar == NULL) {
		/*
		 * If dvar is NULL, it is because we went off the rails:
		 * one of the elements that we traversed in the hash chain
		 * was deleted while we were traversing it.  In this case,
		 * we assert that we aren't doing a dealloc (deallocs lock
		 * the hash bucket to prevent themselves from racing with
		 * one another), and retry the hash chain traversal.
		 */
		ASSERT(op != DTRACE_DYNVAR_DEALLOC);
		goto top;
	}

	if (op != DTRACE_DYNVAR_ALLOC) {
		/*
		 * If we are not to allocate a new variable, we want to
		 * return NULL now.  Before we return, check that the value
		 * of the lock word hasn't changed.  If it has, we may have
		 * seen an inconsistent snapshot.
		 */
		if (op == DTRACE_DYNVAR_NOALLOC) {
			if (hash[bucket].dtdh_lock != lock)
				goto top;
		} else {
			ASSERT(op == DTRACE_DYNVAR_DEALLOC);
			ASSERT(hash[bucket].dtdh_lock == lock);
			ASSERT(lock & 1);
			hash[bucket].dtdh_lock++;
		}

		return (NULL);
	}

	/*
	 * We need to allocate a new dynamic variable.  The size we need is the
	 * size of dtrace_dynvar plus the size of nkeys dtrace_key_t's plus the
	 * size of any auxiliary key data (rounded up to 8-byte alignment) plus
	 * the size of any referred-to data (dsize).  We then round the final
	 * size up to the chunksize for allocation.
	 */
	for (ksize = 0, i = 0; i < nkeys; i++)
		ksize += P2ROUNDUP(key[i].dttk_size, sizeof (uint64_t));

	/*
	 * This should be pretty much impossible, but could happen if, say,
	 * strange DIF specified the tuple.  Ideally, this should be an
	 * assertion and not an error condition -- but that requires that the
	 * chunksize calculation in dtrace_difo_chunksize() be absolutely
	 * bullet-proof.  (That is, it must not be able to be fooled by
	 * malicious DIF.)  Given the lack of backwards branches in DIF,
	 * solving this would presumably not amount to solving the Halting
	 * Problem -- but it still seems awfully hard.
	 */
	if (sizeof (dtrace_dynvar_t) + sizeof (dtrace_key_t) * (nkeys - 1) +
	    ksize + dsize > chunksize) {
		dcpu->dtdsc_drops++;
		return (NULL);
	}

	nstate = DTRACE_DSTATE_EMPTY;

	do {
retry:
		free = dcpu->dtdsc_free;

		if (free == NULL) {
			dtrace_dynvar_t *clean = dcpu->dtdsc_clean;
			void *rval;

			if (clean == NULL) {
				/*
				 * We're out of dynamic variable space on
				 * this CPU.  Unless we have tried all CPUs,
				 * we'll try to allocate from a different
				 * CPU.
				 */
				switch (dstate->dtds_state) {
				case DTRACE_DSTATE_CLEAN: {
					void *sp = &dstate->dtds_state;

					if (++cpu >= NCPU)
						cpu = 0;

					if (dcpu->dtdsc_dirty != NULL &&
					    nstate == DTRACE_DSTATE_EMPTY)
						nstate = DTRACE_DSTATE_DIRTY;

					if (dcpu->dtdsc_rinsing != NULL)
						nstate = DTRACE_DSTATE_RINSING;

					dcpu = &dstate->dtds_percpu[cpu];

					if (cpu != me)
						goto retry;

					(void) dtrace_cas32(sp,
					    DTRACE_DSTATE_CLEAN, nstate);

					/*
					 * To increment the correct bean
					 * counter, take another lap.
					 */
					goto retry;
				}

				case DTRACE_DSTATE_DIRTY:
					dcpu->dtdsc_dirty_drops++;
					break;

				case DTRACE_DSTATE_RINSING:
					dcpu->dtdsc_rinsing_drops++;
					break;

				case DTRACE_DSTATE_EMPTY:
					dcpu->dtdsc_drops++;
					break;
				}

				DTRACE_CPUFLAG_SET(CPU_DTRACE_DROP);
				return (NULL);
			}

			/*
			 * The clean list appears to be non-empty.  We want to
			 * move the clean list to the free list; we start by
			 * moving the clean pointer aside.
			 */
			if (dtrace_casptr(&dcpu->dtdsc_clean,
			    clean, NULL) != clean) {
				/*
				 * We are in one of two situations:
				 *
				 *  (a)	The clean list was switched to the
				 *	free list by another CPU.
				 *
				 *  (b)	The clean list was added to by the
				 *	cleansing cyclic.
				 *
				 * In either of these situations, we can
				 * just reattempt the free list allocation.
				 */
				goto retry;
			}

			ASSERT(clean->dtdv_hashval == DTRACE_DYNHASH_FREE);

			/*
			 * Now we'll move the clean list to our free list.
			 * It's impossible for this to fail:  the only way
			 * the free list can be updated is through this
			 * code path, and only one CPU can own the clean list.
			 * Thus, it would only be possible for this to fail if
			 * this code were racing with dtrace_dynvar_clean().
			 * (That is, if dtrace_dynvar_clean() updated the clean
			 * list, and we ended up racing to update the free
			 * list.)  This race is prevented by the dtrace_sync()
			 * in dtrace_dynvar_clean() -- which flushes the
			 * owners of the clean lists out before resetting
			 * the clean lists.
			 */
			dcpu = &dstate->dtds_percpu[me];
			rval = dtrace_casptr(&dcpu->dtdsc_free, NULL, clean);
			ASSERT(rval == NULL);
			goto retry;
		}

		dvar = free;
		new_free = dvar->dtdv_next;
	} while (dtrace_casptr(&dcpu->dtdsc_free, free, new_free) != free);

	/*
	 * We have now allocated a new chunk.  We copy the tuple keys into the
	 * tuple array and copy any referenced key data into the data space
	 * following the tuple array.  As we do this, we relocate dttk_value
	 * in the final tuple to point to the key data address in the chunk.
	 */
	kdata = (uintptr_t)&dvar->dtdv_tuple.dtt_key[nkeys];
	dvar->dtdv_data = (void *)(kdata + ksize);
	dvar->dtdv_tuple.dtt_nkeys = nkeys;

	for (i = 0; i < nkeys; i++) {
		dtrace_key_t *dkey = &dvar->dtdv_tuple.dtt_key[i];
		size_t kesize = key[i].dttk_size;

		if (kesize != 0) {
			dtrace_bcopy(
			    (const void *)(uintptr_t)key[i].dttk_value,
			    (void *)kdata, kesize);
			dkey->dttk_value = kdata;
			kdata += P2ROUNDUP(kesize, sizeof (uint64_t));
		} else {
			dkey->dttk_value = key[i].dttk_value;
		}

		dkey->dttk_size = kesize;
	}

	ASSERT(dvar->dtdv_hashval == DTRACE_DYNHASH_FREE);
	dvar->dtdv_hashval = hashval;
	dvar->dtdv_next = start;

	if (dtrace_casptr(&hash[bucket].dtdh_chain, start, dvar) == start)
		return (dvar);

	/*
	 * The cas has failed.  Either another CPU is adding an element to
	 * this hash chain, or another CPU is deleting an element from this
	 * hash chain.  The simplest way to deal with both of these cases
	 * (though not necessarily the most efficient) is to free our
	 * allocated block and re-attempt it all.  Note that the free is
	 * to the dirty list and _not_ to the free list.  This is to prevent
	 * races with allocators, above.
	 */
	dvar->dtdv_hashval = DTRACE_DYNHASH_FREE;

	dtrace_membar_producer();

	do {
		free = dcpu->dtdsc_dirty;
		dvar->dtdv_next = free;
	} while (dtrace_casptr(&dcpu->dtdsc_dirty, free, dvar) != free);

	goto top;
}

static void
dtrace_aggregate_min(uint64_t *oval, uint64_t nval, uint64_t arg)
{
	if ((int64_t)nval < (int64_t)*oval)
		*oval = nval;
}

/*ARGSUSED*/
static void
dtrace_aggregate_max(uint64_t *oval, uint64_t nval, uint64_t arg)
{
	if ((int64_t)nval > (int64_t)*oval)
		*oval = nval;
}

static void
dtrace_aggregate_quantize(uint64_t *quanta, uint64_t nval, uint64_t incr)
{
	int i, zero = DTRACE_QUANTIZE_ZEROBUCKET;
	int64_t val = (int64_t)nval;

	if (val < 0) {
		for (i = 0; i < zero; i++) {
			if (val <= DTRACE_QUANTIZE_BUCKETVAL(i)) {
				quanta[i] += incr;
				return;
			}
		}
	} else {
		for (i = zero + 1; i < DTRACE_QUANTIZE_NBUCKETS; i++) {
			if (val < DTRACE_QUANTIZE_BUCKETVAL(i)) {
				quanta[i - 1] += incr;
				return;
			}
		}

		quanta[DTRACE_QUANTIZE_NBUCKETS - 1] += incr;
		return;
	}

	assert(0);
}

static void
dtrace_aggregate_lquantize(uint64_t *lquanta, uint64_t nval, uint64_t incr)
{
	uint64_t arg = *lquanta++;
	int32_t base = DTRACE_LQUANTIZE_BASE(arg);
	uint16_t step = DTRACE_LQUANTIZE_STEP(arg);
	uint16_t levels = DTRACE_LQUANTIZE_LEVELS(arg);
	int32_t val = (int32_t)nval, level;

	assert(step != 0);
	assert(levels != 0);

	if (val < base) {
		/*
		 * This is an underflow.
		 */
		lquanta[0] += incr;
		return;
	}

	level = (val - base) / step;

	if (level < levels) {
		lquanta[level + 1] += incr;
		return;
	}

	/*
	 * This is an overflow.
	 */
	lquanta[levels + 1] += incr;
}

static int
dtrace_aggregate_llquantize_bucket(uint16_t factor, uint16_t low,
    uint16_t high, uint16_t nsteps, int64_t value)
{
	int64_t this = 1, last, next;
	int base = 1, order;

	assert(factor <= nsteps);
	assert(nsteps % factor == 0);

	for (order = 0; order < low; order++)
		this *= factor;

	/*
	 * If our value is less than our factor taken to the power of the
	 * low order of magnitude, it goes into the zeroth bucket.
	 */
	if (value < (last = this))
		return (0);

	for (this *= factor; order <= high; order++) {
		int nbuckets = this > nsteps ? nsteps : this;

		if ((next = this * factor) < this) {
			/*
			 * We should not generally get log/linear quantizations
			 * with a high magnitude that allows 64-bits to
			 * overflow, but we nonetheless protect against this
			 * by explicitly checking for overflow, and clamping
			 * our value accordingly.
			 */
			value = this - 1;
		}

		if (value < this) {
			/*
			 * If our value lies within this order of magnitude,
			 * determine its position by taking the offset within
			 * the order of magnitude, dividing by the bucket
			 * width, and adding to our (accumulated) base.
			 */
			return (base + (value - last) / (this / nbuckets));
		}

		base += nbuckets - (nbuckets / factor);
		last = this;
		this = next;
	}

	/*
	 * Our value is greater than or equal to our factor taken to the
	 * power of one plus the high magnitude -- return the top bucket.
	 */
	return (base);
}

static void
dtrace_aggregate_llquantize(uint64_t *llquanta, uint64_t nval, uint64_t incr)
{
	uint64_t arg = *llquanta++;
	uint16_t factor = DTRACE_LLQUANTIZE_FACTOR(arg);
	uint16_t low = DTRACE_LLQUANTIZE_LOW(arg);
	uint16_t high = DTRACE_LLQUANTIZE_HIGH(arg);
	uint16_t nsteps = DTRACE_LLQUANTIZE_NSTEP(arg);

	llquanta[dtrace_aggregate_llquantize_bucket(factor,
	    low, high, nsteps, nval)] += incr;
}

/*ARGSUSED*/
static void
dtrace_aggregate_avg(uint64_t *data, uint64_t nval, uint64_t arg)
{
	data[0]++;
	data[1] += nval;
}

/*ARGSUSED*/
static void
dtrace_aggregate_stddev(uint64_t *data, uint64_t nval, uint64_t arg)
{
	int64_t snval = (int64_t)nval;
	uint64_t tmp[2];

	data[0]++;
	data[1] += nval;

	/*
	 * What we want to say here is:
	 *
	 * data[2] += nval * nval;
	 *
	 * But given that nval is 64-bit, we could easily overflow, so
	 * we do this as 128-bit arithmetic.
	 */
	if (snval < 0)
		snval = -snval;

	dtrace_multiply_128((uint64_t)snval, (uint64_t)snval, tmp);
	dtrace_add_128(data + 2, tmp, data + 2);
}

/*ARGSUSED*/
static void
dtrace_aggregate_count(uint64_t *oval, uint64_t nval, uint64_t arg)
{
	*oval = *oval + 1;
}

/*ARGSUSED*/
static void
dtrace_aggregate_sum(uint64_t *oval, uint64_t nval, uint64_t arg)
{
	*oval += nval;
}

/*
 * Aggregate given the tuple in the principal data buffer, and the aggregating
 * action denoted by the specified dtrace_aggregation_t.  The aggregation
 * buffer is specified as the buf parameter.  This routine does not return
 * failure; if there is no space in the aggregation buffer, the data will be
 * dropped, and a corresponding counter incremented.
 */
static void
dtrace_aggregate(dtrace_aggregation_t *agg, dtrace_buffer_t *dbuf,
    intptr_t offset, dtrace_buffer_t *buf, uint64_t expr, uint64_t arg)
{
#if 0
	dtrace_recdesc_t *rec = &agg->dtag_action.dta_rec;
	uint32_t i, ndx, size, fsize;
	uint32_t align = sizeof (uint64_t) - 1;
	dtrace_aggbuffer_t *agb;
	dtrace_aggkey_t *key;
	uint32_t hashval = 0, limit, isstr;
	caddr_t tomax, data, kdata;
	dtrace_actkind_t action;
	dtrace_action_t *act;
	uintptr_t offs;

	if (buf == NULL)
		return;

	if (!agg->dtag_hasarg) {
		/*
		 * Currently, only quantize() and lquantize() take additional
		 * arguments, and they have the same semantics:  an increment
		 * value that defaults to 1 when not present.  If additional
		 * aggregating actions take arguments, the setting of the
		 * default argument value will presumably have to become more
		 * sophisticated...
		 */
		arg = 1;
	}

	action = agg->dtag_action.dta_kind - DTRACEACT_AGGREGATION;
	size = rec->dtrd_offset - agg->dtag_base;
	fsize = size + rec->dtrd_size;

	assert(dbuf->dtb_tomax != NULL);
	data = dbuf->dtb_tomax + offset + agg->dtag_base;

	if ((tomax = buf->dtb_tomax) == NULL) {
		dtrace_buffer_drop(buf);
		return;
	}

	/*
	 * The metastructure is always at the bottom of the buffer.
	 */
	agb = (dtrace_aggbuffer_t *)(tomax + buf->dtb_size -
	    sizeof (dtrace_aggbuffer_t));

	if (buf->dtb_offset == 0) {
		/*
		 * We just kludge up approximately 1/8th of the size to be
		 * buckets.  If this guess ends up being routinely
		 * off-the-mark, we may need to dynamically readjust this
		 * based on past performance.
		 */
		uintptr_t hashsize = (buf->dtb_size >> 3) / sizeof (uintptr_t);

		if ((uintptr_t)agb - hashsize * sizeof (dtrace_aggkey_t *) <
		    (uintptr_t)tomax || hashsize == 0) {
			/*
			 * We've been given a ludicrously small buffer;
			 * increment our drop count and leave.
			 */
			dtrace_buffer_drop(buf);
			return;
		}

		/*
		 * And now, a pathetic attempt to try to get a an odd (or
		 * perchance, a prime) hash size for better hash distribution.
		 */
		if (hashsize > (DTRACE_AGGHASHSIZE_SLEW << 3))
			hashsize -= DTRACE_AGGHASHSIZE_SLEW;

		agb->dtagb_hashsize = hashsize;
		agb->dtagb_hash = (dtrace_aggkey_t **)((uintptr_t)agb -
		    agb->dtagb_hashsize * sizeof (dtrace_aggkey_t *));
		agb->dtagb_free = (uintptr_t)agb->dtagb_hash;

		for (i = 0; i < agb->dtagb_hashsize; i++)
			agb->dtagb_hash[i] = NULL;
	}

	assert(agg->dtag_first != NULL);
	assert(agg->dtag_first->dta_intuple);

	/*
	 * Calculate the hash value based on the key.  Note that we _don't_
	 * include the aggid in the hashing (but we will store it as part of
	 * the key).  The hashing algorithm is Bob Jenkins' "One-at-a-time"
	 * algorithm: a simple, quick algorithm that has no known funnels, and
	 * gets good distribution in practice.  The efficacy of the hashing
	 * algorithm (and a comparison with other algorithms) may be found by
	 * running the ::dtrace_aggstat MDB dcmd.
	 */
	for (act = agg->dtag_first; act->dta_intuple; act = act->dta_next) {
		i = act->dta_rec.dtrd_offset - agg->dtag_base;
		limit = i + act->dta_rec.dtrd_size;
		assert(limit <= size);
		isstr = DTRACEACT_ISSTRING(act);

		for (; i < limit; i++) {
			hashval += data[i];
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);

			if (isstr && data[i] == '\0')
				break;
		}
	}

	hashval += (hashval << 3);
	hashval ^= (hashval >> 11);
	hashval += (hashval << 15);

	/*
	 * Yes, the divide here is expensive -- but it's generally the least
	 * of the performance issues given the amount of data that we iterate
	 * over to compute hash values, compare data, etc.
	 */
	ndx = hashval % agb->dtagb_hashsize;

	for (key = agb->dtagb_hash[ndx]; key != NULL; key = key->dtak_next) {
		assert((caddr_t)key >= tomax);
		assert((caddr_t)key < tomax + buf->dtb_size);

		if (hashval != key->dtak_hashval || key->dtak_size != size)
			continue;

		kdata = key->dtak_data;
		assert(kdata >= tomax && kdata < tomax + buf->dtb_size);

		for (act = agg->dtag_first; act->dta_intuple;
		    act = act->dta_next) {
			i = act->dta_rec.dtrd_offset - agg->dtag_base;
			limit = i + act->dta_rec.dtrd_size;
			assert(limit <= size);
			isstr = DTRACEACT_ISSTRING(act);

			for (; i < limit; i++) {
				if (kdata[i] != data[i])
					goto next;

				if (isstr && data[i] == '\0')
					break;
			}
		}

		if (action != key->dtak_action) {
			/*
			 * We are aggregating on the same value in the same
			 * aggregation with two different aggregating actions.
			 * (This should have been picked up in the compiler,
			 * so we may be dealing with errant or devious DIF.)
			 * This is an error condition; we indicate as much,
			 * and return.
			 */
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			return;
		}

		/*
		 * This is a hit:  we need to apply the aggregator to
		 * the value at this key.
		 */
		agg->dtag_aggregate((uint64_t *)(kdata + size), expr, arg);
		return;
next:
		continue;
	}

	/*
	 * We didn't find it.  We need to allocate some zero-filled space,
	 * link it into the hash table appropriately, and apply the aggregator
	 * to the (zero-filled) value.
	 */
	offs = buf->dtb_offset;
	while (offs & (align - 1))
		offs += sizeof (uint32_t);

	/*
	 * If we don't have enough room to both allocate a new key _and_
	 * its associated data, increment the drop count and return.
	 */
	if ((uintptr_t)tomax + offs + fsize >
	    agb->dtagb_free - sizeof (dtrace_aggkey_t)) {
		dtrace_buffer_drop(buf);
		return;
	}

	/*CONSTCOND*/
	assert(!(sizeof (dtrace_aggkey_t) & (sizeof (uintptr_t) - 1)));
	key = (dtrace_aggkey_t *)(agb->dtagb_free - sizeof (dtrace_aggkey_t));
	agb->dtagb_free -= sizeof (dtrace_aggkey_t);

	key->dtak_data = kdata = tomax + offs;
	buf->dtb_offset = offs + fsize;

	/*
	 * Now copy the data across.
	 */
	*((dtrace_aggid_t *)kdata) = agg->dtag_id;

	for (i = sizeof (dtrace_aggid_t); i < size; i++)
		kdata[i] = data[i];

	/*
	 * Because strings are not zeroed out by default, we need to iterate
	 * looking for actions that store strings, and we need to explicitly
	 * pad these strings out with zeroes.
	 */
	for (act = agg->dtag_first; act->dta_intuple; act = act->dta_next) {
		int nul;

		if (!DTRACEACT_ISSTRING(act))
			continue;

		i = act->dta_rec.dtrd_offset - agg->dtag_base;
		limit = i + act->dta_rec.dtrd_size;
		assert(limit <= size);

		for (nul = 0; i < limit; i++) {
			if (nul) {
				kdata[i] = '\0';
				continue;
			}

			if (data[i] != '\0')
				continue;

			nul = 1;
		}
	}

	for (i = size; i < fsize; i++)
		kdata[i] = 0;

	key->dtak_hashval = hashval;
	key->dtak_size = size;
	key->dtak_action = action;
	key->dtak_next = agb->dtagb_hash[ndx];
	agb->dtagb_hash[ndx] = key;

	/*
	 * Finally, apply the aggregator.
	 */
	*((uint64_t *)(key->dtak_data + size)) = agg->dtag_initial;
	agg->dtag_aggregate((uint64_t *)(key->dtak_data + size), expr, arg);
#endif
}

/*
 * Given consumer state, this routine finds a speculation in the INACTIVE
 * state and transitions it into the ACTIVE state.  If there is no speculation
 * in the INACTIVE state, 0 is returned.  In this case, no error counter is
 * incremented -- it is up to the caller to take appropriate action.
 */
static int
dtrace_speculation(dtrace_state_t *state)
{
	int i = 0;
	dtrace_speculation_state_t current;
	uint32_t *stat = &state->dts_speculations_unavail, count;

	while (i < state->dts_nspeculations) {
		dtrace_speculation_t *spec = &state->dts_speculations[i];

		current = spec->dtsp_state;

		if (current != DTRACESPEC_INACTIVE) {
			if (current == DTRACESPEC_COMMITTINGMANY ||
			    current == DTRACESPEC_COMMITTING ||
			    current == DTRACESPEC_DISCARDING)
				stat = &state->dts_speculations_busy;
			i++;
			continue;
		}

		if (dtrace_cas32((uint32_t *)&spec->dtsp_state,
		    current, DTRACESPEC_ACTIVE) == current)
			return (i + 1);
	}

	/*
	 * We couldn't find a speculation.  If we found as much as a single
	 * busy speculation buffer, we'll attribute this failure as "busy"
	 * instead of "unavail".
	 */
	do {
		count = *stat;
	} while (dtrace_cas32(stat, count, count + 1) != count);

	return (0);
}

/*
 * This routine commits an active speculation.  If the specified speculation
 * is not in a valid state to perform a commit(), this routine will silently do
 * nothing.  The state of the specified speculation is transitioned according
 * to the state transition diagram outlined in <sys/dtrace_impl.h>
 */
static void
dtrace_speculation_commit(dtrace_state_t *state, processorid_t cpu,
    dtrace_specid_t which)
{
	dtrace_speculation_t *spec;
	dtrace_buffer_t *src, *dest;
	uintptr_t daddr, saddr, dlimit, slimit;
	dtrace_speculation_state_t current, new = 0;
	intptr_t offs;
	uint64_t timestamp;

	if (which == 0)
		return;

	if (which > state->dts_nspeculations) {
		cpuc_dtrace_flags |= CPU_DTRACE_ILLOP;
		return;
	}

	spec = &state->dts_speculations[which - 1];
	src = &spec->dtsp_buffer[cpu];
	dest = &state->dts_buffer[cpu];

	do {
		current = spec->dtsp_state;

		if (current == DTRACESPEC_COMMITTINGMANY)
			break;

		switch (current) {
		case DTRACESPEC_INACTIVE:
		case DTRACESPEC_DISCARDING:
			return;

		case DTRACESPEC_COMMITTING:
			/*
			 * This is only possible if we are (a) commit()'ing
			 * without having done a prior speculate() on this CPU
			 * and (b) racing with another commit() on a different
			 * CPU.  There's nothing to do -- we just assert that
			 * our offset is 0.
			 */
			ASSERT(src->dtb_offset == 0);
			return;

		case DTRACESPEC_ACTIVE:
			new = DTRACESPEC_COMMITTING;
			break;

		case DTRACESPEC_ACTIVEONE:
			/*
			 * This speculation is active on one CPU.  If our
			 * buffer offset is non-zero, we know that the one CPU
			 * must be us.  Otherwise, we are committing on a
			 * different CPU from the speculate(), and we must
			 * rely on being asynchronously cleaned.
			 */
			if (src->dtb_offset != 0) {
				new = DTRACESPEC_COMMITTING;
				break;
			}
			/*FALLTHROUGH*/

		case DTRACESPEC_ACTIVEMANY:
			new = DTRACESPEC_COMMITTINGMANY;
			break;

		default:
			ASSERT(0);
		}
	} while (dtrace_cas32((uint32_t *)&spec->dtsp_state,
	    current, new) != current);

	/*
	 * We have set the state to indicate that we are committing this
	 * speculation.  Now reserve the necessary space in the destination
	 * buffer.
	 */
	if ((offs = dtrace_buffer_reserve(dest, src->dtb_offset,
	    sizeof (uint64_t), state, NULL)) < 0) {
		dtrace_buffer_drop(dest);
		goto out;
	}

	/*
	 * We have sufficient space to copy the speculative buffer into the
	 * primary buffer.  First, modify the speculative buffer, filling
	 * in the timestamp of all entries with the current time.  The data
	 * must have the commit() time rather than the time it was traced,
	 * so that all entries in the primary buffer are in timestamp order.
	 */
	/*
	 * TODO: We want the timestamp.
	 */
#if 0
	timestamp = dtrace_gethrtime();
#endif
	saddr = (uintptr_t)src->dtb_tomax;
	slimit = saddr + src->dtb_offset;
	while (saddr < slimit) {
		size_t size;
		dtrace_rechdr_t *dtrh = (dtrace_rechdr_t *)saddr;

		if (dtrh->dtrh_epid == DTRACE_EPIDNONE) {
			saddr += sizeof (dtrace_epid_t);
			continue;
		}
		ASSERT3U(dtrh->dtrh_epid, <=, state->dts_necbs);
		size = state->dts_ecbs[dtrh->dtrh_epid - 1]->dte_size;

		ASSERT3U(saddr + size, <=, slimit);
		ASSERT3U(size, >=, sizeof (dtrace_rechdr_t));
		ASSERT3U(DTRACE_RECORD_LOAD_TIMESTAMP(dtrh), ==, UINT64_MAX);

		DTRACE_RECORD_STORE_TIMESTAMP(dtrh, timestamp);

		saddr += size;
	}

	/*
	 * Copy the buffer across.  (Note that this is a
	 * highly subobtimal bcopy(); in the unlikely event that this becomes
	 * a serious performance issue, a high-performance DTrace-specific
	 * bcopy() should obviously be invented.)
	 */
	daddr = (uintptr_t)dest->dtb_tomax + offs;
	dlimit = daddr + src->dtb_offset;
	saddr = (uintptr_t)src->dtb_tomax;

	/*
	 * First, the aligned portion.
	 */
	while (dlimit - daddr >= sizeof (uint64_t)) {
		*((uint64_t *)daddr) = *((uint64_t *)saddr);

		daddr += sizeof (uint64_t);
		saddr += sizeof (uint64_t);
	}

	/*
	 * Now any left-over bit...
	 */
	while (dlimit - daddr)
		*((uint8_t *)daddr++) = *((uint8_t *)saddr++);

	/*
	 * Finally, commit the reserved space in the destination buffer.
	 */
	dest->dtb_offset = offs + src->dtb_offset;

out:
	/*
	 * If we're lucky enough to be the only active CPU on this speculation
	 * buffer, we can just set the state back to DTRACESPEC_INACTIVE.
	 */
	if (current == DTRACESPEC_ACTIVE ||
	    (current == DTRACESPEC_ACTIVEONE && new == DTRACESPEC_COMMITTING)) {
		uint32_t rval = dtrace_cas32((uint32_t *)&spec->dtsp_state,
		    DTRACESPEC_COMMITTING, DTRACESPEC_INACTIVE);

		ASSERT(rval == DTRACESPEC_COMMITTING);
	}

	src->dtb_offset = 0;
	src->dtb_xamot_drops += src->dtb_drops;
	src->dtb_drops = 0;
}

/*
 * This routine discards an active speculation.  If the specified speculation
 * is not in a valid state to perform a discard(), this routine will silently
 * do nothing.  The state of the specified speculation is transitioned
 * according to the state transition diagram outlined in <sys/dtrace_impl.h>
 */
static void
dtrace_speculation_discard(dtrace_state_t *state, processorid_t cpu,
    dtrace_specid_t which)
{
	dtrace_speculation_t *spec;
	dtrace_speculation_state_t current, new = 0;
	dtrace_buffer_t *buf;

	if (which == 0)
		return;

	if (which > state->dts_nspeculations) {
		cpuc_dtrace_flags |= CPU_DTRACE_ILLOP;
		return;
	}

	spec = &state->dts_speculations[which - 1];
	buf = &spec->dtsp_buffer[cpu];

	do {
		current = spec->dtsp_state;

		switch (current) {
		case DTRACESPEC_INACTIVE:
		case DTRACESPEC_COMMITTINGMANY:
		case DTRACESPEC_COMMITTING:
		case DTRACESPEC_DISCARDING:
			return;

		case DTRACESPEC_ACTIVE:
		case DTRACESPEC_ACTIVEMANY:
			new = DTRACESPEC_DISCARDING;
			break;

		case DTRACESPEC_ACTIVEONE:
			if (buf->dtb_offset != 0) {
				new = DTRACESPEC_INACTIVE;
			} else {
				new = DTRACESPEC_DISCARDING;
			}
			break;

		default:
			ASSERT(0);
		}
	} while (dtrace_cas32((uint32_t *)&spec->dtsp_state,
	    current, new) != current);

	buf->dtb_offset = 0;
	buf->dtb_drops = 0;
}

/*
 * Note:  not called from probe context.  This function is called
 * asynchronously from cross call context to clean any speculations that are
 * in the COMMITTINGMANY or DISCARDING states.  These speculations may not be
 * transitioned back to the INACTIVE state until all CPUs have cleaned the
 * speculation.
 */
static void
dtrace_speculation_clean_here(dtrace_state_t *state)
{
	dtrace_icookie_t cookie;
	processorid_t cpu = curcpu;
	dtrace_buffer_t *dest = &state->dts_buffer[cpu];
	dtrace_specid_t i;

	cookie = dtrace_interrupt_disable();

	if (dest->dtb_tomax == NULL) {
		dtrace_interrupt_enable(cookie);
		return;
	}

	for (i = 0; i < state->dts_nspeculations; i++) {
		dtrace_speculation_t *spec = &state->dts_speculations[i];
		dtrace_buffer_t *src = &spec->dtsp_buffer[cpu];

		if (src->dtb_tomax == NULL)
			continue;

		if (spec->dtsp_state == DTRACESPEC_DISCARDING) {
			src->dtb_offset = 0;
			continue;
		}

		if (spec->dtsp_state != DTRACESPEC_COMMITTINGMANY)
			continue;

		if (src->dtb_offset == 0)
			continue;

		dtrace_speculation_commit(state, cpu, i + 1);
	}

	dtrace_interrupt_enable(cookie);
}

/*
 * Note:  not called from probe context.  This function is called
 * asynchronously (and at a regular interval) to clean any speculations that
 * are in the COMMITTINGMANY or DISCARDING states.  If it discovers that there
 * is work to be done, it cross calls all CPUs to perform that work;
 * COMMITMANY and DISCARDING speculations may not be transitioned back to the
 * INACTIVE state until they have been cleaned by all CPUs.
 */
static void
dtrace_speculation_clean(dtrace_state_t *state)
{
	int work = 0, rv;
	dtrace_specid_t i;

	for (i = 0; i < state->dts_nspeculations; i++) {
		dtrace_speculation_t *spec = &state->dts_speculations[i];

		ASSERT(!spec->dtsp_cleaning);

		if (spec->dtsp_state != DTRACESPEC_DISCARDING &&
		    spec->dtsp_state != DTRACESPEC_COMMITTINGMANY)
			continue;

		work++;
		spec->dtsp_cleaning = 1;
	}

	if (!work)
		return;

	/*
	 * We now know that all CPUs have committed or discarded their
	 * speculation buffers, as appropriate.  We can now set the state
	 * to inactive.
	 */
	for (i = 0; i < state->dts_nspeculations; i++) {
		dtrace_speculation_t *spec = &state->dts_speculations[i];
		dtrace_speculation_state_t current, new;

		if (!spec->dtsp_cleaning)
			continue;

		current = spec->dtsp_state;
		ASSERT(current == DTRACESPEC_DISCARDING ||
		    current == DTRACESPEC_COMMITTINGMANY);

		new = DTRACESPEC_INACTIVE;

		rv = dtrace_cas32((uint32_t *)&spec->dtsp_state, current, new);
		ASSERT(rv == current);
		spec->dtsp_cleaning = 0;
	}
}

/*
 * FIXME: Do not speculate for now
 */
#if 0
/*
 * Called as part of a speculate() to get the speculative buffer associated
 * with a given speculation.  Returns NULL if the specified speculation is not
 * in an ACTIVE state.  If the speculation is in the ACTIVEONE state -- and
 * the active CPU is not the specified CPU -- the speculation will be
 * atomically transitioned into the ACTIVEMANY state.
 */
static dtrace_buffer_t *
dtrace_speculation_buffer(dtrace_state_t *state, processorid_t cpuid,
    dtrace_specid_t which)
{
	dtrace_speculation_t *spec;
	dtrace_speculation_state_t current, new = 0;
	dtrace_buffer_t *buf;

	if (which == 0)
		return (NULL);

	if (which > state->dts_nspeculations) {
		cpu_core[cpuid].cpuc_dtrace_flags |= CPU_DTRACE_ILLOP;
		return (NULL);
	}

	spec = &state->dts_speculations[which - 1];
	buf = &spec->dtsp_buffer[cpuid];

	do {
		current = spec->dtsp_state;

		switch (current) {
		case DTRACESPEC_INACTIVE:
		case DTRACESPEC_COMMITTINGMANY:
		case DTRACESPEC_DISCARDING:
			return (NULL);

		case DTRACESPEC_COMMITTING:
			ASSERT(buf->dtb_offset == 0);
			return (NULL);

		case DTRACESPEC_ACTIVEONE:
			/*
			 * This speculation is currently active on one CPU.
			 * Check the offset in the buffer; if it's non-zero,
			 * that CPU must be us (and we leave the state alone).
			 * If it's zero, assume that we're starting on a new
			 * CPU -- and change the state to indicate that the
			 * speculation is active on more than one CPU.
			 */
			if (buf->dtb_offset != 0)
				return (buf);

			new = DTRACESPEC_ACTIVEMANY;
			break;

		case DTRACESPEC_ACTIVEMANY:
			return (buf);

		case DTRACESPEC_ACTIVE:
			new = DTRACESPEC_ACTIVEONE;
			break;

		default:
			ASSERT(0);
		}
	} while (dtrace_cas32((uint32_t *)&spec->dtsp_state,
	    current, new) != current);

	ASSERT(new == DTRACESPEC_ACTIVEONE || new == DTRACESPEC_ACTIVEMANY);
	return (buf);
}
#endif

/*
 * Return a string.  In the event that the user lacks the privilege to access
 * arbitrary kernel memory, we copy the string out to scratch memory so that we
 * don't fail access checking.
 *
 * dtrace_dif_variable() uses this routine as a helper for various
 * builtin values such as 'execname' and 'probefunc.'
 */
uintptr_t
dtrace_dif_varstr(uintptr_t addr, dtrace_state_t *state,
    dtrace_mstate_t *mstate)
{
	uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
	uintptr_t ret;
	size_t strsz;

	/*
	 * The easy case: this probe is allowed to read all of memory, so
	 * we can just return this as a vanilla pointer.
	 */
	if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) != 0)
		return (addr);

	/*
	 * This is the tougher case: we copy the string in question from
	 * kernel memory into scratch memory and return it that way: this
	 * ensures that we won't trip up when access checking tests the
	 * BYREF return value.
	 */
	strsz = dtrace_strlen((char *)addr, size) + 1;

	if (mstate->dtms_scratch_ptr + strsz >
	    mstate->dtms_scratch_base + mstate->dtms_scratch_size) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
		return (0);
	}

	dtrace_strcpy((const void *)addr, (void *)mstate->dtms_scratch_ptr,
	    strsz);
	ret = mstate->dtms_scratch_ptr;
	mstate->dtms_scratch_ptr += strsz;
	return (ret);
}

/*
 * Return a string from a memoy address which is known to have one or
 * more concatenated, individually zero terminated, sub-strings.
 * In the event that the user lacks the privilege to access
 * arbitrary kernel memory, we copy the string out to scratch memory so that we
 * don't fail access checking.
 *
 * dtrace_dif_variable() uses this routine as a helper for various
 * builtin values such as 'execargs'.
 */
static uintptr_t
dtrace_dif_varstrz(uintptr_t addr, size_t strsz, dtrace_state_t *state,
    dtrace_mstate_t *mstate)
{
	char *p;
	size_t i;
	uintptr_t ret;

	if (mstate->dtms_scratch_ptr + strsz >
	    mstate->dtms_scratch_base + mstate->dtms_scratch_size) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
		return (0);
	}

	dtrace_bcopy((const void *)addr, (void *)mstate->dtms_scratch_ptr,
	    strsz);

	/* Replace sub-string termination characters with a space. */
	for (p = (char *) mstate->dtms_scratch_ptr, i = 0; i < strsz - 1;
	    p++, i++)
		if (*p == '\0')
			*p = ' ';

	ret = mstate->dtms_scratch_ptr;
	mstate->dtms_scratch_ptr += strsz;
	return (ret);
}

/*
 * This function implements the DIF emulator's variable lookups.  The emulator
 * passes a reserved variable identifier and optional built-in array index.
 */
static uint64_t
dtrace_dif_variable(dtrace_mstate_t *mstate, dtrace_state_t *state, uint64_t v,
    uint64_t ndx)
{
	/*
	 * If we're accessing one of the uncached arguments, we'll turn this
	 * into a reference in the args array.
	 */
	if (v >= DIF_VAR_ARG0 && v <= DIF_VAR_ARG9) {
		ndx = v - DIF_VAR_ARG0;
		v = DIF_VAR_ARGS;
	}

	switch (v) {
	case DIF_VAR_ARGS:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_ARGS);
		if (ndx >= sizeof (mstate->dtms_arg) /
		    sizeof (mstate->dtms_arg[0])) {
			int aframes = mstate->dtms_probe->dtpr_aframes + 2;
			dtrace_provider_t *pv;
			uint64_t val;

			pv = mstate->dtms_probe->dtpr_provider;
			if (pv->dtpv_pops.dtps_getargval != NULL)
				val = pv->dtpv_pops.dtps_getargval(pv->dtpv_arg,
				    mstate->dtms_probe->dtpr_id,
				    mstate->dtms_probe->dtpr_arg, ndx, aframes);
			else
				val = dtrace_getarg(ndx, aframes);

			/*
			 * This is regrettably required to keep the compiler
			 * from tail-optimizing the call to dtrace_getarg().
			 * The condition always evaluates to true, but the
			 * compiler has no way of figuring that out a priori.
			 * (None of this would be necessary if the compiler
			 * could be relied upon to _always_ tail-optimize
			 * the call to dtrace_getarg() -- but it can't.)
			 */
			if (mstate->dtms_probe != NULL)
				return (val);

			ASSERT(0);
		}

		return (mstate->dtms_arg[ndx]);

#ifdef illumos
	case DIF_VAR_UREGS: {
		klwp_t *lwp;

		if (!dtrace_priv_proc(state))
			return (0);

		if ((lwp = curthread->t_lwp) == NULL) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpuc_dtrace_illval = NULL;
			return (0);
		}

		return (dtrace_getreg(lwp->lwp_regs, ndx));
		return (0);
	}
#else
	/*
	 * FIXME: We actually want to get registers, but we do not have a thread
	 * frame here. Need to deal with it in some other way.
	 */
#if 0
	case DIF_VAR_UREGS: {
		struct trapframe *tframe;

		if (!dtrace_priv_proc(state))
			return (0);

		if ((tframe = curthread->td_frame) == NULL) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[curcpu].cpuc_dtrace_illval = 0;
			return (0);
		}

		return (dtrace_getreg(tframe, ndx));
	}
#endif
#endif

	case DIF_VAR_CURTHREAD:
		if (!dtrace_priv_proc(state))
			return (0);
		return (1);

	/*
	 * TODO: We want timestamps
	 */
#if 0
	case DIF_VAR_TIMESTAMP:
		if (!(mstate->dtms_present & DTRACE_MSTATE_TIMESTAMP)) {
			mstate->dtms_timestamp = dtrace_gethrtime();
			mstate->dtms_present |= DTRACE_MSTATE_TIMESTAMP;
		}
		return (mstate->dtms_timestamp);

	case DIF_VAR_VTIMESTAMP:
		ASSERT(dtrace_vtime_references != 0);
		return (curthread->t_dtrace_vtime);

	case DIF_VAR_WALLTIMESTAMP:
		if (!(mstate->dtms_present & DTRACE_MSTATE_WALLTIMESTAMP)) {
			mstate->dtms_walltimestamp = dtrace_gethrestime();
			mstate->dtms_present |= DTRACE_MSTATE_WALLTIMESTAMP;
		}
		return (mstate->dtms_walltimestamp);
#endif

#ifdef illumos
	case DIF_VAR_IPL:
		if (!dtrace_priv_kernel(state))
			return (0);
		if (!(mstate->dtms_present & DTRACE_MSTATE_IPL)) {
			mstate->dtms_ipl = dtrace_getipl();
			mstate->dtms_present |= DTRACE_MSTATE_IPL;
		}
		return (mstate->dtms_ipl);
#endif

	case DIF_VAR_EPID:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_EPID);
		return (mstate->dtms_epid);

	case DIF_VAR_ID:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);
		return (mstate->dtms_probe->dtpr_id);

	case DIF_VAR_STACKDEPTH:
		if (!dtrace_priv_kernel(state))
			return (0);
		if (!(mstate->dtms_present & DTRACE_MSTATE_STACKDEPTH)) {
			int aframes = mstate->dtms_probe->dtpr_aframes + 2;

			mstate->dtms_stackdepth = dtrace_getstackdepth(aframes);
			mstate->dtms_present |= DTRACE_MSTATE_STACKDEPTH;
		}
		return (mstate->dtms_stackdepth);

	/*
	 * FIXME: We still want this, but can't get it from userspace at this
	 * point.
	 */
#if 0
	case DIF_VAR_USTACKDEPTH:
		if (!dtrace_priv_proc(state))
			return (0);
		if (!(mstate->dtms_present & DTRACE_MSTATE_USTACKDEPTH)) {
			/*
			 * See comment in DIF_VAR_PID.
			 */
			if (DTRACE_ANCHORED(mstate->dtms_probe) &&
			    CPU_ON_INTR(CPU)) {
				mstate->dtms_ustackdepth = 0;
			} else {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
				mstate->dtms_ustackdepth =
				    dtrace_getustackdepth();
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
			}
			mstate->dtms_present |= DTRACE_MSTATE_USTACKDEPTH;
		}
		return (mstate->dtms_ustackdepth);
#endif

	case DIF_VAR_CALLER:
		if (!dtrace_priv_kernel(state))
			return (0);
		if (!(mstate->dtms_present & DTRACE_MSTATE_CALLER)) {
			int aframes = mstate->dtms_probe->dtpr_aframes + 2;

			if (!DTRACE_ANCHORED(mstate->dtms_probe)) {
				/*
				 * If this is an unanchored probe, we are
				 * required to go through the slow path:
				 * dtrace_caller() only guarantees correct
				 * results for anchored probes.
				 */
				pc_t caller[2] = {0, 0};

				dtrace_getpcstack(caller, 2, aframes,
				    (uint32_t *)(uintptr_t)mstate->dtms_arg[0]);
				mstate->dtms_caller = caller[1];
			} else if ((mstate->dtms_caller =
			    dtrace_caller(aframes)) == -1) {
				/*
				 * We have failed to do this the quick way;
				 * we must resort to the slower approach of
				 * calling dtrace_getpcstack().
				 */
				pc_t caller = 0;

				dtrace_getpcstack(&caller, 1, aframes, NULL);
				mstate->dtms_caller = caller;
			}

			mstate->dtms_present |= DTRACE_MSTATE_CALLER;
		}
		return (mstate->dtms_caller);

	case DIF_VAR_UCALLER:
		if (!dtrace_priv_proc(state))
			return (0);

		if (!(mstate->dtms_present & DTRACE_MSTATE_UCALLER)) {
			uint64_t ustack[3];

			/*
			 * dtrace_getupcstack() fills in the first uint64_t
			 * with the current PID.  The second uint64_t will
			 * be the program counter at user-level.  The third
			 * uint64_t will contain the caller, which is what
			 * we're after.
			 */
			ustack[2] = 0;
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			dtrace_getupcstack(ustack, 3);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
			mstate->dtms_ucaller = ustack[2];
			mstate->dtms_present |= DTRACE_MSTATE_UCALLER;
		}

		return (mstate->dtms_ucaller);

	case DIF_VAR_PROBEPROV:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);
		return (dtrace_dif_varstr(
		    (uintptr_t)mstate->dtms_probe->dtpr_provider->dtpv_name,
		    state, mstate));

	case DIF_VAR_PROBEMOD:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);
		return (dtrace_dif_varstr(
		    (uintptr_t)mstate->dtms_probe->dtpr_mod,
		    state, mstate));

	case DIF_VAR_PROBEFUNC:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);
		return (dtrace_dif_varstr(
		    (uintptr_t)mstate->dtms_probe->dtpr_func,
		    state, mstate));

	case DIF_VAR_PROBENAME:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);
		return (dtrace_dif_varstr(
		    (uintptr_t)mstate->dtms_probe->dtpr_name,
		    state, mstate));

	case DIF_VAR_PID:
		if (!dtrace_priv_proc(state))
			return (0);

#ifdef illumos
		/*
		 * Note that we are assuming that an unanchored probe is
		 * always due to a high-level interrupt.  (And we're assuming
		 * that there is only a single high level interrupt.)
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			return (pid0.pid_id);

		/*
		 * It is always safe to dereference one's own t_procp pointer:
		 * it always points to a valid, allocated proc structure.
		 * Further, it is always safe to dereference the p_pidp member
		 * of one's own proc structure.  (These are truisms becuase
		 * threads and processes don't clean up their own state --
		 * they leave that task to whomever reaps them.)
		 */
		return ((uint64_t)curthread->t_procp->p_pidp->pid_id);
#else
		/*
		 * FIXME: This is the process that is _tracing_, not the
		 * _traced_ process, we want the traced process here. getpid()
		 * won't suffice, so we need to figure out some way to name
		 * things in this case and return the necessary pid, i.e., the
		 * one that actually called into the library.
		 * 
		 * XXX: Maybe this actually does work if we link libdtrace-core
		 * into the consumers that actually trace -- but I highly doubt
		 * that it's a good idea, as we would have to compile every
		 * program with libdtrace in there (possibly a thing???)
		 */
		return (getpid());
#endif

	case DIF_VAR_PPID:
		if (!dtrace_priv_proc(state))
			return (0);

#ifdef illumos
		/*
		 * See comment in DIF_VAR_PID.
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			return (pid0.pid_id);

		/*
		 * It is always safe to dereference one's own t_procp pointer:
		 * it always points to a valid, allocated proc structure.
		 * (This is true because threads don't clean up their own
		 * state -- they leave that task to whomever reaps them.)
		 */
		return ((uint64_t)curthread->t_procp->p_ppid);
#else
		/*
		 * FIXME: Same case as with DIF_VAR_PID
		 */
		return (getppid());
#endif

	case DIF_VAR_TID:
#ifdef illumos
		/*
		 * See comment in DIF_VAR_PID.
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			return (0);
#endif

		/*
		 * We are running on 1 thread here
		 */
		return (1);
	/*
	 * TODO: From my understanding, this is const char *argv[], and we might
	 * be able to get it by caching processes and their arguments in
	 * userspace.
	 */
#if 0
	case DIF_VAR_EXECARGS: {
		struct pargs *p_args = curthread->td_proc->p_args;

		if (p_args == NULL)
			return(0);

		return (dtrace_dif_varstrz(
		    (uintptr_t) p_args->ar_args, p_args->ar_length, state, mstate));
	}
#endif

	case DIF_VAR_EXECNAME:
#ifdef illumos
		if (!dtrace_priv_proc(state))
			return (0);

		/*
		 * See comment in DIF_VAR_PID.
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			return ((uint64_t)(uintptr_t)p0.p_user.u_comm);

		/*
		 * It is always safe to dereference one's own t_procp pointer:
		 * it always points to a valid, allocated proc structure.
		 * (This is true because threads don't clean up their own
		 * state -- they leave that task to whomever reaps them.)
		 */
		return (dtrace_dif_varstr(
		    (uintptr_t)curthread->t_procp->p_user.u_comm,
		    state, mstate));
#else
		/*
		 * FIXME: This is probably not what we want, same situation as
		 * with DIF_VAR_PID and DIF_VAR_PPID
		 */
		return (dtrace_dif_varstr((uintptr_t)getprogname(),
		    state, mstate));
#endif

	case DIF_VAR_ZONENAME:
#ifdef illumos
		if (!dtrace_priv_proc(state))
			return (0);

		/*
		 * See comment in DIF_VAR_PID.
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			return ((uint64_t)(uintptr_t)p0.p_zone->zone_name);

		/*
		 * It is always safe to dereference one's own t_procp pointer:
		 * it always points to a valid, allocated proc structure.
		 * (This is true because threads don't clean up their own
		 * state -- they leave that task to whomever reaps them.)
		 */
		return (dtrace_dif_varstr(
		    (uintptr_t)curthread->t_procp->p_zone->zone_name,
		    state, mstate));
#else
		return (0);
#endif

	case DIF_VAR_UID:
		if (!dtrace_priv_proc(state))
			return (0);

#ifdef illumos
		/*
		 * See comment in DIF_VAR_PID.
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			return ((uint64_t)p0.p_cred->cr_uid);

		/*
		 * It is always safe to dereference one's own t_procp pointer:
		 * it always points to a valid, allocated proc structure.
		 * (This is true because threads don't clean up their own
		 * state -- they leave that task to whomever reaps them.)
		 *
		 * Additionally, it is safe to dereference one's own process
		 * credential, since this is never NULL after process birth.
		 */
		return ((uint64_t)curthread->t_procp->p_cred->cr_uid);
#else
		/*
		 * FIXME: Same situation as with PID, PPID and the rest...
		 */
		return (getuid());
#endif

	case DIF_VAR_GID:
		if (!dtrace_priv_proc(state))
			return (0);

#ifdef illumos
		/*
		 * See comment in DIF_VAR_PID.
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			return ((uint64_t)p0.p_cred->cr_gid);

		/*
		 * It is always safe to dereference one's own t_procp pointer:
		 * it always points to a valid, allocated proc structure.
		 * (This is true because threads don't clean up their own
		 * state -- they leave that task to whomever reaps them.)
		 *
		 * Additionally, it is safe to dereference one's own process
		 * credential, since this is never NULL after process birth.
		 */
		return ((uint64_t)curthread->t_procp->p_cred->cr_gid);
#else
		/*
		 * FIXME: Same situation as with PID, PPID and the rest...
		 */
		return (getgid());
#endif

	case DIF_VAR_ERRNO: {
#ifdef illumos
		klwp_t *lwp;
		if (!dtrace_priv_proc(state))
			return (0);

		/*
		 * See comment in DIF_VAR_PID.
		 */
		if (DTRACE_ANCHORED(mstate->dtms_probe) && CPU_ON_INTR(CPU))
			return (0);

		/*
		 * It is always safe to dereference one's own t_lwp pointer in
		 * the event that this pointer is non-NULL.  (This is true
		 * because threads and lwps don't clean up their own state --
		 * they leave that task to whomever reaps them.)
		 */
		if ((lwp = curthread->t_lwp) == NULL)
			return (0);

		return ((uint64_t)lwp->lwp_errno);
#else
		/*
		 * FIXME: Again, probably not what we want?
		 */
		return (errno);
#endif
	}
#ifndef illumos
	case DIF_VAR_CPU: {
		return curcpu;
	}
#endif
	default:
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return (0);
	}
}

typedef enum dtrace_json_state {
	DTRACE_JSON_REST = 1,
	DTRACE_JSON_OBJECT,
	DTRACE_JSON_STRING,
	DTRACE_JSON_STRING_ESCAPE,
	DTRACE_JSON_STRING_ESCAPE_UNICODE,
	DTRACE_JSON_COLON,
	DTRACE_JSON_COMMA,
	DTRACE_JSON_VALUE,
	DTRACE_JSON_IDENTIFIER,
	DTRACE_JSON_NUMBER,
	DTRACE_JSON_NUMBER_FRAC,
	DTRACE_JSON_NUMBER_EXP,
	DTRACE_JSON_COLLECT_OBJECT
} dtrace_json_state_t;

/*
 * This function possesses just enough knowledge about JSON to extract a single
 * value from a JSON string and store it in the scratch buffer.  It is able
 * to extract nested object values, and members of arrays by index.
 *
 * elemlist is a list of JSON keys, stored as packed NUL-terminated strings, to
 * be looked up as we descend into the object tree.  e.g.
 *
 *    foo[0].bar.baz[32] --> "foo" NUL "0" NUL "bar" NUL "baz" NUL "32" NUL
 *       with nelems = 5.
 *
 * The run time of this function must be bounded above by strsize to limit the
 * amount of work done in probe context.  As such, it is implemented as a
 * simple state machine, reading one character at a time using safe loads
 * until we find the requested element, hit a parsing error or run off the
 * end of the object or string.
 *
 * As there is no way for a subroutine to return an error without interrupting
 * clause execution, we simply return NULL in the event of a missing key or any
 * other error condition.  Each NULL return in this function is commented with
 * the error condition it represents -- parsing or otherwise.
 *
 * The set of states for the state machine closely matches the JSON
 * specification (http://json.org/).  Briefly:
 *
 *   DTRACE_JSON_REST:
 *     Skip whitespace until we find either a top-level Object, moving
 *     to DTRACE_JSON_OBJECT; or an Array, moving to DTRACE_JSON_VALUE.
 *
 *   DTRACE_JSON_OBJECT:
 *     Locate the next key String in an Object.  Sets a flag to denote
 *     the next String as a key string and moves to DTRACE_JSON_STRING.
 *
 *   DTRACE_JSON_COLON:
 *     Skip whitespace until we find the colon that separates key Strings
 *     from their values.  Once found, move to DTRACE_JSON_VALUE.
 *
 *   DTRACE_JSON_VALUE:
 *     Detects the type of the next value (String, Number, Identifier, Object
 *     or Array) and routes to the states that process that type.  Here we also
 *     deal with the element selector list if we are requested to traverse down
 *     into the object tree.
 *
 *   DTRACE_JSON_COMMA:
 *     Skip whitespace until we find the comma that separates key-value pairs
 *     in Objects (returning to DTRACE_JSON_OBJECT) or values in Arrays
 *     (similarly DTRACE_JSON_VALUE).  All following literal value processing
 *     states return to this state at the end of their value, unless otherwise
 *     noted.
 *
 *   DTRACE_JSON_NUMBER, DTRACE_JSON_NUMBER_FRAC, DTRACE_JSON_NUMBER_EXP:
 *     Processes a Number literal from the JSON, including any exponent
 *     component that may be present.  Numbers are returned as strings, which
 *     may be passed to strtoll() if an integer is required.
 *
 *   DTRACE_JSON_IDENTIFIER:
 *     Processes a "true", "false" or "null" literal in the JSON.
 *
 *   DTRACE_JSON_STRING, DTRACE_JSON_STRING_ESCAPE,
 *   DTRACE_JSON_STRING_ESCAPE_UNICODE:
 *     Processes a String literal from the JSON, whether the String denotes
 *     a key, a value or part of a larger Object.  Handles all escape sequences
 *     present in the specification, including four-digit unicode characters,
 *     but merely includes the escape sequence without converting it to the
 *     actual escaped character.  If the String is flagged as a key, we
 *     move to DTRACE_JSON_COLON rather than DTRACE_JSON_COMMA.
 *
 *   DTRACE_JSON_COLLECT_OBJECT:
 *     This state collects an entire Object (or Array), correctly handling
 *     embedded strings.  If the full element selector list matches this nested
 *     object, we return the Object in full as a string.  If not, we use this
 *     state to skip to the next value at this level and continue processing.
 *
 * NOTE: This function uses various macros from strtolctype.h to manipulate
 * digit values, etc -- these have all been checked to ensure they make
 * no additional function calls.
 */
static char *
dtrace_json(uint64_t size, uintptr_t json, char *elemlist, int nelems,
    char *dest)
{
	dtrace_json_state_t state = DTRACE_JSON_REST;
	int64_t array_elem = INT64_MIN;
	int64_t array_pos = 0;
	uint8_t escape_unicount = 0;
	boolean_t string_is_key = B_FALSE;
	boolean_t collect_object = B_FALSE;
	boolean_t found_key = B_FALSE;
	boolean_t in_array = B_FALSE;
	uint32_t braces = 0, brackets = 0;
	char *elem = elemlist;
	char *dd = dest;
	uintptr_t cur;

	for (cur = json; cur < json + size; cur++) {
		char cc = dtrace_load8(cur);
		if (cc == '\0')
			return (NULL);

		switch (state) {
		case DTRACE_JSON_REST:
			if (isspace(cc))
				break;

			if (cc == '{') {
				state = DTRACE_JSON_OBJECT;
				break;
			}

			if (cc == '[') {
				in_array = B_TRUE;
				array_pos = 0;
				array_elem = dtrace_strtoll(elem, 10, size);
				found_key = array_elem == 0 ? B_TRUE : B_FALSE;
				state = DTRACE_JSON_VALUE;
				break;
			}

			/*
			 * ERROR: expected to find a top-level object or array.
			 */
			return (NULL);
		case DTRACE_JSON_OBJECT:
			if (isspace(cc))
				break;

			if (cc == '"') {
				state = DTRACE_JSON_STRING;
				string_is_key = B_TRUE;
				break;
			}

			/*
			 * ERROR: either the object did not start with a key
			 * string, or we've run off the end of the object
			 * without finding the requested key.
			 */
			return (NULL);
		case DTRACE_JSON_STRING:
			if (cc == '\\') {
				*dd++ = '\\';
				state = DTRACE_JSON_STRING_ESCAPE;
				break;
			}

			if (cc == '"') {
				if (collect_object) {
					/*
					 * We don't reset the dest here, as
					 * the string is part of a larger
					 * object being collected.
					 */
					*dd++ = cc;
					collect_object = B_FALSE;
					state = DTRACE_JSON_COLLECT_OBJECT;
					break;
				}
				*dd = '\0';
				dd = dest; /* reset string buffer */
				if (string_is_key) {
					if (dtrace_strncmp(dest, elem,
					    size) == 0)
						found_key = B_TRUE;
				} else if (found_key) {
					if (nelems > 1) {
						/*
						 * We expected an object, not
						 * this string.
						 */
						return (NULL);
					}
					return (dest);
				}
				state = string_is_key ? DTRACE_JSON_COLON :
				    DTRACE_JSON_COMMA;
				string_is_key = B_FALSE;
				break;
			}

			*dd++ = cc;
			break;
		case DTRACE_JSON_STRING_ESCAPE:
			*dd++ = cc;
			if (cc == 'u') {
				escape_unicount = 0;
				state = DTRACE_JSON_STRING_ESCAPE_UNICODE;
			} else {
				state = DTRACE_JSON_STRING;
			}
			break;
		case DTRACE_JSON_STRING_ESCAPE_UNICODE:
			if (!isxdigit(cc)) {
				/*
				 * ERROR: invalid unicode escape, expected
				 * four valid hexidecimal digits.
				 */
				return (NULL);
			}

			*dd++ = cc;
			if (++escape_unicount == 4)
				state = DTRACE_JSON_STRING;
			break;
		case DTRACE_JSON_COLON:
			if (isspace(cc))
				break;

			if (cc == ':') {
				state = DTRACE_JSON_VALUE;
				break;
			}

			/*
			 * ERROR: expected a colon.
			 */
			return (NULL);
		case DTRACE_JSON_COMMA:
			if (isspace(cc))
				break;

			if (cc == ',') {
				if (in_array) {
					state = DTRACE_JSON_VALUE;
					if (++array_pos == array_elem)
						found_key = B_TRUE;
				} else {
					state = DTRACE_JSON_OBJECT;
				}
				break;
			}

			/*
			 * ERROR: either we hit an unexpected character, or
			 * we reached the end of the object or array without
			 * finding the requested key.
			 */
			return (NULL);
		case DTRACE_JSON_IDENTIFIER:
			if (islower(cc)) {
				*dd++ = cc;
				break;
			}

			*dd = '\0';
			dd = dest; /* reset string buffer */

			if (dtrace_strncmp(dest, "true", 5) == 0 ||
			    dtrace_strncmp(dest, "false", 6) == 0 ||
			    dtrace_strncmp(dest, "null", 5) == 0) {
				if (found_key) {
					if (nelems > 1) {
						/*
						 * ERROR: We expected an object,
						 * not this identifier.
						 */
						return (NULL);
					}
					return (dest);
				} else {
					cur--;
					state = DTRACE_JSON_COMMA;
					break;
				}
			}

			/*
			 * ERROR: we did not recognise the identifier as one
			 * of those in the JSON specification.
			 */
			return (NULL);
		case DTRACE_JSON_NUMBER:
			if (cc == '.') {
				*dd++ = cc;
				state = DTRACE_JSON_NUMBER_FRAC;
				break;
			}

			if (cc == 'x' || cc == 'X') {
				/*
				 * ERROR: specification explicitly excludes
				 * hexidecimal or octal numbers.
				 */
				return (NULL);
			}

			/* FALLTHRU */
		case DTRACE_JSON_NUMBER_FRAC:
			if (cc == 'e' || cc == 'E') {
				*dd++ = cc;
				state = DTRACE_JSON_NUMBER_EXP;
				break;
			}

			if (cc == '+' || cc == '-') {
				/*
				 * ERROR: expect sign as part of exponent only.
				 */
				return (NULL);
			}
			/* FALLTHRU */
		case DTRACE_JSON_NUMBER_EXP:
			if (isdigit(cc) || cc == '+' || cc == '-') {
				*dd++ = cc;
				break;
			}

			*dd = '\0';
			dd = dest; /* reset string buffer */
			if (found_key) {
				if (nelems > 1) {
					/*
					 * ERROR: We expected an object, not
					 * this number.
					 */
					return (NULL);
				}
				return (dest);
			}

			cur--;
			state = DTRACE_JSON_COMMA;
			break;
		case DTRACE_JSON_VALUE:
			if (isspace(cc))
				break;

			if (cc == '{' || cc == '[') {
				if (nelems > 1 && found_key) {
					in_array = cc == '[' ? B_TRUE : B_FALSE;
					/*
					 * If our element selector directs us
					 * to descend into this nested object,
					 * then move to the next selector
					 * element in the list and restart the
					 * state machine.
					 */
					while (*elem != '\0')
						elem++;
					elem++; /* skip the inter-element NUL */
					nelems--;
					dd = dest;
					if (in_array) {
						state = DTRACE_JSON_VALUE;
						array_pos = 0;
						array_elem = dtrace_strtoll(
						    elem, 10, size);
						found_key = array_elem == 0 ?
						    B_TRUE : B_FALSE;
					} else {
						found_key = B_FALSE;
						state = DTRACE_JSON_OBJECT;
					}
					break;
				}

				/*
				 * Otherwise, we wish to either skip this
				 * nested object or return it in full.
				 */
				if (cc == '[')
					brackets = 1;
				else
					braces = 1;
				*dd++ = cc;
				state = DTRACE_JSON_COLLECT_OBJECT;
				break;
			}

			if (cc == '"') {
				state = DTRACE_JSON_STRING;
				break;
			}

			if (islower(cc)) {
				/*
				 * Here we deal with true, false and null.
				 */
				*dd++ = cc;
				state = DTRACE_JSON_IDENTIFIER;
				break;
			}

			if (cc == '-' || isdigit(cc)) {
				*dd++ = cc;
				state = DTRACE_JSON_NUMBER;
				break;
			}

			/*
			 * ERROR: unexpected character at start of value.
			 */
			return (NULL);
		case DTRACE_JSON_COLLECT_OBJECT:
			if (cc == '\0')
				/*
				 * ERROR: unexpected end of input.
				 */
				return (NULL);

			*dd++ = cc;
			if (cc == '"') {
				collect_object = B_TRUE;
				state = DTRACE_JSON_STRING;
				break;
			}

			if (cc == ']') {
				if (brackets-- == 0) {
					/*
					 * ERROR: unbalanced brackets.
					 */
					return (NULL);
				}
			} else if (cc == '}') {
				if (braces-- == 0) {
					/*
					 * ERROR: unbalanced braces.
					 */
					return (NULL);
				}
			} else if (cc == '{') {
				braces++;
			} else if (cc == '[') {
				brackets++;
			}

			if (brackets == 0 && braces == 0) {
				if (found_key) {
					*dd = '\0';
					return (dest);
				}
				dd = dest; /* reset string buffer */
				state = DTRACE_JSON_COMMA;
			}
			break;
		}
	}
	return (NULL);
}

/*
 * Emulate the execution of DTrace ID subroutines invoked by the call opcode.
 * Notice that we don't bother validating the proper number of arguments or
 * their types in the tuple stack.  This isn't needed because all argument
 * interpretation is safe because of our load safety -- the worst that can
 * happen is that a bogus program can obtain bogus results.
 */
static void
dtrace_dif_subr(uint_t subr, uint_t rd, uint64_t *regs,
    dtrace_key_t *tupregs, int nargs,
    dtrace_mstate_t *mstate, dtrace_state_t *state)
{
	volatile uint16_t *flags = &cpuc_dtrace_flags;
	volatile uintptr_t *illval = &cpuc_dtrace_illval;
	dtrace_vstate_t *vstate = &state->dts_vstate;

#ifdef illumos
	union {
		mutex_impl_t mi;
		uint64_t mx;
	} m;

	union {
		krwlock_t ri;
		uintptr_t rw;
	} r;
#else
#if 0
	struct thread *lowner;
	union {
		struct lock_object *li;
		uintptr_t lx;
	} l;
#endif
#endif

	switch (subr) {
	case DIF_SUBR_RAND:
		regs[rd] = arc4random();
		break;

#ifdef illumos
	case DIF_SUBR_MUTEX_OWNED:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (kmutex_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		m.mx = dtrace_load64(tupregs[0].dttk_value);
		if (MUTEX_TYPE_ADAPTIVE(&m.mi))
			regs[rd] = MUTEX_OWNER(&m.mi) != MUTEX_NO_OWNER;
		else
			regs[rd] = LOCK_HELD(&m.mi.m_spin.m_spinlock);
		break;

	case DIF_SUBR_MUTEX_OWNER:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (kmutex_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		m.mx = dtrace_load64(tupregs[0].dttk_value);
		if (MUTEX_TYPE_ADAPTIVE(&m.mi) &&
		    MUTEX_OWNER(&m.mi) != MUTEX_NO_OWNER)
			regs[rd] = (uintptr_t)MUTEX_OWNER(&m.mi);
		else
			regs[rd] = 0;
		break;

	case DIF_SUBR_MUTEX_TYPE_ADAPTIVE:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (kmutex_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		m.mx = dtrace_load64(tupregs[0].dttk_value);
		regs[rd] = MUTEX_TYPE_ADAPTIVE(&m.mi);
		break;

	case DIF_SUBR_MUTEX_TYPE_SPIN:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (kmutex_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		m.mx = dtrace_load64(tupregs[0].dttk_value);
		regs[rd] = MUTEX_TYPE_SPIN(&m.mi);
		break;

	case DIF_SUBR_RW_READ_HELD: {
		uintptr_t tmp;

		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (uintptr_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		r.rw = dtrace_loadptr(tupregs[0].dttk_value);
		regs[rd] = _RW_READ_HELD(&r.ri, tmp);
		break;
	}

	case DIF_SUBR_RW_WRITE_HELD:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (krwlock_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		r.rw = dtrace_loadptr(tupregs[0].dttk_value);
		regs[rd] = _RW_WRITE_HELD(&r.ri);
		break;

	case DIF_SUBR_RW_ISWRITER:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (krwlock_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		r.rw = dtrace_loadptr(tupregs[0].dttk_value);
		regs[rd] = _RW_ISWRITER(&r.ri);
		break;

#else /* !illumos */
#if 0
	case DIF_SUBR_MUTEX_OWNED:
		if (!dtrace_canload(tupregs[0].dttk_value,
			sizeof (struct lock_object), mstate, vstate)) {
			regs[rd] = 0;
			break;
		}
		l.lx = dtrace_loadptr((uintptr_t)&tupregs[0].dttk_value);
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		regs[rd] = LOCK_CLASS(l.li)->lc_owner(l.li, &lowner);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		break;

	case DIF_SUBR_MUTEX_OWNER:
		if (!dtrace_canload(tupregs[0].dttk_value,
			sizeof (struct lock_object), mstate, vstate)) {
			regs[rd] = 0;
			break;
		}
		l.lx = dtrace_loadptr((uintptr_t)&tupregs[0].dttk_value);
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		LOCK_CLASS(l.li)->lc_owner(l.li, &lowner);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		regs[rd] = (uintptr_t)lowner;
		break;

	case DIF_SUBR_MUTEX_TYPE_ADAPTIVE:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (struct mtx),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}
		l.lx = dtrace_loadptr((uintptr_t)&tupregs[0].dttk_value);
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		regs[rd] = (LOCK_CLASS(l.li)->lc_flags & LC_SLEEPLOCK) != 0;
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		break;

	case DIF_SUBR_MUTEX_TYPE_SPIN:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (struct mtx),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}
		l.lx = dtrace_loadptr((uintptr_t)&tupregs[0].dttk_value);
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		regs[rd] = (LOCK_CLASS(l.li)->lc_flags & LC_SPINLOCK) != 0;
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		break;

	case DIF_SUBR_RW_READ_HELD: 
	case DIF_SUBR_SX_SHARED_HELD: 
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (uintptr_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}
		l.lx = dtrace_loadptr((uintptr_t)&tupregs[0].dttk_value);
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		regs[rd] = LOCK_CLASS(l.li)->lc_owner(l.li, &lowner) &&
		    lowner == NULL;
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		break;

	case DIF_SUBR_RW_WRITE_HELD:
	case DIF_SUBR_SX_EXCLUSIVE_HELD:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (uintptr_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}
		l.lx = dtrace_loadptr(tupregs[0].dttk_value);
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		regs[rd] = LOCK_CLASS(l.li)->lc_owner(l.li, &lowner) &&
		    lowner != NULL;
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		break;

	case DIF_SUBR_RW_ISWRITER:
	case DIF_SUBR_SX_ISEXCLUSIVE:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof (uintptr_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}
		l.lx = dtrace_loadptr(tupregs[0].dttk_value);
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		LOCK_CLASS(l.li)->lc_owner(l.li, &lowner);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		regs[rd] = (lowner == curthread);
		break;
#endif
#endif /* illumos */

	case DIF_SUBR_BCOPY: {
		/*
		 * We need to be sure that the destination is in the scratch
		 * region -- no other region is allowed.
		 */
		uintptr_t src = tupregs[0].dttk_value;
		uintptr_t dest = tupregs[1].dttk_value;
		size_t size = tupregs[2].dttk_value;

		if (!dtrace_inscratch(dest, size, mstate)) {
			*flags |= CPU_DTRACE_BADADDR;
			*illval = regs[rd];
			break;
		}

		if (!dtrace_canload(src, size, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		dtrace_bcopy((void *)src, (void *)dest, size);
		break;
	}

	case DIF_SUBR_ALLOCA:
	case DIF_SUBR_COPYIN: {
		uintptr_t dest = P2ROUNDUP(mstate->dtms_scratch_ptr, 8);
		uint64_t size =
		    tupregs[subr == DIF_SUBR_ALLOCA ? 0 : 1].dttk_value;
		size_t scratch_size = (dest - mstate->dtms_scratch_ptr) + size;

		/*
		 * This action doesn't require any credential checks since
		 * probes will not activate in user contexts to which the
		 * enabling user does not have permissions.
		 */

		/*
		 * Rounding up the user allocation size could have overflowed
		 * a large, bogus allocation (like -1ULL) to 0.
		 */
		if (scratch_size < size ||
		    !DTRACE_INSCRATCH(mstate, scratch_size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		if (subr == DIF_SUBR_COPYIN) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			dtrace_copyin(tupregs[0].dttk_value, dest, size, flags);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		}

		mstate->dtms_scratch_ptr += scratch_size;
		regs[rd] = dest;
		break;
	}

	case DIF_SUBR_COPYINTO: {
		uint64_t size = tupregs[1].dttk_value;
		uintptr_t dest = tupregs[2].dttk_value;

		/*
		 * This action doesn't require any credential checks since
		 * probes will not activate in user contexts to which the
		 * enabling user does not have permissions.
		 */
		if (!dtrace_inscratch(dest, size, mstate)) {
			*flags |= CPU_DTRACE_BADADDR;
			*illval = regs[rd];
			break;
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		dtrace_copyin(tupregs[0].dttk_value, dest, size, flags);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		break;
	}

	case DIF_SUBR_COPYINSTR: {
		uintptr_t dest = mstate->dtms_scratch_ptr;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];

		if (nargs > 1 && tupregs[1].dttk_value < size)
			size = tupregs[1].dttk_value + 1;

		/*
		 * This action doesn't require any credential checks since
		 * probes will not activate in user contexts to which the
		 * enabling user does not have permissions.
		 */
		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		dtrace_copyinstr(tupregs[0].dttk_value, dest, size, flags);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

		((char *)dest)[size - 1] = '\0';
		mstate->dtms_scratch_ptr += size;
		regs[rd] = dest;
		break;
	}

#ifdef illumos
	case DIF_SUBR_MSGSIZE:
	case DIF_SUBR_MSGDSIZE: {
		uintptr_t baddr = tupregs[0].dttk_value, daddr;
		uintptr_t wptr, rptr;
		size_t count = 0;
		int cont = 0;

		while (baddr != 0 && !(*flags & CPU_DTRACE_FAULT)) {

			if (!dtrace_canload(baddr, sizeof (mblk_t), mstate,
			    vstate)) {
				regs[rd] = 0;
				break;
			}

			wptr = dtrace_loadptr(baddr +
			    offsetof(mblk_t, b_wptr));

			rptr = dtrace_loadptr(baddr +
			    offsetof(mblk_t, b_rptr));

			if (wptr < rptr) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = tupregs[0].dttk_value;
				break;
			}

			daddr = dtrace_loadptr(baddr +
			    offsetof(mblk_t, b_datap));

			baddr = dtrace_loadptr(baddr +
			    offsetof(mblk_t, b_cont));

			/*
			 * We want to prevent against denial-of-service here,
			 * so we're only going to search the list for
			 * dtrace_msgdsize_max mblks.
			 */
			if (cont++ > dtrace_msgdsize_max) {
				*flags |= CPU_DTRACE_ILLOP;
				break;
			}

			if (subr == DIF_SUBR_MSGDSIZE) {
				if (dtrace_load8(daddr +
				    offsetof(dblk_t, db_type)) != M_DATA)
					continue;
			}

			count += wptr - rptr;
		}

		if (!(*flags & CPU_DTRACE_FAULT))
			regs[rd] = count;

		break;
	}
#endif

	/*
	 * FIXME: We probably want this, but it's a little bit unclear as to how
	 * to check this...
	 */
#if 0
	case DIF_SUBR_PROGENYOF: {
		pid_t pid = tupregs[0].dttk_value;
		proc_t *p;
		int rval = 0;

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);

		for (p = curthread->t_procp; p != NULL; p = p->p_parent) {
#ifdef illumos
			if (p->p_pidp->pid_id == pid) {
#else
			if (p->p_pid == pid) {
#endif
				rval = 1;
				break;
			}
		}

		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

		regs[rd] = rval;
		break;
	}
#endif

	case DIF_SUBR_SPECULATION:
		regs[rd] = dtrace_speculation(state);
		break;

	case DIF_SUBR_COPYOUT: {
		uintptr_t kaddr = tupregs[0].dttk_value;
		uintptr_t uaddr = tupregs[1].dttk_value;
		uint64_t size = tupregs[2].dttk_value;

		if (!dtrace_destructive_disallow &&
		    dtrace_priv_proc_control(state) &&
		    !dtrace_istoxic(kaddr, size) &&
		    dtrace_canload(kaddr, size, mstate, vstate)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			dtrace_copyout(kaddr, uaddr, size, flags);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		}
		break;
	}

	case DIF_SUBR_COPYOUTSTR: {
		uintptr_t kaddr = tupregs[0].dttk_value;
		uintptr_t uaddr = tupregs[1].dttk_value;
		uint64_t size = tupregs[2].dttk_value;
		size_t lim;

		if (!dtrace_destructive_disallow &&
		    dtrace_priv_proc_control(state) &&
		    !dtrace_istoxic(kaddr, size) &&
		    dtrace_strcanload(kaddr, size, &lim, mstate, vstate)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			dtrace_copyoutstr(kaddr, uaddr, lim, flags);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		}
		break;
	}

	case DIF_SUBR_STRLEN: {
		size_t size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t addr = (uintptr_t)tupregs[0].dttk_value;
		size_t lim;

		if (!dtrace_strcanload(addr, size, &lim, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		regs[rd] = dtrace_strlen((char *)addr, lim);
		break;
	}

	case DIF_SUBR_STRCHR:
	case DIF_SUBR_STRRCHR: {
		/*
		 * We're going to iterate over the string looking for the
		 * specified character.  We will iterate until we have reached
		 * the string length or we have found the character.  If this
		 * is DIF_SUBR_STRRCHR, we will look for the last occurrence
		 * of the specified character instead of the first.
		 */
		uintptr_t addr = tupregs[0].dttk_value;
		uintptr_t addr_limit;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		size_t lim;
		char c, target = (char)tupregs[1].dttk_value;

		if (!dtrace_strcanload(addr, size, &lim, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}
		addr_limit = addr + lim;

		for (regs[rd] = 0; addr < addr_limit; addr++) {
			if ((c = dtrace_load8(addr)) == target) {
				regs[rd] = addr;

				if (subr == DIF_SUBR_STRCHR)
					break;
			}

			if (c == '\0')
				break;
		}
		break;
	}

	case DIF_SUBR_STRSTR:
	case DIF_SUBR_INDEX:
	case DIF_SUBR_RINDEX: {
		/*
		 * We're going to iterate over the string looking for the
		 * specified string.  We will iterate until we have reached
		 * the string length or we have found the string.  (Yes, this
		 * is done in the most naive way possible -- but considering
		 * that the string we're searching for is likely to be
		 * relatively short, the complexity of Rabin-Karp or similar
		 * hardly seems merited.)
		 */
		char *addr = (char *)(uintptr_t)tupregs[0].dttk_value;
		char *substr = (char *)(uintptr_t)tupregs[1].dttk_value;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		size_t len = dtrace_strlen(addr, size);
		size_t sublen = dtrace_strlen(substr, size);
		char *limit = addr + len, *orig = addr;
		int notfound = subr == DIF_SUBR_STRSTR ? 0 : -1;
		int inc = 1;

		regs[rd] = notfound;

		if (!dtrace_canload((uintptr_t)addr, len + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!dtrace_canload((uintptr_t)substr, sublen + 1, mstate,
		    vstate)) {
			regs[rd] = 0;
			break;
		}

		/*
		 * strstr() and index()/rindex() have similar semantics if
		 * both strings are the empty string: strstr() returns a
		 * pointer to the (empty) string, and index() and rindex()
		 * both return index 0 (regardless of any position argument).
		 */
		if (sublen == 0 && len == 0) {
			if (subr == DIF_SUBR_STRSTR)
				regs[rd] = (uintptr_t)addr;
			else
				regs[rd] = 0;
			break;
		}

		if (subr != DIF_SUBR_STRSTR) {
			if (subr == DIF_SUBR_RINDEX) {
				limit = orig - 1;
				addr += len;
				inc = -1;
			}

			/*
			 * Both index() and rindex() take an optional position
			 * argument that denotes the starting position.
			 */
			if (nargs == 3) {
				int64_t pos = (int64_t)tupregs[2].dttk_value;

				/*
				 * If the position argument to index() is
				 * negative, Perl implicitly clamps it at
				 * zero.  This semantic is a little surprising
				 * given the special meaning of negative
				 * positions to similar Perl functions like
				 * substr(), but it appears to reflect a
				 * notion that index() can start from a
				 * negative index and increment its way up to
				 * the string.  Given this notion, Perl's
				 * rindex() is at least self-consistent in
				 * that it implicitly clamps positions greater
				 * than the string length to be the string
				 * length.  Where Perl completely loses
				 * coherence, however, is when the specified
				 * substring is the empty string ("").  In
				 * this case, even if the position is
				 * negative, rindex() returns 0 -- and even if
				 * the position is greater than the length,
				 * index() returns the string length.  These
				 * semantics violate the notion that index()
				 * should never return a value less than the
				 * specified position and that rindex() should
				 * never return a value greater than the
				 * specified position.  (One assumes that
				 * these semantics are artifacts of Perl's
				 * implementation and not the results of
				 * deliberate design -- it beggars belief that
				 * even Larry Wall could desire such oddness.)
				 * While in the abstract one would wish for
				 * consistent position semantics across
				 * substr(), index() and rindex() -- or at the
				 * very least self-consistent position
				 * semantics for index() and rindex() -- we
				 * instead opt to keep with the extant Perl
				 * semantics, in all their broken glory.  (Do
				 * we have more desire to maintain Perl's
				 * semantics than Perl does?  Probably.)
				 */
				if (subr == DIF_SUBR_RINDEX) {
					if (pos < 0) {
						if (sublen == 0)
							regs[rd] = 0;
						break;
					}

					if (pos > len)
						pos = len;
				} else {
					if (pos < 0)
						pos = 0;

					if (pos >= len) {
						if (sublen == 0)
							regs[rd] = len;
						break;
					}
				}

				addr = orig + pos;
			}
		}

		for (regs[rd] = notfound; addr != limit; addr += inc) {
			if (dtrace_strncmp(addr, substr, sublen) == 0) {
				if (subr != DIF_SUBR_STRSTR) {
					/*
					 * As D index() and rindex() are
					 * modeled on Perl (and not on awk),
					 * we return a zero-based (and not a
					 * one-based) index.  (For you Perl
					 * weenies: no, we're not going to add
					 * $[ -- and shouldn't you be at a con
					 * or something?)
					 */
					regs[rd] = (uintptr_t)(addr - orig);
					break;
				}

				ASSERT(subr == DIF_SUBR_STRSTR);
				regs[rd] = (uintptr_t)addr;
				break;
			}
		}

		break;
	}

	case DIF_SUBR_STRTOK: {
		uintptr_t addr = tupregs[0].dttk_value;
		uintptr_t tokaddr = tupregs[1].dttk_value;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t limit, toklimit;
		size_t clim;
		uint8_t c = 0, tokmap[32];	 /* 256 / 8 */
		char *dest = (char *)mstate->dtms_scratch_ptr;
		int i;

		/*
		 * Check both the token buffer and (later) the input buffer,
		 * since both could be non-scratch addresses.
		 */
		if (!dtrace_strcanload(tokaddr, size, &clim, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}
		toklimit = tokaddr + clim;

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		if (addr == 0) {
			/*
			 * If the address specified is NULL, we use our saved
			 * strtok pointer from the mstate.  Note that this
			 * means that the saved strtok pointer is _only_
			 * valid within multiple enablings of the same probe --
			 * it behaves like an implicit clause-local variable.
			 */
			addr = mstate->dtms_strtok;
			limit = mstate->dtms_strtok_limit;
		} else {
			/*
			 * If the user-specified address is non-NULL we must
			 * access check it.  This is the only time we have
			 * a chance to do so, since this address may reside
			 * in the string table of this clause-- future calls
			 * (when we fetch addr from mstate->dtms_strtok)
			 * would fail this access check.
			 */
			if (!dtrace_strcanload(addr, size, &clim, mstate,
			    vstate)) {
				regs[rd] = 0;
				break;
			}
			limit = addr + clim;
		}

		/*
		 * First, zero the token map, and then process the token
		 * string -- setting a bit in the map for every character
		 * found in the token string.
		 */
		for (i = 0; i < sizeof (tokmap); i++)
			tokmap[i] = 0;

		for (; tokaddr < toklimit; tokaddr++) {
			if ((c = dtrace_load8(tokaddr)) == '\0')
				break;

			ASSERT((c >> 3) < sizeof (tokmap));
			tokmap[c >> 3] |= (1 << (c & 0x7));
		}

		for (; addr < limit; addr++) {
			/*
			 * We're looking for a character that is _not_
			 * contained in the token string.
			 */
			if ((c = dtrace_load8(addr)) == '\0')
				break;

			if (!(tokmap[c >> 3] & (1 << (c & 0x7))))
				break;
		}

		if (c == '\0') {
			/*
			 * We reached the end of the string without finding
			 * any character that was not in the token string.
			 * We return NULL in this case, and we set the saved
			 * address to NULL as well.
			 */
			regs[rd] = 0;
			mstate->dtms_strtok = 0;
			mstate->dtms_strtok_limit = 0;
			break;
		}

		/*
		 * From here on, we're copying into the destination string.
		 */
		for (i = 0; addr < limit && i < size - 1; addr++) {
			if ((c = dtrace_load8(addr)) == '\0')
				break;

			if (tokmap[c >> 3] & (1 << (c & 0x7)))
				break;

			ASSERT(i < size);
			dest[i++] = c;
		}

		ASSERT(i < size);
		dest[i] = '\0';
		regs[rd] = (uintptr_t)dest;
		mstate->dtms_scratch_ptr += size;
		mstate->dtms_strtok = addr;
		mstate->dtms_strtok_limit = limit;
		break;
	}

	case DIF_SUBR_SUBSTR: {
		uintptr_t s = tupregs[0].dttk_value;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		char *d = (char *)mstate->dtms_scratch_ptr;
		int64_t index = (int64_t)tupregs[1].dttk_value;
		int64_t remaining = (int64_t)tupregs[2].dttk_value;
		size_t len = dtrace_strlen((char *)s, size);
		int64_t i;

		if (!dtrace_canload(s, len + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		if (nargs <= 2)
			remaining = (int64_t)size;

		if (index < 0) {
			index += len;

			if (index < 0 && index + remaining > 0) {
				remaining += index;
				index = 0;
			}
		}

		if (index >= len || index < 0) {
			remaining = 0;
		} else if (remaining < 0) {
			remaining += len - index;
		} else if (index + remaining > size) {
			remaining = size - index;
		}

		for (i = 0; i < remaining; i++) {
			if ((d[i] = dtrace_load8(s + index + i)) == '\0')
				break;
		}

		d[i] = '\0';

		mstate->dtms_scratch_ptr += size;
		regs[rd] = (uintptr_t)d;
		break;
	}

	case DIF_SUBR_JSON: {
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t json = tupregs[0].dttk_value;
		size_t jsonlen = dtrace_strlen((char *)json, size);
		uintptr_t elem = tupregs[1].dttk_value;
		size_t elemlen = dtrace_strlen((char *)elem, size);

		char *dest = (char *)mstate->dtms_scratch_ptr;
		char *elemlist = (char *)mstate->dtms_scratch_ptr + jsonlen + 1;
		char *ee = elemlist;
		int nelems = 1;
		uintptr_t cur;

		if (!dtrace_canload(json, jsonlen + 1, mstate, vstate) ||
		    !dtrace_canload(elem, elemlen + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, jsonlen + 1 + elemlen + 1)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		/*
		 * Read the element selector and split it up into a packed list
		 * of strings.
		 */
		for (cur = elem; cur < elem + elemlen; cur++) {
			char cc = dtrace_load8(cur);

			if (cur == elem && cc == '[') {
				/*
				 * If the first element selector key is
				 * actually an array index then ignore the
				 * bracket.
				 */
				continue;
			}

			if (cc == ']')
				continue;

			if (cc == '.' || cc == '[') {
				nelems++;
				cc = '\0';
			}

			*ee++ = cc;
		}
		*ee++ = '\0';

		if ((regs[rd] = (uintptr_t)dtrace_json(size, json, elemlist,
		    nelems, dest)) != 0)
			mstate->dtms_scratch_ptr += jsonlen + 1;
		break;
	}

	case DIF_SUBR_TOUPPER:
	case DIF_SUBR_TOLOWER: {
		uintptr_t s = tupregs[0].dttk_value;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		char *dest = (char *)mstate->dtms_scratch_ptr, c;
		size_t len = dtrace_strlen((char *)s, size);
		char lower, upper, convert;
		int64_t i;

		if (subr == DIF_SUBR_TOUPPER) {
			lower = 'a';
			upper = 'z';
			convert = 'A';
		} else {
			lower = 'A';
			upper = 'Z';
			convert = 'a';
		}

		if (!dtrace_canload(s, len + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		for (i = 0; i < size - 1; i++) {
			if ((c = dtrace_load8(s + i)) == '\0')
				break;

			if (c >= lower && c <= upper)
				c = convert + (c - lower);

			dest[i] = c;
		}

		ASSERT(i < size);
		dest[i] = '\0';
		regs[rd] = (uintptr_t)dest;
		mstate->dtms_scratch_ptr += size;
		break;
	}

#ifdef illumos
	case DIF_SUBR_GETMAJOR:
#ifdef _LP64
		regs[rd] = (tupregs[0].dttk_value >> NBITSMINOR64) & MAXMAJ64;
#else
		regs[rd] = (tupregs[0].dttk_value >> NBITSMINOR) & MAXMAJ;
#endif
		break;

	case DIF_SUBR_GETMINOR:
#ifdef _LP64
		regs[rd] = tupregs[0].dttk_value & MAXMIN64;
#else
		regs[rd] = tupregs[0].dttk_value & MAXMIN;
#endif
		break;

	case DIF_SUBR_DDI_PATHNAME: {
		/*
		 * This one is a galactic mess.  We are going to roughly
		 * emulate ddi_pathname(), but it's made more complicated
		 * by the fact that we (a) want to include the minor name and
		 * (b) must proceed iteratively instead of recursively.
		 */
		uintptr_t dest = mstate->dtms_scratch_ptr;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		char *start = (char *)dest, *end = start + size - 1;
		uintptr_t daddr = tupregs[0].dttk_value;
		int64_t minor = (int64_t)tupregs[1].dttk_value;
		char *s;
		int i, len, depth = 0;

		/*
		 * Due to all the pointer jumping we do and context we must
		 * rely upon, we just mandate that the user must have kernel
		 * read privileges to use this routine.
		 */
		if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) == 0) {
			*flags |= CPU_DTRACE_KPRIV;
			*illval = daddr;
			regs[rd] = 0;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		*end = '\0';

		/*
		 * We want to have a name for the minor.  In order to do this,
		 * we need to walk the minor list from the devinfo.  We want
		 * to be sure that we don't infinitely walk a circular list,
		 * so we check for circularity by sending a scout pointer
		 * ahead two elements for every element that we iterate over;
		 * if the list is circular, these will ultimately point to the
		 * same element.  You may recognize this little trick as the
		 * answer to a stupid interview question -- one that always
		 * seems to be asked by those who had to have it laboriously
		 * explained to them, and who can't even concisely describe
		 * the conditions under which one would be forced to resort to
		 * this technique.  Needless to say, those conditions are
		 * found here -- and probably only here.  Is this the only use
		 * of this infamous trick in shipping, production code?  If it
		 * isn't, it probably should be...
		 */
		if (minor != -1) {
			uintptr_t maddr = dtrace_loadptr(daddr +
			    offsetof(struct dev_info, devi_minor));

			uintptr_t next = offsetof(struct ddi_minor_data, next);
			uintptr_t name = offsetof(struct ddi_minor_data,
			    d_minor) + offsetof(struct ddi_minor, name);
			uintptr_t dev = offsetof(struct ddi_minor_data,
			    d_minor) + offsetof(struct ddi_minor, dev);
			uintptr_t scout;

			if (maddr != NULL)
				scout = dtrace_loadptr(maddr + next);

			while (maddr != NULL && !(*flags & CPU_DTRACE_FAULT)) {
				uint64_t m;
#ifdef _LP64
				m = dtrace_load64(maddr + dev) & MAXMIN64;
#else
				m = dtrace_load32(maddr + dev) & MAXMIN;
#endif
				if (m != minor) {
					maddr = dtrace_loadptr(maddr + next);

					if (scout == NULL)
						continue;

					scout = dtrace_loadptr(scout + next);

					if (scout == NULL)
						continue;

					scout = dtrace_loadptr(scout + next);

					if (scout == NULL)
						continue;

					if (scout == maddr) {
						*flags |= CPU_DTRACE_ILLOP;
						break;
					}

					continue;
				}

				/*
				 * We have the minor data.  Now we need to
				 * copy the minor's name into the end of the
				 * pathname.
				 */
				s = (char *)dtrace_loadptr(maddr + name);
				len = dtrace_strlen(s, size);

				if (*flags & CPU_DTRACE_FAULT)
					break;

				if (len != 0) {
					if ((end -= (len + 1)) < start)
						break;

					*end = ':';
				}

				for (i = 1; i <= len; i++)
					end[i] = dtrace_load8((uintptr_t)s++);
				break;
			}
		}

		while (daddr != NULL && !(*flags & CPU_DTRACE_FAULT)) {
			ddi_node_state_t devi_state;

			devi_state = dtrace_load32(daddr +
			    offsetof(struct dev_info, devi_node_state));

			if (*flags & CPU_DTRACE_FAULT)
				break;

			if (devi_state >= DS_INITIALIZED) {
				s = (char *)dtrace_loadptr(daddr +
				    offsetof(struct dev_info, devi_addr));
				len = dtrace_strlen(s, size);

				if (*flags & CPU_DTRACE_FAULT)
					break;

				if (len != 0) {
					if ((end -= (len + 1)) < start)
						break;

					*end = '@';
				}

				for (i = 1; i <= len; i++)
					end[i] = dtrace_load8((uintptr_t)s++);
			}

			/*
			 * Now for the node name...
			 */
			s = (char *)dtrace_loadptr(daddr +
			    offsetof(struct dev_info, devi_node_name));

			daddr = dtrace_loadptr(daddr +
			    offsetof(struct dev_info, devi_parent));

			/*
			 * If our parent is NULL (that is, if we're the root
			 * node), we're going to use the special path
			 * "devices".
			 */
			if (daddr == 0)
				s = "devices";

			len = dtrace_strlen(s, size);
			if (*flags & CPU_DTRACE_FAULT)
				break;

			if ((end -= (len + 1)) < start)
				break;

			for (i = 1; i <= len; i++)
				end[i] = dtrace_load8((uintptr_t)s++);
			*end = '/';

			if (depth++ > dtrace_devdepth_max) {
				*flags |= CPU_DTRACE_ILLOP;
				break;
			}
		}

		if (end < start)
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);

		if (daddr == 0) {
			regs[rd] = (uintptr_t)end;
			mstate->dtms_scratch_ptr += size;
		}

		break;
	}
#endif

	case DIF_SUBR_STRJOIN: {
		char *d = (char *)mstate->dtms_scratch_ptr;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t s1 = tupregs[0].dttk_value;
		uintptr_t s2 = tupregs[1].dttk_value;
		int i = 0, j = 0;
		size_t lim1, lim2;
		char c;

		if (!dtrace_strcanload(s1, size, &lim1, mstate, vstate) ||
		    !dtrace_strcanload(s2, size, &lim2, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		for (;;) {
			if (i >= size) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}
			c = (i >= lim1) ? '\0' : dtrace_load8(s1++);
			if ((d[i++] = c) == '\0') {
				i--;
				break;
			}
		}

		for (;;) {
			if (i >= size) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}

			c = (j++ >= lim2) ? '\0' : dtrace_load8(s2++);
			if ((d[i++] = c) == '\0')
				break;
		}

		if (i < size) {
			mstate->dtms_scratch_ptr += i;
			regs[rd] = (uintptr_t)d;
		}

		break;
	}

	case DIF_SUBR_STRTOLL: {
		uintptr_t s = tupregs[0].dttk_value;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		size_t lim;
		int base = 10;

		if (nargs > 1) {
			if ((base = tupregs[1].dttk_value) <= 1 ||
			    base > ('z' - 'a' + 1) + ('9' - '0' + 1)) {
				*flags |= CPU_DTRACE_ILLOP;
				break;
			}
		}

		if (!dtrace_strcanload(s, size, &lim, mstate, vstate)) {
			regs[rd] = INT64_MIN;
			break;
		}

		regs[rd] = dtrace_strtoll((char *)s, base, lim);
		break;
	}

	case DIF_SUBR_LLTOSTR: {
		int64_t i = (int64_t)tupregs[0].dttk_value;
		uint64_t val, digit;
		uint64_t size = 65;	/* enough room for 2^64 in binary */
		char *end = (char *)mstate->dtms_scratch_ptr + size - 1;
		int base = 10;

		if (nargs > 1) {
			if ((base = tupregs[1].dttk_value) <= 1 ||
			    base > ('z' - 'a' + 1) + ('9' - '0' + 1)) {
				*flags |= CPU_DTRACE_ILLOP;
				break;
			}
		}

		val = (base == 10 && i < 0) ? i * -1 : i;

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		for (*end-- = '\0'; val; val /= base) {
			if ((digit = val % base) <= '9' - '0') {
				*end-- = '0' + digit;
			} else {
				*end-- = 'a' + (digit - ('9' - '0') - 1);
			}
		}

		if (i == 0 && base == 16)
			*end-- = '0';

		if (base == 16)
			*end-- = 'x';

		if (i == 0 || base == 8 || base == 16)
			*end-- = '0';

		if (i < 0 && base == 10)
			*end-- = '-';

		regs[rd] = (uintptr_t)end + 1;
		mstate->dtms_scratch_ptr += size;
		break;
	}

	case DIF_SUBR_HTONS:
	case DIF_SUBR_NTOHS:
#if BYTE_ORDER == BIG_ENDIAN
		regs[rd] = (uint16_t)tupregs[0].dttk_value;
#else
		regs[rd] = DT_BSWAP_16((uint16_t)tupregs[0].dttk_value);
#endif
		break;


	case DIF_SUBR_HTONL:
	case DIF_SUBR_NTOHL:
#if BYTE_ORDER == BIG_ENDIAN
		regs[rd] = (uint32_t)tupregs[0].dttk_value;
#else
		regs[rd] = DT_BSWAP_32((uint32_t)tupregs[0].dttk_value);
#endif
		break;


	case DIF_SUBR_HTONLL:
	case DIF_SUBR_NTOHLL:
#if BYTE_ORDER == BIG_ENDIAN
		regs[rd] = (uint64_t)tupregs[0].dttk_value;
#else
		regs[rd] = DT_BSWAP_64((uint64_t)tupregs[0].dttk_value);
#endif
		break;


	case DIF_SUBR_DIRNAME:
	case DIF_SUBR_BASENAME: {
		char *dest = (char *)mstate->dtms_scratch_ptr;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t src = tupregs[0].dttk_value;
		int i, j, len = dtrace_strlen((char *)src, size);
		int lastbase = -1, firstbase = -1, lastdir = -1;
		int start, end;

		if (!dtrace_canload(src, len + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		/*
		 * The basename and dirname for a zero-length string is
		 * defined to be "."
		 */
		if (len == 0) {
			len = 1;
			src = (uintptr_t)".";
		}

		/*
		 * Start from the back of the string, moving back toward the
		 * front until we see a character that isn't a slash.  That
		 * character is the last character in the basename.
		 */
		for (i = len - 1; i >= 0; i--) {
			if (dtrace_load8(src + i) != '/')
				break;
		}

		if (i >= 0)
			lastbase = i;

		/*
		 * Starting from the last character in the basename, move
		 * towards the front until we find a slash.  The character
		 * that we processed immediately before that is the first
		 * character in the basename.
		 */
		for (; i >= 0; i--) {
			if (dtrace_load8(src + i) == '/')
				break;
		}

		if (i >= 0)
			firstbase = i + 1;

		/*
		 * Now keep going until we find a non-slash character.  That
		 * character is the last character in the dirname.
		 */
		for (; i >= 0; i--) {
			if (dtrace_load8(src + i) != '/')
				break;
		}

		if (i >= 0)
			lastdir = i;

		ASSERT(!(lastbase == -1 && firstbase != -1));
		ASSERT(!(firstbase == -1 && lastdir != -1));

		if (lastbase == -1) {
			/*
			 * We didn't find a non-slash character.  We know that
			 * the length is non-zero, so the whole string must be
			 * slashes.  In either the dirname or the basename
			 * case, we return '/'.
			 */
			ASSERT(firstbase == -1);
			firstbase = lastbase = lastdir = 0;
		}

		if (firstbase == -1) {
			/*
			 * The entire string consists only of a basename
			 * component.  If we're looking for dirname, we need
			 * to change our string to be just "."; if we're
			 * looking for a basename, we'll just set the first
			 * character of the basename to be 0.
			 */
			if (subr == DIF_SUBR_DIRNAME) {
				ASSERT(lastdir == -1);
				src = (uintptr_t)".";
				lastdir = 0;
			} else {
				firstbase = 0;
			}
		}

		if (subr == DIF_SUBR_DIRNAME) {
			if (lastdir == -1) {
				/*
				 * We know that we have a slash in the name --
				 * or lastdir would be set to 0, above.  And
				 * because lastdir is -1, we know that this
				 * slash must be the first character.  (That
				 * is, the full string must be of the form
				 * "/basename".)  In this case, the last
				 * character of the directory name is 0.
				 */
				lastdir = 0;
			}

			start = 0;
			end = lastdir;
		} else {
			ASSERT(subr == DIF_SUBR_BASENAME);
			ASSERT(firstbase != -1 && lastbase != -1);
			start = firstbase;
			end = lastbase;
		}

		for (i = start, j = 0; i <= end && j < size - 1; i++, j++)
			dest[j] = dtrace_load8(src + i);

		dest[j] = '\0';
		regs[rd] = (uintptr_t)dest;
		mstate->dtms_scratch_ptr += size;
		break;
	}

	/*
	 * FIXME: We want this.
	 */
#if 0
	case DIF_SUBR_GETF: {
		uintptr_t fd = tupregs[0].dttk_value;
		struct filedesc *fdp;
		file_t *fp;

		if (!dtrace_priv_proc(state)) {
			regs[rd] = 0;
			break;
		}
		fdp = curproc->p_fd;
		FILEDESC_SLOCK(fdp);
		fp = fget_locked(fdp, fd);
		mstate->dtms_getf = fp;
		regs[rd] = (uintptr_t)fp;
		FILEDESC_SUNLOCK(fdp);
		break;
	}
#endif

	case DIF_SUBR_CLEANPATH: {
		char *dest = (char *)mstate->dtms_scratch_ptr, c;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t src = tupregs[0].dttk_value;
		size_t lim;
		int i = 0, j = 0;
#ifdef illumos
		zone_t *z;
#endif

		if (!dtrace_strcanload(src, size, &lim, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		/*
		 * Move forward, loading each character.
		 */
		do {
			c = (i >= lim) ? '\0' : dtrace_load8(src + i++);
next:
			if (j + 5 >= size)	/* 5 = strlen("/..c\0") */
				break;

			if (c != '/') {
				dest[j++] = c;
				continue;
			}

			c = (i >= lim) ? '\0' : dtrace_load8(src + i++);

			if (c == '/') {
				/*
				 * We have two slashes -- we can just advance
				 * to the next character.
				 */
				goto next;
			}

			if (c != '.') {
				/*
				 * This is not "." and it's not ".." -- we can
				 * just store the "/" and this character and
				 * drive on.
				 */
				dest[j++] = '/';
				dest[j++] = c;
				continue;
			}

			c = (i >= lim) ? '\0' : dtrace_load8(src + i++);

			if (c == '/') {
				/*
				 * This is a "/./" component.  We're not going
				 * to store anything in the destination buffer;
				 * we're just going to go to the next component.
				 */
				goto next;
			}

			if (c != '.') {
				/*
				 * This is not ".." -- we can just store the
				 * "/." and this character and continue
				 * processing.
				 */
				dest[j++] = '/';
				dest[j++] = '.';
				dest[j++] = c;
				continue;
			}

			c = (i >= lim) ? '\0' : dtrace_load8(src + i++);

			if (c != '/' && c != '\0') {
				/*
				 * This is not ".." -- it's "..[mumble]".
				 * We'll store the "/.." and this character
				 * and continue processing.
				 */
				dest[j++] = '/';
				dest[j++] = '.';
				dest[j++] = '.';
				dest[j++] = c;
				continue;
			}

			/*
			 * This is "/../" or "/..\0".  We need to back up
			 * our destination pointer until we find a "/".
			 */
			i--;
			while (j != 0 && dest[--j] != '/')
				continue;

			if (c == '\0')
				dest[++j] = '/';
		} while (c != '\0');

		dest[j] = '\0';

#ifdef illumos
		if (mstate->dtms_getf != NULL &&
		    !(mstate->dtms_access & DTRACE_ACCESS_KERNEL) &&
		    (z = state->dts_cred.dcr_cred->cr_zone) != kcred->cr_zone) {
			/*
			 * If we've done a getf() as a part of this ECB and we
			 * don't have kernel access (and we're not in the global
			 * zone), check if the path we cleaned up begins with
			 * the zone's root path, and trim it off if so.  Note
			 * that this is an output cleanliness issue, not a
			 * security issue: knowing one's zone root path does
			 * not enable privilege escalation.
			 */
			if (strstr(dest, z->zone_rootpath) == dest)
				dest += strlen(z->zone_rootpath) - 1;
		}
#endif

		regs[rd] = (uintptr_t)dest;
		mstate->dtms_scratch_ptr += size;
		break;
	}

	/*
	 * FIXME: We want to handle this -- but not yet. Too difficult to get to
	 * compile.
	 */
#if 0
	case DIF_SUBR_INET_NTOA:
	case DIF_SUBR_INET_NTOA6:
	case DIF_SUBR_INET_NTOP: {
		size_t size;
		int af, argi, i;
		char *base, *end;

		if (subr == DIF_SUBR_INET_NTOP) {
			af = (int)tupregs[0].dttk_value;
			argi = 1;
		} else {
			af = subr == DIF_SUBR_INET_NTOA ? AF_INET: AF_INET6;
			argi = 0;
		}

		if (af == AF_INET) {
			ipaddr_t ip4;
			uint8_t *ptr8, val;

			if (!dtrace_canload(tupregs[argi].dttk_value,
			    sizeof (ipaddr_t), mstate, vstate)) {
				regs[rd] = 0;
				break;
			}

			/*
			 * Safely load the IPv4 address.
			 */
			ip4 = dtrace_load32(tupregs[argi].dttk_value);

			/*
			 * Check an IPv4 string will fit in scratch.
			 */
			size = INET_ADDRSTRLEN;
			if (!DTRACE_INSCRATCH(mstate, size)) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}
			base = (char *)mstate->dtms_scratch_ptr;
			end = (char *)mstate->dtms_scratch_ptr + size - 1;

			/*
			 * Stringify as a dotted decimal quad.
			 */
			*end-- = '\0';
			ptr8 = (uint8_t *)&ip4;
			for (i = 3; i >= 0; i--) {
				val = ptr8[i];

				if (val == 0) {
					*end-- = '0';
				} else {
					for (; val; val /= 10) {
						*end-- = '0' + (val % 10);
					}
				}

				if (i > 0)
					*end-- = '.';
			}
			ASSERT(end + 1 >= base);

		} else if (af == AF_INET6) {
			struct in6_addr ip6;
			int firstzero, tryzero, numzero, v6end;
			uint16_t val;
			const char digits[] = "0123456789abcdef";

			/*
			 * Stringify using RFC 1884 convention 2 - 16 bit
			 * hexadecimal values with a zero-run compression.
			 * Lower case hexadecimal digits are used.
			 * 	eg, fe80::214:4fff:fe0b:76c8.
			 * The IPv4 embedded form is returned for inet_ntop,
			 * just the IPv4 string is returned for inet_ntoa6.
			 */

			if (!dtrace_canload(tupregs[argi].dttk_value,
			    sizeof (struct in6_addr), mstate, vstate)) {
				regs[rd] = 0;
				break;
			}

			/*
			 * Safely load the IPv6 address.
			 */
			dtrace_bcopy(
			    (void *)(uintptr_t)tupregs[argi].dttk_value,
			    (void *)(uintptr_t)&ip6, sizeof (struct in6_addr));

			/*
			 * Check an IPv6 string will fit in scratch.
			 */
			size = INET6_ADDRSTRLEN;
			if (!DTRACE_INSCRATCH(mstate, size)) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}
			base = (char *)mstate->dtms_scratch_ptr;
			end = (char *)mstate->dtms_scratch_ptr + size - 1;
			*end-- = '\0';

			/*
			 * Find the longest run of 16 bit zero values
			 * for the single allowed zero compression - "::".
			 */
			firstzero = -1;
			tryzero = -1;
			numzero = 1;
			for (i = 0; i < sizeof (struct in6_addr); i++) {
#ifdef illumos
				if (ip6._S6_un._S6_u8[i] == 0 &&
#else
				if (ip6.__u6_addr.__u6_addr8[i] == 0 &&
#endif
				    tryzero == -1 && i % 2 == 0) {
					tryzero = i;
					continue;
				}

				if (tryzero != -1 &&
#ifdef illumos
				    (ip6._S6_un._S6_u8[i] != 0 ||
#else
				    (ip6.__u6_addr.__u6_addr8[i] != 0 ||
#endif
				    i == sizeof (struct in6_addr) - 1)) {

					if (i - tryzero <= numzero) {
						tryzero = -1;
						continue;
					}

					firstzero = tryzero;
					numzero = i - i % 2 - tryzero;
					tryzero = -1;

#ifdef illumos
					if (ip6._S6_un._S6_u8[i] == 0 &&
#else
					if (ip6.__u6_addr.__u6_addr8[i] == 0 &&
#endif
					    i == sizeof (struct in6_addr) - 1)
						numzero += 2;
				}
			}
			ASSERT(firstzero + numzero <= sizeof (struct in6_addr));

			/*
			 * Check for an IPv4 embedded address.
			 */
			v6end = sizeof (struct in6_addr) - 2;
			if (IN6_IS_ADDR_V4MAPPED(&ip6) ||
			    IN6_IS_ADDR_V4COMPAT(&ip6)) {
				for (i = sizeof (struct in6_addr) - 1;
				    i >= DTRACE_V4MAPPED_OFFSET; i--) {
					ASSERT(end >= base);

#ifdef illumos
					val = ip6._S6_un._S6_u8[i];
#else
					val = ip6.__u6_addr.__u6_addr8[i];
#endif

					if (val == 0) {
						*end-- = '0';
					} else {
						for (; val; val /= 10) {
							*end-- = '0' + val % 10;
						}
					}

					if (i > DTRACE_V4MAPPED_OFFSET)
						*end-- = '.';
				}

				if (subr == DIF_SUBR_INET_NTOA6)
					goto inetout;

				/*
				 * Set v6end to skip the IPv4 address that
				 * we have already stringified.
				 */
				v6end = 10;
			}

			/*
			 * Build the IPv6 string by working through the
			 * address in reverse.
			 */
			for (i = v6end; i >= 0; i -= 2) {
				ASSERT(end >= base);

				if (i == firstzero + numzero - 2) {
					*end-- = ':';
					*end-- = ':';
					i -= numzero - 2;
					continue;
				}

				if (i < 14 && i != firstzero - 2)
					*end-- = ':';

#ifdef illumos
				val = (ip6._S6_un._S6_u8[i] << 8) +
				    ip6._S6_un._S6_u8[i + 1];
#else
				val = (ip6.__u6_addr.__u6_addr8[i] << 8) +
				    ip6.__u6_addr.__u6_addr8[i + 1];
#endif

				if (val == 0) {
					*end-- = '0';
				} else {
					for (; val; val /= 16) {
						*end-- = digits[val % 16];
					}
				}
			}
			ASSERT(end + 1 >= base);

		} else {
			/*
			 * The user didn't use AH_INET or AH_INET6.
			 */
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			regs[rd] = 0;
			break;
		}

inetout:	regs[rd] = (uintptr_t)end + 1;
		mstate->dtms_scratch_ptr += size;
		break;
	}
#endif

	case DIF_SUBR_MEMREF: {
		uintptr_t size = 2 * sizeof(uintptr_t);
		uintptr_t *memref = (uintptr_t *) P2ROUNDUP(mstate->dtms_scratch_ptr, sizeof(uintptr_t));
		size_t scratch_size = ((uintptr_t) memref - mstate->dtms_scratch_ptr) + size;

		/* address and length */
		memref[0] = tupregs[0].dttk_value;
		memref[1] = tupregs[1].dttk_value;

		regs[rd] = (uintptr_t) memref;
		mstate->dtms_scratch_ptr += scratch_size;
		break;
	}

#if 0
#ifndef illumos
	case DIF_SUBR_MEMSTR: {
		char *str = (char *)mstate->dtms_scratch_ptr;
		uintptr_t mem = tupregs[0].dttk_value;
		char c = tupregs[1].dttk_value;
		size_t size = tupregs[2].dttk_value;
		uint8_t n;
		int i;

		regs[rd] = 0;

		if (size == 0)
			break;

		if (!dtrace_canload(mem, size - 1, mstate, vstate))
			break;

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			break;
		}

		if (dtrace_memstr_max != 0 && size > dtrace_memstr_max) {
			*flags |= CPU_DTRACE_ILLOP;
			break;
		}

		for (i = 0; i < size - 1; i++) {
			n = dtrace_load8(mem++);
			str[i] = (n == 0) ? c : n;
		}
		str[size - 1] = 0;

		regs[rd] = (uintptr_t)str;
		mstate->dtms_scratch_ptr += size;
		break;
	}
#endif
#endif
	}
}

/*
 * Emulate the execution of DTrace IR instructions specified by the given
 * DIF object.  This function is deliberately void of assertions as all of
 * the necessary checks are handled by a call to dtrace_difo_validate().
 */
static uint64_t
dtrace_dif_emulate(dtrace_difo_t *difo, dtrace_mstate_t *mstate,
    dtrace_vstate_t *vstate, dtrace_state_t *state)
{
	const dif_instr_t *text = difo->dtdo_buf;
	const uint_t textlen = difo->dtdo_len;
	const char *strtab = difo->dtdo_strtab;
	const uint64_t *inttab = difo->dtdo_inttab;

	uint64_t rval = 0;
	dtrace_statvar_t *svar;
	dtrace_dstate_t *dstate = &vstate->dtvs_dynvars;
	dtrace_difv_t *v;
	volatile uint16_t *flags = &cpuc_dtrace_flags;
	volatile uintptr_t *illval = &cpuc_dtrace_illval;

	dtrace_key_t tupregs[DIF_DTR_NREGS + 2]; /* +2 for thread and id */
	uint64_t regs[DIF_DIR_NREGS];
	uint64_t *tmp;

	uint8_t cc_n = 0, cc_z = 0, cc_v = 0, cc_c = 0;
	int64_t cc_r;
	uint_t pc = 0, id, opc = 0;
	uint8_t ttop = 0;
	dif_instr_t instr;
	uint_t r1, r2, rd;

	/*
	 * We stash the current DIF object into the machine state: we need it
	 * for subsequent access checking.
	 */
	mstate->dtms_difo = difo;

	regs[DIF_REG_R0] = 0; 		/* %r0 is fixed at zero */

	while (pc < textlen && !(*flags & CPU_DTRACE_FAULT)) {
		opc = pc;

		instr = text[pc++];
		r1 = DIF_INSTR_R1(instr);
		r2 = DIF_INSTR_R2(instr);
		rd = DIF_INSTR_RD(instr);

		switch (DIF_INSTR_OP(instr)) {
		case DIF_OP_OR:
			regs[rd] = regs[r1] | regs[r2];
			break;
		case DIF_OP_XOR:
			regs[rd] = regs[r1] ^ regs[r2];
			break;
		case DIF_OP_AND:
			regs[rd] = regs[r1] & regs[r2];
			break;
		case DIF_OP_SLL:
			regs[rd] = regs[r1] << regs[r2];
			break;
		case DIF_OP_SRL:
			regs[rd] = regs[r1] >> regs[r2];
			break;
		case DIF_OP_SUB:
			regs[rd] = regs[r1] - regs[r2];
			break;
		case DIF_OP_ADD:
			regs[rd] = regs[r1] + regs[r2];
			break;
		case DIF_OP_MUL:
			regs[rd] = regs[r1] * regs[r2];
			break;
		case DIF_OP_SDIV:
			if (regs[r2] == 0) {
				regs[rd] = 0;
				*flags |= CPU_DTRACE_DIVZERO;
			} else {
				regs[rd] = (int64_t)regs[r1] /
				    (int64_t)regs[r2];
			}
			break;

		case DIF_OP_UDIV:
			if (regs[r2] == 0) {
				regs[rd] = 0;
				*flags |= CPU_DTRACE_DIVZERO;
			} else {
				regs[rd] = regs[r1] / regs[r2];
			}
			break;

		case DIF_OP_SREM:
			if (regs[r2] == 0) {
				regs[rd] = 0;
				*flags |= CPU_DTRACE_DIVZERO;
			} else {
				regs[rd] = (int64_t)regs[r1] %
				    (int64_t)regs[r2];
			}
			break;

		case DIF_OP_UREM:
			if (regs[r2] == 0) {
				regs[rd] = 0;
				*flags |= CPU_DTRACE_DIVZERO;
			} else {
				regs[rd] = regs[r1] % regs[r2];
			}
			break;

		case DIF_OP_NOT:
			regs[rd] = ~regs[r1];
			break;
		case DIF_OP_MOV:
			regs[rd] = regs[r1];
			break;
		case DIF_OP_CMP:
			cc_r = regs[r1] - regs[r2];
			cc_n = cc_r < 0;
			cc_z = cc_r == 0;
			cc_v = 0;
			cc_c = regs[r1] < regs[r2];
			break;
		case DIF_OP_TST:
			cc_n = cc_v = cc_c = 0;
			cc_z = regs[r1] == 0;
			break;
		case DIF_OP_BA:
			pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BE:
			if (cc_z)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BNE:
			if (cc_z == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BG:
			if ((cc_z | (cc_n ^ cc_v)) == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BGU:
			if ((cc_c | cc_z) == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BGE:
			if ((cc_n ^ cc_v) == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BGEU:
			if (cc_c == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BL:
			if (cc_n ^ cc_v)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BLU:
			if (cc_c)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BLE:
			if (cc_z | (cc_n ^ cc_v))
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BLEU:
			if (cc_c | cc_z)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_RLDSB:
			if (!dtrace_canload(regs[r1], 1, mstate, vstate))
				break;
			/*FALLTHROUGH*/
		case DIF_OP_LDSB:
			regs[rd] = (int8_t)dtrace_load8(regs[r1]);
			break;
		case DIF_OP_RLDSH:
			if (!dtrace_canload(regs[r1], 2, mstate, vstate))
				break;
			/*FALLTHROUGH*/
		case DIF_OP_LDSH:
			regs[rd] = (int16_t)dtrace_load16(regs[r1]);
			break;
		case DIF_OP_RLDSW:
			if (!dtrace_canload(regs[r1], 4, mstate, vstate))
				break;
			/*FALLTHROUGH*/
		case DIF_OP_LDSW:
			regs[rd] = (int32_t)dtrace_load32(regs[r1]);
			break;
		case DIF_OP_RLDUB:
			if (!dtrace_canload(regs[r1], 1, mstate, vstate))
				break;
			/*FALLTHROUGH*/
		case DIF_OP_LDUB:
			regs[rd] = dtrace_load8(regs[r1]);
			break;
		case DIF_OP_RLDUH:
			if (!dtrace_canload(regs[r1], 2, mstate, vstate))
				break;
			/*FALLTHROUGH*/
		case DIF_OP_LDUH:
			regs[rd] = dtrace_load16(regs[r1]);
			break;
		case DIF_OP_RLDUW:
			if (!dtrace_canload(regs[r1], 4, mstate, vstate))
				break;
			/*FALLTHROUGH*/
		case DIF_OP_LDUW:
			regs[rd] = dtrace_load32(regs[r1]);
			break;
		case DIF_OP_RLDX:
			if (!dtrace_canload(regs[r1], 8, mstate, vstate))
				break;
			/*FALLTHROUGH*/
		case DIF_OP_LDX:
			regs[rd] = dtrace_load64(regs[r1]);
			break;
		case DIF_OP_ULDSB:
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			regs[rd] = (int8_t)
			    dtrace_fuword8((void *)(uintptr_t)regs[r1]);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
			break;
		case DIF_OP_ULDSH:
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			regs[rd] = (int16_t)
			    dtrace_fuword16((void *)(uintptr_t)regs[r1]);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
			break;
		case DIF_OP_ULDSW:
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			regs[rd] = (int32_t)
			    dtrace_fuword32((void *)(uintptr_t)regs[r1]);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
			break;
		case DIF_OP_ULDUB:
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			regs[rd] =
			    dtrace_fuword8((void *)(uintptr_t)regs[r1]);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
			break;
		case DIF_OP_ULDUH:
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			regs[rd] =
			    dtrace_fuword16((void *)(uintptr_t)regs[r1]);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
			break;
		case DIF_OP_ULDUW:
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			regs[rd] =
			    dtrace_fuword32((void *)(uintptr_t)regs[r1]);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
			break;
		case DIF_OP_ULDX:
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			regs[rd] =
			    dtrace_fuword64((void *)(uintptr_t)regs[r1]);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
			break;
		case DIF_OP_RET:
			rval = regs[rd];
			pc = textlen;
			break;
		case DIF_OP_NOP:
			break;
		case DIF_OP_SETX:
			regs[rd] = inttab[DIF_INSTR_INTEGER(instr)];
			break;
		case DIF_OP_SETS:
			regs[rd] = (uint64_t)(uintptr_t)
			    (strtab + DIF_INSTR_STRING(instr));
			break;
		case DIF_OP_SCMP: {
			size_t sz = state->dts_options[DTRACEOPT_STRSIZE];
			uintptr_t s1 = regs[r1];
			uintptr_t s2 = regs[r2];
			size_t lim1, lim2;

			if (s1 != 0 &&
			    !dtrace_strcanload(s1, sz, &lim1, mstate, vstate))
				break;
			if (s2 != 0 &&
			    !dtrace_strcanload(s2, sz, &lim2, mstate, vstate))
				break;

			cc_r = dtrace_strncmp((char *)s1, (char *)s2,
			    MIN(lim1, lim2));

			cc_n = cc_r < 0;
			cc_z = cc_r == 0;
			cc_v = cc_c = 0;
			break;
		}
		case DIF_OP_LDGA:
			regs[rd] = dtrace_dif_variable(mstate, state,
			    r1, regs[r2]);
			break;
		case DIF_OP_LDGS:
			id = DIF_INSTR_VAR(instr);

			if (id >= DIF_VAR_OTHER_UBASE) {
				uintptr_t a;

				id -= DIF_VAR_OTHER_UBASE;
				svar = vstate->dtvs_globals[id];
				assert(svar != NULL);
				v = &svar->dtsv_var;

				if (!(v->dtdv_type.dtdt_flags & DIF_TF_BYREF)) {
					regs[rd] = svar->dtsv_data;
					break;
				}

				a = (uintptr_t)svar->dtsv_data;

				if (*(uint8_t *)a == UINT8_MAX) {
					/*
					 * If the 0th byte is set to UINT8_MAX
					 * then this is to be treated as a
					 * reference to a NULL variable.
					 */
					regs[rd] = 0;
				} else {
					regs[rd] = a + sizeof (uint64_t);
				}

				break;
			}

			regs[rd] = dtrace_dif_variable(mstate, state, id, 0);
			break;

		case DIF_OP_STGS:
			id = DIF_INSTR_VAR(instr);

			assert(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;

			VERIFY(id < vstate->dtvs_nglobals);
			svar = vstate->dtvs_globals[id];
			assert(svar != NULL);
			v = &svar->dtsv_var;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t a = (uintptr_t)svar->dtsv_data;
				size_t lim;

				assert(a != 0);
				assert(svar->dtsv_size != 0);

				if (regs[rd] == 0) {
					*(uint8_t *)a = UINT8_MAX;
					break;
				} else {
					*(uint8_t *)a = 0;
					a += sizeof (uint64_t);
				}
				if (!dtrace_vcanload(
				    (void *)(uintptr_t)regs[rd], &v->dtdv_type,
				    &lim, mstate, vstate))
					break;

				dtrace_vcopy((void *)(uintptr_t)regs[rd],
				    (void *)a, &v->dtdv_type, lim);
				break;
			}

			svar->dtsv_data = regs[rd];
			break;

		case DIF_OP_LDTA:
			/*
			 * There are no DTrace built-in thread-local arrays at
			 * present.  This opcode is saved for future work.
			 */
			*flags |= CPU_DTRACE_ILLOP;
			regs[rd] = 0;
			break;

		case DIF_OP_LDLS:
			id = DIF_INSTR_VAR(instr);

			if (id < DIF_VAR_OTHER_UBASE) {
				/*
				 * For now, this has no meaning.
				 */
				regs[rd] = 0;
				break;
			}

			id -= DIF_VAR_OTHER_UBASE;

			assert(id < vstate->dtvs_nlocals);
			assert(vstate->dtvs_locals != NULL);

			svar = vstate->dtvs_locals[id];
			assert(svar != NULL);
			v = &svar->dtsv_var;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t a = (uintptr_t)svar->dtsv_data;
				size_t sz = v->dtdv_type.dtdt_size;
				size_t lim;

				sz += sizeof (uint64_t);
				assert(svar->dtsv_size == NCPU * sz);
				a += curcpu * sz;

				if (*(uint8_t *)a == UINT8_MAX) {
					/*
					 * If the 0th byte is set to UINT8_MAX
					 * then this is to be treated as a
					 * reference to a NULL variable.
					 */
					regs[rd] = 0;
				} else {
					regs[rd] = a + sizeof (uint64_t);
				}

				break;
			}

			assert(svar->dtsv_size == NCPU * sizeof (uint64_t));
			tmp = (uint64_t *)(uintptr_t)svar->dtsv_data;
			regs[rd] = tmp[curcpu];
			break;

		case DIF_OP_STLS:
			id = DIF_INSTR_VAR(instr);

			assert(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;
			VERIFY(id < vstate->dtvs_nlocals);

			assert(vstate->dtvs_locals != NULL);
			svar = vstate->dtvs_locals[id];
			assert(svar != NULL);
			v = &svar->dtsv_var;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t a = (uintptr_t)svar->dtsv_data;
				size_t sz = v->dtdv_type.dtdt_size;
				size_t lim;

				sz += sizeof (uint64_t);
				assert(svar->dtsv_size == NCPU * sz);
				a += curcpu * sz;

				if (regs[rd] == 0) {
					*(uint8_t *)a = UINT8_MAX;
					break;
				} else {
					*(uint8_t *)a = 0;
					a += sizeof (uint64_t);
				}

				if (!dtrace_vcanload(
				    (void *)(uintptr_t)regs[rd], &v->dtdv_type,
				    &lim, mstate, vstate))
					break;

				dtrace_vcopy((void *)(uintptr_t)regs[rd],
				    (void *)a, &v->dtdv_type, lim);
				break;
			}

			assert(svar->dtsv_size == NCPU * sizeof (uint64_t));
			tmp = (uint64_t *)(uintptr_t)svar->dtsv_data;
			tmp[curcpu] = regs[rd];
			break;

		case DIF_OP_LDTS: {
			dtrace_dynvar_t *dvar;
			dtrace_key_t *key;

			id = DIF_INSTR_VAR(instr);
			assert(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;
			v = &vstate->dtvs_tlocals[id];

			key = &tupregs[DIF_DTR_NREGS];
			key[0].dttk_value = (uint64_t)id;
			key[0].dttk_size = 0;
			/*
			 * XXX: What are thread-local variables here?
			 */
#if 0
			DTRACE_TLS_THRKEY(key[1].dttk_value);
#endif
			key[1].dttk_size = 0;

			dvar = dtrace_dynvar(dstate, 2, key,
			    sizeof (uint64_t), DTRACE_DYNVAR_NOALLOC,
			    mstate, vstate);

			if (dvar == NULL) {
				regs[rd] = 0;
				break;
			}

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				regs[rd] = (uint64_t)(uintptr_t)dvar->dtdv_data;
			} else {
				regs[rd] = *((uint64_t *)dvar->dtdv_data);
			}

			break;
		}

		case DIF_OP_STTS: {
			dtrace_dynvar_t *dvar;
			dtrace_key_t *key;

			id = DIF_INSTR_VAR(instr);
			assert(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;
			VERIFY(id < vstate->dtvs_ntlocals);

			key = &tupregs[DIF_DTR_NREGS];
			key[0].dttk_value = (uint64_t)id;
			key[0].dttk_size = 0;
			/*
			 * XXX: What are thread local variables here?
			 */
#if 0
			DTRACE_TLS_THRKEY(key[1].dttk_value);
#endif
			key[1].dttk_size = 0;
			v = &vstate->dtvs_tlocals[id];

			dvar = dtrace_dynvar(dstate, 2, key,
			    v->dtdv_type.dtdt_size > sizeof (uint64_t) ?
			    v->dtdv_type.dtdt_size : sizeof (uint64_t),
			    regs[rd] ? DTRACE_DYNVAR_ALLOC :
			    DTRACE_DYNVAR_DEALLOC, mstate, vstate);

			/*
			 * Given that we're storing to thread-local data,
			 * we need to flush our predicate cache.
			 */
			predcache = 0;

			if (dvar == NULL)
				break;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				size_t lim;

				if (!dtrace_vcanload(
				    (void *)(uintptr_t)regs[rd],
				    &v->dtdv_type, &lim, mstate, vstate))
					break;

				dtrace_vcopy((void *)(uintptr_t)regs[rd],
				    dvar->dtdv_data, &v->dtdv_type, lim);
			} else {
				*((uint64_t *)dvar->dtdv_data) = regs[rd];
			}

			break;
		}

		case DIF_OP_SRA:
			regs[rd] = (int64_t)regs[r1] >> regs[r2];
			break;

		case DIF_OP_CALL:
			dtrace_dif_subr(DIF_INSTR_SUBR(instr), rd,
			    regs, tupregs, ttop, mstate, state);
			break;

		case DIF_OP_PUSHTR:
			if (ttop == DIF_DTR_NREGS) {
				*flags |= CPU_DTRACE_TUPOFLOW;
				break;
			}

			if (r1 == DIF_TYPE_STRING) {
				/*
				 * If this is a string type and the size is 0,
				 * we'll use the system-wide default string
				 * size.  Note that we are _not_ looking at
				 * the value of the DTRACEOPT_STRSIZE option;
				 * had this been set, we would expect to have
				 * a non-zero size value in the "pushtr".
				 */
				tupregs[ttop].dttk_size =
				    dtrace_strlen((char *)(uintptr_t)regs[rd],
				    regs[r2] ? regs[r2] :
				    dtrace_strsize_default) + 1;
			} else {
				if (regs[r2] > LONG_MAX) {
					*flags |= CPU_DTRACE_ILLOP;
					break;
				}

				tupregs[ttop].dttk_size = regs[r2];
			}

			tupregs[ttop++].dttk_value = regs[rd];
			break;

		case DIF_OP_PUSHTV:
			if (ttop == DIF_DTR_NREGS) {
				*flags |= CPU_DTRACE_TUPOFLOW;
				break;
			}

			tupregs[ttop].dttk_value = regs[rd];
			tupregs[ttop++].dttk_size = 0;
			break;

		case DIF_OP_POPTS:
			if (ttop != 0)
				ttop--;
			break;

		case DIF_OP_FLUSHTS:
			ttop = 0;
			break;

#if 0
		case DIF_OP_LDGAA:
		case DIF_OP_LDTAA: {
			dtrace_dynvar_t *dvar;
			dtrace_key_t *key = tupregs;
			uint_t nkeys = ttop;

			id = DIF_INSTR_VAR(instr);
			assert(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;

			key[nkeys].dttk_value = (uint64_t)id;
			key[nkeys++].dttk_size = 0;

			if (DIF_INSTR_OP(instr) == DIF_OP_LDTAA) {
				DTRACE_TLS_THRKEY(key[nkeys].dttk_value);
				key[nkeys++].dttk_size = 0;
				VERIFY(id < vstate->dtvs_ntlocals);
				v = &vstate->dtvs_tlocals[id];
			} else {
				VERIFY(id < vstate->dtvs_nglobals);
				v = &vstate->dtvs_globals[id]->dtsv_var;
			}

			dvar = dtrace_dynvar(dstate, nkeys, key,
			    v->dtdv_type.dtdt_size > sizeof (uint64_t) ?
			    v->dtdv_type.dtdt_size : sizeof (uint64_t),
			    DTRACE_DYNVAR_NOALLOC, mstate, vstate);

			if (dvar == NULL) {
				regs[rd] = 0;
				break;
			}

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				regs[rd] = (uint64_t)(uintptr_t)dvar->dtdv_data;
			} else {
				regs[rd] = *((uint64_t *)dvar->dtdv_data);
			}

			break;
		}
#endif

#if 0
		case DIF_OP_STGAA:
		case DIF_OP_STTAA: {
			dtrace_dynvar_t *dvar;
			dtrace_key_t *key = tupregs;
			uint_t nkeys = ttop;

			id = DIF_INSTR_VAR(instr);
			assert(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;

			key[nkeys].dttk_value = (uint64_t)id;
			key[nkeys++].dttk_size = 0;

			if (DIF_INSTR_OP(instr) == DIF_OP_STTAA) {
				DTRACE_TLS_THRKEY(key[nkeys].dttk_value);
				key[nkeys++].dttk_size = 0;
				VERIFY(id < vstate->dtvs_ntlocals);
				v = &vstate->dtvs_tlocals[id];
			} else {
				VERIFY(id < vstate->dtvs_nglobals);
				v = &vstate->dtvs_globals[id]->dtsv_var;
			}

			dvar = dtrace_dynvar(dstate, nkeys, key,
			    v->dtdv_type.dtdt_size > sizeof (uint64_t) ?
			    v->dtdv_type.dtdt_size : sizeof (uint64_t),
			    regs[rd] ? DTRACE_DYNVAR_ALLOC :
			    DTRACE_DYNVAR_DEALLOC, mstate, vstate);

			if (dvar == NULL)
				break;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				size_t lim;

				if (!dtrace_vcanload(
				    (void *)(uintptr_t)regs[rd], &v->dtdv_type,
				    &lim, mstate, vstate))
					break;

				dtrace_vcopy((void *)(uintptr_t)regs[rd],
				    dvar->dtdv_data, &v->dtdv_type, lim);
			} else {
				*((uint64_t *)dvar->dtdv_data) = regs[rd];
			}

			break;
		}
#endif

		case DIF_OP_ALLOCS: {
			uintptr_t ptr = P2ROUNDUP(mstate->dtms_scratch_ptr, 8);
			size_t size = ptr - mstate->dtms_scratch_ptr + regs[r1];

			/*
			 * Rounding up the user allocation size could have
			 * overflowed large, bogus allocations (like -1ULL) to
			 * 0.
			 */
			if (size < regs[r1] ||
			    !DTRACE_INSCRATCH(mstate, size)) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}

			dtrace_bzero((void *) mstate->dtms_scratch_ptr, size);
			mstate->dtms_scratch_ptr += size;
			regs[rd] = ptr;
			break;
		}

		case DIF_OP_COPYS:
			if (!dtrace_canstore(regs[rd], regs[r2],
			    mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}

			if (!dtrace_canload(regs[r1], regs[r2], mstate, vstate))
				break;

			dtrace_bcopy((void *)(uintptr_t)regs[r1],
			    (void *)(uintptr_t)regs[rd], (size_t)regs[r2]);
			break;

		case DIF_OP_STB:
			if (!dtrace_canstore(regs[rd], 1, mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}
			*((uint8_t *)(uintptr_t)regs[rd]) = (uint8_t)regs[r1];
			break;

		case DIF_OP_STH:
			if (!dtrace_canstore(regs[rd], 2, mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}
			if (regs[rd] & 1) {
				*flags |= CPU_DTRACE_BADALIGN;
				*illval = regs[rd];
				break;
			}
			*((uint16_t *)(uintptr_t)regs[rd]) = (uint16_t)regs[r1];
			break;

		case DIF_OP_STW:
			if (!dtrace_canstore(regs[rd], 4, mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}
			if (regs[rd] & 3) {
				*flags |= CPU_DTRACE_BADALIGN;
				*illval = regs[rd];
				break;
			}
			*((uint32_t *)(uintptr_t)regs[rd]) = (uint32_t)regs[r1];
			break;

		case DIF_OP_STX:
			if (!dtrace_canstore(regs[rd], 8, mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}
			if (regs[rd] & 7) {
				*flags |= CPU_DTRACE_BADALIGN;
				*illval = regs[rd];
				break;
			}
			*((uint64_t *)(uintptr_t)regs[rd]) = regs[r1];
			break;
		}
	}

	if (!(*flags & CPU_DTRACE_FAULT))
		return (rval);

	mstate->dtms_fltoffs = opc * sizeof (dif_instr_t);
	mstate->dtms_present |= DTRACE_MSTATE_FLTOFFS;

	return (0);
}

static void
dtrace_store_by_ref(dtrace_difo_t *dp, caddr_t tomax, size_t size,
    size_t *valoffsp, uint64_t *valp, uint64_t end, int intuple, int dtkind)
{
	volatile uint16_t *flags;
	uint64_t val = *valp;
	size_t valoffs = *valoffsp;

	flags = (volatile uint16_t *)&cpuc_dtrace_flags;
	ASSERT(dtkind == DIF_TF_BYREF || dtkind == DIF_TF_BYUREF);

	/*
	 * If this is a string, we're going to only load until we find the zero
	 * byte -- after which we'll store zero bytes.
	 */
	if (dp->dtdo_rtype.dtdt_kind == DIF_TYPE_STRING) {
		char c = '\0' + 1;
		size_t s;

		for (s = 0; s < size; s++) {
			if (c != '\0' && dtkind == DIF_TF_BYREF) {
				c = dtrace_load8(val++);
			} else if (c != '\0' && dtkind == DIF_TF_BYUREF) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
				c = dtrace_fuword8((void *)(uintptr_t)val++);
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
				if (*flags & CPU_DTRACE_FAULT)
					break;
			}

			DTRACE_STORE(uint8_t, tomax, valoffs++, c);

			if (c == '\0' && intuple)
				break;
		}
	} else {
		uint8_t c;
		while (valoffs < end) {
			if (dtkind == DIF_TF_BYREF) {
				c = dtrace_load8(val++);
			} else if (dtkind == DIF_TF_BYUREF) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
				c = dtrace_fuword8((void *)(uintptr_t)val++);
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
				if (*flags & CPU_DTRACE_FAULT)
					break;
			}

			DTRACE_STORE(uint8_t, tomax,
			    valoffs++, c);
		}
	}

	*valp = val;
	*valoffsp = valoffs;
}


/*
 * If you're looking for the epicenter of DTrace, you just found it.  This
 * is the function called by the provider to fire a probe -- from which all
 * subsequent probe-context DTrace activity emanates.
 */
void
dtrace_probe(dtrace_id_t id, uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4)
{
	dtrace_icookie_t cookie;
	dtrace_probe_t *probe;
	dtrace_mstate_t mstate;
	dtrace_ecb_t *ecb;
	dtrace_action_t *act;
	intptr_t offs;
	size_t size;
	int vtime, onintr;
	volatile uint16_t *flags;
	hrtime_t now;

	probe = dtrace_probes[id - 1];

	/*
	 * TODO: We need a way to ask for a timestamp from the kernel in an
	 * efficient, but safe way. This should also be as high resolution as
	 * possible.
	 */
#if 0
	now = mstate.dtms_timestamp = dtrace_gethrtime();
	mstate.dtms_present |= DTRACE_MSTATE_TIMESTAMP;
	vtime = dtrace_vtime_references != 0;

	if (vtime && curthread->t_dtrace_start)
		curthread->t_dtrace_vtime += now - curthread->t_dtrace_start;
#endif

	mstate.dtms_difo = NULL;
	mstate.dtms_probe = probe;
	mstate.dtms_strtok = 0;
	mstate.dtms_arg[0] = arg0;
	mstate.dtms_arg[1] = arg1;
	mstate.dtms_arg[2] = arg2;
	mstate.dtms_arg[3] = arg3;
	mstate.dtms_arg[4] = arg4;

	/*
	 * XXX: This might become something else eventually...?
	 */
#if 0
	flags = (volatile uint16_t *)&cpu_core[cpuid].cpuc_dtrace_flags;
#endif

	for (ecb = probe->dtpr_ecb; ecb != NULL; ecb = ecb->dte_next) {
		dtrace_predicate_t *pred = ecb->dte_predicate;
		dtrace_state_t *state = ecb->dte_state;
		/*
		 * TODO: Figure out how to best aggregate (probably by arbitrary
		 * things??)
		 */
		/*
		 * FIXME: The state structure has lots of buffers on a per-CPU
		 * basis. We want it on a per-* basis -- but initially, we just
		 * want one.
		 */
		dtrace_buffer_t *buf = &state->dts_buffer;
		dtrace_buffer_t *aggbuf = &state->dts_aggbuffer;
		dtrace_vstate_t *vstate = &state->dts_vstate;
		dtrace_provider_t *prov = probe->dtpr_provider;
		uint64_t tracememsize = 0;
		int committed = 0;
		caddr_t tomax;

		/*
		 * A little subtlety with the following (seemingly innocuous)
		 * declaration of the automatic 'val':  by looking at the
		 * code, you might think that it could be declared in the
		 * action processing loop, below.  (That is, it's only used in
		 * the action processing loop.)  However, it must be declared
		 * out of that scope because in the case of DIF expression
		 * arguments to aggregating actions, one iteration of the
		 * action loop will use the last iteration's value.
		 */
		uint64_t val = 0;

		mstate.dtms_present = DTRACE_MSTATE_ARGS | DTRACE_MSTATE_PROBE;
		mstate.dtms_getf = NULL;

		*flags &= ~CPU_DTRACE_ERROR;

		if (prov == dtrace_provider) {
			/*
			 * If dtrace itself is the provider of this probe,
			 * we're only going to continue processing the ECB if
			 * arg0 (the dtrace_state_t) is equal to the ECB's
			 * creating state.  (This prevents disjoint consumers
			 * from seeing one another's metaprobes.)
			 */
			if (arg0 != (uint64_t)(uintptr_t)state)
				continue;
		}

		if (state->dts_activity != DTRACE_ACTIVITY_ACTIVE) {
			/*
			 * We're not currently active.  If our provider isn't
			 * the dtrace pseudo provider, we're not interested.
			 */
			if (prov != dtrace_provider)
				continue;

			/*
			 * Now we must further check if we are in the BEGIN
			 * probe.  If we are, we will only continue processing
			 * if we're still in WARMUP -- if one BEGIN enabling
			 * has invoked the exit() action, we don't want to
			 * evaluate subsequent BEGIN enablings.
			 */
			if (probe->dtpr_id == dtrace_probeid_begin &&
			    state->dts_activity != DTRACE_ACTIVITY_WARMUP) {
				assert(state->dts_activity ==
				    DTRACE_ACTIVITY_DRAINING);
				continue;
			}
		}

		if (ecb->dte_cond) {
			/*
			 * If the dte_cond bits indicate that this
			 * consumer is only allowed to see user-mode firings
			 * of this probe, call the provider's dtps_usermode()
			 * entry point to check that the probe was fired
			 * while in a user context. Skip this ECB if that's
			 * not the case.
			 */
			if ((ecb->dte_cond & DTRACE_COND_USERMODE) &&
			    prov->dtpv_pops.dtps_usermode(prov->dtpv_arg,
			    probe->dtpr_id, probe->dtpr_arg) == 0)
				continue;
		}

		/*
		 * TODO: Here we want to enable destructive actions, but it's
		 * unclear as to how to do so (at least to me). We could set
		 * some sort of a flag and have a co-processor in the kernel...?
		 */
#if 0
		if (now - state->dts_alive > dtrace_deadman_timeout) {
			/*
			 * We seem to be dead.  Unless we (a) have kernel
			 * destructive permissions (b) have explicitly enabled
			 * destructive actions and (c) destructive actions have
			 * not been disabled, we're going to transition into
			 * the KILLED state, from which no further processing
			 * on this state will be performed.
			 */
			if (!dtrace_priv_kernel_destructive(state) ||
			    !state->dts_cred.dcr_destructive ||
			    dtrace_destructive_disallow) {
				void *activity = &state->dts_activity;
				dtrace_activity_t current;

				do {
					current = state->dts_activity;
				} while (dtrace_cas32(activity, current,
				    DTRACE_ACTIVITY_KILLED) != current);

				continue;
			}
		}
#endif

		if ((offs = dtrace_buffer_reserve(buf, ecb->dte_needed,
		    ecb->dte_alignment, state, &mstate)) < 0)
			continue;


		tomax = buf->dtb_tomax;
		assert(tomax != NULL);

		/*
		 * TODO: Figure out how to timestamp
		 */
#if 0
		if (ecb->dte_size != 0) {
			dtrace_rechdr_t dtrh;
			if (!(mstate.dtms_present & DTRACE_MSTATE_TIMESTAMP)) {
				mstate.dtms_timestamp = dtrace_gethrtime();
				mstate.dtms_present |= DTRACE_MSTATE_TIMESTAMP;
			}
			ASSERT3U(ecb->dte_size, >=, sizeof (dtrace_rechdr_t));
			dtrh.dtrh_epid = ecb->dte_epid;
			DTRACE_RECORD_STORE_TIMESTAMP(&dtrh,
			    mstate.dtms_timestamp);
			*((dtrace_rechdr_t *)(tomax + offs)) = dtrh;
		}
#endif

		mstate.dtms_epid = ecb->dte_epid;
		mstate.dtms_present |= DTRACE_MSTATE_EPID;

		if (state->dts_cred.dcr_visible & DTRACE_CRV_KERNEL)
			mstate.dtms_access = DTRACE_ACCESS_KERNEL;
		else
			mstate.dtms_access = 0;

		if (pred != NULL) {
			dtrace_difo_t *dp = pred->dtp_difo;
			uint64_t rval;

			rval = dtrace_dif_emulate(dp, &mstate, vstate, state);

			if (!(*flags & CPU_DTRACE_ERROR) && !rval) {
				dtrace_cacheid_t cid = probe->dtpr_predcache;

				if (cid != DTRACE_CACHEIDNONE && !onintr) {
					/*
					 * Update the predicate cache...
					 */
					assert(cid == pred->dtp_cacheid);
					predcache = cid;
				}

				continue;
			}
		}

		for (act = ecb->dte_action; !(*flags & CPU_DTRACE_ERROR) &&
		    act != NULL; act = act->dta_next) {
			size_t valoffs;
			dtrace_difo_t *dp;
			dtrace_recdesc_t *rec = &act->dta_rec;

			size = rec->dtrd_size;
			valoffs = offs + rec->dtrd_offset;

			if (DTRACEACT_ISAGG(act->dta_kind)) {
				uint64_t v = 0xbad;
				dtrace_aggregation_t *agg;

				agg = (dtrace_aggregation_t *)act;

				if ((dp = act->dta_difo) != NULL)
					v = dtrace_dif_emulate(dp,
					    &mstate, vstate, state);

				if (*flags & CPU_DTRACE_ERROR)
					continue;

				/*
				 * Note that we always pass the expression
				 * value from the previous iteration of the
				 * action loop.  This value will only be used
				 * if there is an expression argument to the
				 * aggregating action, denoted by the
				 * dtag_hasarg field.
				 */
				dtrace_aggregate(agg, buf,
				    offs, aggbuf, v, val);
				continue;
			}

			switch (act->dta_kind) {
			case DTRACEACT_STOP:
				if (dtrace_priv_proc_destructive(state))
					dtrace_action_stop();
				continue;

			case DTRACEACT_BREAKPOINT:
				if (dtrace_priv_kernel_destructive(state))
					dtrace_action_breakpoint(ecb);
				continue;

			case DTRACEACT_PANIC:
				if (dtrace_priv_kernel_destructive(state))
					dtrace_action_panic(ecb);
				continue;

			case DTRACEACT_STACK:
				if (!dtrace_priv_kernel(state))
					continue;

				dtrace_getpcstack((pc_t *)(tomax + valoffs),
				    size / sizeof (pc_t), probe->dtpr_aframes,
				    DTRACE_ANCHORED(probe) ? NULL :
				    (uint32_t *)arg0);
				continue;

			/*
			 * FIXME: We definitely want to be able to get a proper
			 * DTrace stack trace, but this should probably be done
			 * with some re-usable code...?
			 */
#if 0
			case DTRACEACT_JSTACK:
			case DTRACEACT_USTACK:
				if (!dtrace_priv_proc(state))
					continue;

				/*
				 * See comment in DIF_VAR_PID.
				 */
				if (DTRACE_ANCHORED(mstate.dtms_probe) &&
				    CPU_ON_INTR(CPU)) {
					int depth = DTRACE_USTACK_NFRAMES(
					    rec->dtrd_arg) + 1;

					dtrace_bzero((void *)(tomax + valoffs),
					    DTRACE_USTACK_STRSIZE(rec->dtrd_arg)
					    + depth * sizeof (uint64_t));

					continue;
				}

				if (DTRACE_USTACK_STRSIZE(rec->dtrd_arg) != 0 &&
				    curproc->p_dtrace_helpers != NULL) {
					/*
					 * This is the slow path -- we have
					 * allocated string space, and we're
					 * getting the stack of a process that
					 * has helpers.  Call into a separate
					 * routine to perform this processing.
					 */
					dtrace_action_ustack(&mstate, state,
					    (uint64_t *)(tomax + valoffs),
					    rec->dtrd_arg);
					continue;
				}

				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
				dtrace_getupcstack((uint64_t *)
				    (tomax + valoffs),
				    DTRACE_USTACK_NFRAMES(rec->dtrd_arg) + 1);
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
				continue;
#endif

			default:
				break;
			}

			dp = act->dta_difo;
			assert(dp != NULL);

			val = dtrace_dif_emulate(dp, &mstate, vstate, state);

			if (*flags & CPU_DTRACE_ERROR)
				continue;

			switch (act->dta_kind) {
			/*
			 * FIXME: We want to speculate... but it wans a cpuid
			 * with this code.
			 */
#if 0
			case DTRACEACT_SPECULATE: {
				dtrace_rechdr_t *dtrh;

				assert(buf == &state->dts_buffer[cpuid]);
				buf = dtrace_speculation_buffer(state,
				    cpuid, val);

				if (buf == NULL) {
					*flags |= CPU_DTRACE_DROP;
					continue;
				}

				offs = dtrace_buffer_reserve(buf,
				    ecb->dte_needed, ecb->dte_alignment,
				    state, NULL);

				if (offs < 0) {
					*flags |= CPU_DTRACE_DROP;
					continue;
				}

				tomax = buf->dtb_tomax;
				assert(tomax != NULL);

				if (ecb->dte_size == 0)
					continue;

				ASSERT3U(ecb->dte_size, >=,
				    sizeof (dtrace_rechdr_t));
				dtrh = ((void *)(tomax + offs));
				dtrh->dtrh_epid = ecb->dte_epid;
				/*
				 * When the speculation is committed, all of
				 * the records in the speculative buffer will
				 * have their timestamps set to the commit
				 * time.  Until then, it is set to a sentinel
				 * value, for debugability.
				 */
				DTRACE_RECORD_STORE_TIMESTAMP(dtrh, UINT64_MAX);
				continue;
			}
#endif

			case DTRACEACT_PRINTM: {
				/* The DIF returns a 'memref'. */
				uintptr_t *memref = (uintptr_t *)(uintptr_t) val;

				/* Get the size from the memref. */
				size = memref[1];

				/*
				 * Check if the size exceeds the allocated
				 * buffer size.
				 */
				if (size + sizeof(uintptr_t) > dp->dtdo_rtype.dtdt_size) {
					/* Flag a drop! */
					*flags |= CPU_DTRACE_DROP;
					continue;
				}

				/* Store the size in the buffer first. */
				DTRACE_STORE(uintptr_t, tomax,
				    valoffs, size);

				/*
				 * Offset the buffer address to the start
				 * of the data.
				 */
				valoffs += sizeof(uintptr_t);

				/*
				 * Reset to the memory address rather than
				 * the memref array, then let the BYREF
				 * code below do the work to store the 
				 * memory data in the buffer.
				 */
				val = memref[0];
				break;
			}

			case DTRACEACT_CHILL:
				if (dtrace_priv_kernel_destructive(state))
					dtrace_action_chill(&mstate, val);
				continue;

			case DTRACEACT_RAISE:
				if (dtrace_priv_proc_destructive(state))
					dtrace_action_raise(val);
				continue;

			/*
			 * FIXME: Ignore speculation for now
			 */
#if 0
			case DTRACEACT_COMMIT:
				assert(!committed);

				/*
				 * We need to commit our buffer state.
				 */
				if (ecb->dte_size)
					buf->dtb_offset = offs + ecb->dte_size;
				buf = &state->dts_buffer[cpuid];
				dtrace_speculation_commit(state, cpuid, val);
				committed = 1;
				continue;

			case DTRACEACT_DISCARD:
				dtrace_speculation_discard(state, cpuid, val);
				continue;
#endif

			case DTRACEACT_DIFEXPR:
			case DTRACEACT_LIBACT:
			case DTRACEACT_PRINTF:
			case DTRACEACT_PRINTA:
			case DTRACEACT_SYSTEM:
			case DTRACEACT_FREOPEN:
			case DTRACEACT_TRACEMEM:
				break;

			case DTRACEACT_TRACEMEM_DYNSIZE:
				tracememsize = val;
				break;

			case DTRACEACT_SYM:
			case DTRACEACT_MOD:
				if (!dtrace_priv_kernel(state))
					continue;
				break;

			case DTRACEACT_USYM:
			case DTRACEACT_UMOD:
			case DTRACEACT_UADDR: {
#ifdef illumos
				struct pid *pid = curthread->t_procp->p_pidp;
#endif

				if (!dtrace_priv_proc(state))
					continue;

				DTRACE_STORE(uint64_t, tomax,
#ifdef illumos
				    valoffs, (uint64_t)pid->pid_id);
#else
				    valoffs, getpid());
#endif
				DTRACE_STORE(uint64_t, tomax,
				    valoffs + sizeof (uint64_t), val);

				continue;
			}

			case DTRACEACT_EXIT: {
				/*
				 * For the exit action, we are going to attempt
				 * to atomically set our activity to be
				 * draining.  If this fails (either because
				 * another CPU has beat us to the exit action,
				 * or because our current activity is something
				 * other than ACTIVE or WARMUP), we will
				 * continue.  This assures that the exit action
				 * can be successfully recorded at most once
				 * when we're in the ACTIVE state.  If we're
				 * encountering the exit() action while in
				 * COOLDOWN, however, we want to honor the new
				 * status code.  (We know that we're the only
				 * thread in COOLDOWN, so there is no race.)
				 */
				void *activity = &state->dts_activity;
				dtrace_activity_t current = state->dts_activity;

				if (current == DTRACE_ACTIVITY_COOLDOWN)
					break;

				if (current != DTRACE_ACTIVITY_WARMUP)
					current = DTRACE_ACTIVITY_ACTIVE;

				if (dtrace_cas32(activity, current,
				    DTRACE_ACTIVITY_DRAINING) != current) {
					*flags |= CPU_DTRACE_DROP;
					continue;
				}

				break;
			}

			default:
				assert(0);
			}

			if (dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF ||
			    dp->dtdo_rtype.dtdt_flags & DIF_TF_BYUREF) {
				uintptr_t end = valoffs + size;

				if (tracememsize != 0 &&
				    valoffs + tracememsize < end) {
					end = valoffs + tracememsize;
					tracememsize = 0;
				}

				if (dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF &&
				    !dtrace_vcanload((void *)(uintptr_t)val,
				    &dp->dtdo_rtype, NULL, &mstate, vstate))
					continue;

				dtrace_store_by_ref(dp, tomax, size, &valoffs,
				    &val, end, act->dta_intuple,
				    dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF ?
				    DIF_TF_BYREF: DIF_TF_BYUREF);
				continue;
			}

			switch (size) {
			case 0:
				break;

			case sizeof (uint8_t):
				DTRACE_STORE(uint8_t, tomax, valoffs, val);
				break;
			case sizeof (uint16_t):
				DTRACE_STORE(uint16_t, tomax, valoffs, val);
				break;
			case sizeof (uint32_t):
				DTRACE_STORE(uint32_t, tomax, valoffs, val);
				break;
			case sizeof (uint64_t):
				DTRACE_STORE(uint64_t, tomax, valoffs, val);
				break;
			default:
				/*
				 * Any other size should have been returned by
				 * reference, not by value.
				 */
				assert(0);
				break;
			}
		}

		if (*flags & CPU_DTRACE_DROP)
			continue;

		if (*flags & CPU_DTRACE_FAULT) {
			int ndx;
			dtrace_action_t *err;

			buf->dtb_errors++;

			if (probe->dtpr_id == dtrace_probeid_error) {
				/*
				 * There's nothing we can do -- we had an
				 * error on the error probe.  We bump an
				 * error counter to at least indicate that
				 * this condition happened.
				 */
				dtrace_error(&state->dts_dblerrors);
				continue;
			}

			if (vtime) {
				/*
				 * Before recursing on dtrace_probe(), we
				 * need to explicitly clear out our start
				 * time to prevent it from being accumulated
				 * into t_dtrace_vtime.
				 */
				/*
				 * FIXME: We want timestamps, but definitely do
				 * not want them in userspace.
				 */
#if 0
				curthread->t_dtrace_start = 0;
#endif
			}

			/*
			 * Iterate over the actions to figure out which action
			 * we were processing when we experienced the error.
			 * Note that act points _past_ the faulting action; if
			 * act is ecb->dte_action, the fault was in the
			 * predicate, if it's ecb->dte_action->dta_next it's
			 * in action #1, and so on.
			 */
			for (err = ecb->dte_action, ndx = 0;
			    err != act; err = err->dta_next, ndx++)
				continue;

			dtrace_probe_error(state, ecb->dte_epid, ndx,
			    (mstate.dtms_present & DTRACE_MSTATE_FLTOFFS) ?
			    mstate.dtms_fltoffs : -1, DTRACE_FLAGS2FLT(*flags),
			    cpuc_dtrace_illval);

			continue;
		}

		if (!committed)
			buf->dtb_offset = offs + ecb->dte_size;
	}

#if 0
	if (vtime)
		curthread->t_dtrace_start = dtrace_gethrtime();

	dtrace_interrupt_enable(cookie);
#endif
}


/*
 * DTrace ECB Functions
 */
static dtrace_ecb_t *
dtrace_ecb_add(dtrace_state_t *state, dtrace_probe_t *probe)
{
	dtrace_ecb_t *ecb;
	dtrace_epid_t epid;

	ecb = calloc(1, sizeof (dtrace_ecb_t));
	if (ecb == NULL)
		return (NULL);
	ecb->dte_predicate = NULL;
	ecb->dte_probe = probe;

	/*
	 * The default size is the size of the default action: recording
	 * the header.
	 */
	ecb->dte_size = ecb->dte_needed = sizeof (dtrace_rechdr_t);
	ecb->dte_alignment = sizeof (dtrace_epid_t);

	epid = state->dts_epid++;

	if (epid - 1 >= state->dts_necbs) {
		dtrace_ecb_t **oecbs = state->dts_ecbs, **ecbs;
		int necbs = state->dts_necbs << 1;

		assert(epid == state->dts_necbs + 1);

		if (necbs == 0) {
			assert(oecbs == NULL);
			necbs = 1;
		}

		ecbs = calloc(1, necbs * sizeof (*ecbs));
		if (ecbs == NULL)
			return (NULL);

		if (oecbs != NULL)
			bcopy(oecbs, ecbs, state->dts_necbs * sizeof (*ecbs));

		dtrace_membar_producer();
		state->dts_ecbs = ecbs;

		if (oecbs != NULL) {
			free(oecbs);
		}

		dtrace_membar_producer();
		state->dts_necbs = necbs;
	}

	ecb->dte_state = state;

	assert(state->dts_ecbs[epid - 1] == NULL);
	dtrace_membar_producer();
	state->dts_ecbs[(ecb->dte_epid = epid) - 1] = ecb;

	return (ecb);
}

static dtrace_action_t *
dtrace_ecb_aggregation_create(dtrace_ecb_t *ecb, dtrace_actdesc_t *desc)
{
	dtrace_aggregation_t *agg;
	size_t size = sizeof (uint64_t);
	int ntuple = desc->dtad_ntuple;
	dtrace_action_t *act;
	dtrace_recdesc_t *frec;
	dtrace_aggid_t aggid;
	dtrace_state_t *state = ecb->dte_state;

	agg = calloc(1, sizeof (dtrace_aggregation_t));
	if (agg == NULL)
		return (NULL);
	agg->dtag_ecb = ecb;

	assert(DTRACEACT_ISAGG(desc->dtad_kind));

	switch (desc->dtad_kind) {
	case DTRACEAGG_MIN:
		agg->dtag_initial = INT64_MAX;
		agg->dtag_aggregate = dtrace_aggregate_min;
		break;

	case DTRACEAGG_MAX:
		agg->dtag_initial = INT64_MIN;
		agg->dtag_aggregate = dtrace_aggregate_max;
		break;

	case DTRACEAGG_COUNT:
		agg->dtag_aggregate = dtrace_aggregate_count;
		break;

	case DTRACEAGG_QUANTIZE:
		agg->dtag_aggregate = dtrace_aggregate_quantize;
		size = (((sizeof (uint64_t) * NBBY) - 1) * 2 + 1) *
		    sizeof (uint64_t);
		break;

	case DTRACEAGG_LQUANTIZE: {
		uint16_t step = DTRACE_LQUANTIZE_STEP(desc->dtad_arg);
		uint16_t levels = DTRACE_LQUANTIZE_LEVELS(desc->dtad_arg);

		agg->dtag_initial = desc->dtad_arg;
		agg->dtag_aggregate = dtrace_aggregate_lquantize;

		if (step == 0 || levels == 0)
			goto err;

		size = levels * sizeof (uint64_t) + 3 * sizeof (uint64_t);
		break;
	}

	case DTRACEAGG_LLQUANTIZE: {
		uint16_t factor = DTRACE_LLQUANTIZE_FACTOR(desc->dtad_arg);
		uint16_t low = DTRACE_LLQUANTIZE_LOW(desc->dtad_arg);
		uint16_t high = DTRACE_LLQUANTIZE_HIGH(desc->dtad_arg);
		uint16_t nsteps = DTRACE_LLQUANTIZE_NSTEP(desc->dtad_arg);
		int64_t v;

		agg->dtag_initial = desc->dtad_arg;
		agg->dtag_aggregate = dtrace_aggregate_llquantize;

		if (factor < 2 || low >= high || nsteps < factor)
			goto err;

		/*
		 * Now check that the number of steps evenly divides a power
		 * of the factor.  (This assures both integer bucket size and
		 * linearity within each magnitude.)
		 */
		for (v = factor; v < nsteps; v *= factor)
			continue;

		if ((v % nsteps) || (nsteps % factor))
			goto err;

		size = (dtrace_aggregate_llquantize_bucket(factor,
		    low, high, nsteps, INT64_MAX) + 2) * sizeof (uint64_t);
		break;
	}

	case DTRACEAGG_AVG:
		agg->dtag_aggregate = dtrace_aggregate_avg;
		size = sizeof (uint64_t) * 2;
		break;

	case DTRACEAGG_STDDEV:
		agg->dtag_aggregate = dtrace_aggregate_stddev;
		size = sizeof (uint64_t) * 4;
		break;

	case DTRACEAGG_SUM:
		agg->dtag_aggregate = dtrace_aggregate_sum;
		break;

	default:
		goto err;
	}

	agg->dtag_action.dta_rec.dtrd_size = size;

	if (ntuple == 0)
		goto err;

	/*
	 * We must make sure that we have enough actions for the n-tuple.
	 */
	for (act = ecb->dte_action_last; act != NULL; act = act->dta_prev) {
		if (DTRACEACT_ISAGG(act->dta_kind))
			break;

		if (--ntuple == 0) {
			/*
			 * This is the action with which our n-tuple begins.
			 */
			agg->dtag_first = act;
			goto success;
		}
	}

	/*
	 * This n-tuple is short by ntuple elements.  Return failure.
	 */
	assert(ntuple != 0);
err:
	free(agg);
	return (NULL);

success:
	/*
	 * If the last action in the tuple has a size of zero, it's actually
	 * an expression argument for the aggregating action.
	 */
	assert(ecb->dte_action_last != NULL);
	act = ecb->dte_action_last;

	if (act->dta_kind == DTRACEACT_DIFEXPR) {
		assert(act->dta_difo != NULL);

		if (act->dta_difo->dtdo_rtype.dtdt_size == 0)
			agg->dtag_hasarg = 1;
	}

	/*
	 * We need to allocate an id for this aggregation.
	 */
#ifdef illumos
	aggid = (dtrace_aggid_t)(uintptr_t)vmem_alloc(state->dts_aggid_arena, 1,
	    VM_BESTFIT | VM_SLEEP);
#else
	aggid = alloc_unr(state->dts_aggid_arena);
#endif

	if (aggid - 1 >= state->dts_naggregations) {
		dtrace_aggregation_t **oaggs = state->dts_aggregations;
		dtrace_aggregation_t **aggs;
		int naggs = state->dts_naggregations << 1;
		int onaggs = state->dts_naggregations;

		assert(aggid == state->dts_naggregations + 1);

		if (naggs == 0) {
			assert(oaggs == NULL);
			naggs = 1;
		}

		aggs = calloc(1, naggs * sizeof (*aggs));
		if (aggs == NULL)
			return (NULL);

		if (oaggs != NULL) {
			bcopy(oaggs, aggs, onaggs * sizeof (*aggs));
			free(oaggs);
		}

		state->dts_aggregations = aggs;
		state->dts_naggregations = naggs;
	}

	assert(state->dts_aggregations[aggid - 1] == NULL);
	state->dts_aggregations[(agg->dtag_id = aggid) - 1] = agg;

	frec = &agg->dtag_first->dta_rec;
	if (frec->dtrd_alignment < sizeof (dtrace_aggid_t))
		frec->dtrd_alignment = sizeof (dtrace_aggid_t);

	for (act = agg->dtag_first; act != NULL; act = act->dta_next) {
		assert(!act->dta_intuple);
		act->dta_intuple = 1;
	}

	return (&agg->dtag_action);
}

static void
dtrace_ecb_aggregation_destroy(dtrace_ecb_t *ecb, dtrace_action_t *act)
{
	dtrace_aggregation_t *agg = (dtrace_aggregation_t *)act;
	dtrace_state_t *state = ecb->dte_state;
	dtrace_aggid_t aggid = agg->dtag_id;

	assert(DTRACEACT_ISAGG(act->dta_kind));
	free_unr(state->dts_aggid_arena, aggid);

	assert(state->dts_aggregations[aggid - 1] == agg);
	state->dts_aggregations[aggid - 1] = NULL;

	free(agg);
}

static int
dtrace_ecb_action_add(dtrace_ecb_t *ecb, dtrace_actdesc_t *desc)
{
	dtrace_action_t *action, *last;
	dtrace_difo_t *dp = desc->dtad_difo;
	uint32_t size = 0, align = sizeof (uint8_t), mask;
	uint16_t format = 0;
	dtrace_recdesc_t *rec;
	dtrace_state_t *state = ecb->dte_state;
	dtrace_optval_t *opt = state->dts_options, nframes = 0, strsize;
	uint64_t arg = desc->dtad_arg;

	assert(ecb->dte_action == NULL || ecb->dte_action->dta_refcnt == 1);

	if (DTRACEACT_ISAGG(desc->dtad_kind)) {
		/*
		 * If this is an aggregating action, there must be neither
		 * a speculate nor a commit on the action chain.
		 */
		dtrace_action_t *act;

		for (act = ecb->dte_action; act != NULL; act = act->dta_next) {
			if (act->dta_kind == DTRACEACT_COMMIT)
				return (EINVAL);

			if (act->dta_kind == DTRACEACT_SPECULATE)
				return (EINVAL);
		}

		action = dtrace_ecb_aggregation_create(ecb, desc);

		if (action == NULL)
			return (EINVAL);
	} else {
		if (DTRACEACT_ISDESTRUCTIVE(desc->dtad_kind) ||
		    (desc->dtad_kind == DTRACEACT_DIFEXPR &&
		    dp != NULL && dp->dtdo_destructive)) {
			state->dts_destructive = 1;
		}

		switch (desc->dtad_kind) {
		case DTRACEACT_PRINTF:
		case DTRACEACT_PRINTA:
		case DTRACEACT_SYSTEM:
		case DTRACEACT_FREOPEN:
		case DTRACEACT_DIFEXPR:
			/*
			 * We know that our arg is a string -- turn it into a
			 * format.
			 */
			if (arg == 0) {
				assert(desc->dtad_kind == DTRACEACT_PRINTA ||
				    desc->dtad_kind == DTRACEACT_DIFEXPR);
				format = 0;
			} else {
				assert(arg != 0);
#ifdef illumos
				assert(arg > KERNELBASE);
#endif
				format = dtrace_format_add(state,
				    (char *)(uintptr_t)arg);
			}

			/*FALLTHROUGH*/
		case DTRACEACT_LIBACT:
		case DTRACEACT_TRACEMEM:
		case DTRACEACT_TRACEMEM_DYNSIZE:
			if (dp == NULL)
				return (EINVAL);

			if ((size = dp->dtdo_rtype.dtdt_size) != 0)
				break;

			if (dp->dtdo_rtype.dtdt_kind == DIF_TYPE_STRING) {
				if (!(dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF))
					return (EINVAL);

				size = opt[DTRACEOPT_STRSIZE];
			}

			break;

		case DTRACEACT_STACK:
			if ((nframes = arg) == 0) {
				nframes = opt[DTRACEOPT_STACKFRAMES];
				assert(nframes > 0);
				arg = nframes;
			}

			size = nframes * sizeof (pc_t);
			break;

		case DTRACEACT_JSTACK:
			if ((strsize = DTRACE_USTACK_STRSIZE(arg)) == 0)
				strsize = opt[DTRACEOPT_JSTACKSTRSIZE];

			if ((nframes = DTRACE_USTACK_NFRAMES(arg)) == 0)
				nframes = opt[DTRACEOPT_JSTACKFRAMES];

			arg = DTRACE_USTACK_ARG(nframes, strsize);

			/*FALLTHROUGH*/
		case DTRACEACT_USTACK:
			if (desc->dtad_kind != DTRACEACT_JSTACK &&
			    (nframes = DTRACE_USTACK_NFRAMES(arg)) == 0) {
				strsize = DTRACE_USTACK_STRSIZE(arg);
				nframes = opt[DTRACEOPT_USTACKFRAMES];
				assert(nframes > 0);
				arg = DTRACE_USTACK_ARG(nframes, strsize);
			}

			/*
			 * Save a slot for the pid.
			 */
			size = (nframes + 1) * sizeof (uint64_t);
			size += DTRACE_USTACK_STRSIZE(arg);
			size = P2ROUNDUP(size, (uint32_t)(sizeof (uintptr_t)));

			break;

		case DTRACEACT_SYM:
		case DTRACEACT_MOD:
			if (dp == NULL || ((size = dp->dtdo_rtype.dtdt_size) !=
			    sizeof (uint64_t)) ||
			    (dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF))
				return (EINVAL);
			break;

		case DTRACEACT_USYM:
		case DTRACEACT_UMOD:
		case DTRACEACT_UADDR:
			if (dp == NULL ||
			    (dp->dtdo_rtype.dtdt_size != sizeof (uint64_t)) ||
			    (dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF))
				return (EINVAL);

			/*
			 * We have a slot for the pid, plus a slot for the
			 * argument.  To keep things simple (aligned with
			 * bitness-neutral sizing), we store each as a 64-bit
			 * quantity.
			 */
			size = 2 * sizeof (uint64_t);
			break;

		case DTRACEACT_STOP:
		case DTRACEACT_BREAKPOINT:
		case DTRACEACT_PANIC:
			break;

		case DTRACEACT_CHILL:
		case DTRACEACT_DISCARD:
		case DTRACEACT_RAISE:
			if (dp == NULL)
				return (EINVAL);
			break;

		case DTRACEACT_EXIT:
			if (dp == NULL ||
			    (size = dp->dtdo_rtype.dtdt_size) != sizeof (int) ||
			    (dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF))
				return (EINVAL);
			break;

		case DTRACEACT_SPECULATE:
			if (ecb->dte_size > sizeof (dtrace_rechdr_t))
				return (EINVAL);

			if (dp == NULL)
				return (EINVAL);

			state->dts_speculates = 1;
			break;

		case DTRACEACT_PRINTM:
		    	size = dp->dtdo_rtype.dtdt_size;
			break;

		case DTRACEACT_COMMIT: {
			dtrace_action_t *act = ecb->dte_action;

			for (; act != NULL; act = act->dta_next) {
				if (act->dta_kind == DTRACEACT_COMMIT)
					return (EINVAL);
			}

			if (dp == NULL)
				return (EINVAL);
			break;
		}

		default:
			return (EINVAL);
		}

		if (size != 0 || desc->dtad_kind == DTRACEACT_SPECULATE) {
			/*
			 * If this is a data-storing action or a speculate,
			 * we must be sure that there isn't a commit on the
			 * action chain.
			 */
			dtrace_action_t *act = ecb->dte_action;

			for (; act != NULL; act = act->dta_next) {
				if (act->dta_kind == DTRACEACT_COMMIT)
					return (EINVAL);
			}
		}

		action = calloc(1, sizeof (dtrace_action_t));
		if (action == NULL)
			return (ENOMEM);

		action->dta_rec.dtrd_size = size;
	}

	action->dta_refcnt = 1;
	rec = &action->dta_rec;
	size = rec->dtrd_size;

	for (mask = sizeof (uint64_t) - 1; size != 0 && mask > 0; mask >>= 1) {
		if (!(size & mask)) {
			align = mask + 1;
			break;
		}
	}

	action->dta_kind = desc->dtad_kind;

	if ((action->dta_difo = dp) != NULL)
		dtrace_difo_hold(dp);

	rec->dtrd_action = action->dta_kind;
	rec->dtrd_arg = arg;
	rec->dtrd_uarg = desc->dtad_uarg;
	rec->dtrd_alignment = (uint16_t)align;
	rec->dtrd_format = format;

	if ((last = ecb->dte_action_last) != NULL) {
		assert(ecb->dte_action != NULL);
		action->dta_prev = last;
		last->dta_next = action;
	} else {
		assert(ecb->dte_action == NULL);
		ecb->dte_action = action;
	}

	ecb->dte_action_last = action;

	return (0);
}

static void
dtrace_ecb_action_remove(dtrace_ecb_t *ecb)
{
	dtrace_action_t *act = ecb->dte_action, *next;
	dtrace_vstate_t *vstate = &ecb->dte_state->dts_vstate;
	dtrace_difo_t *dp;
	uint16_t format;

	if (act != NULL && act->dta_refcnt > 1) {
		assert(act->dta_next == NULL || act->dta_next->dta_refcnt == 1);
		act->dta_refcnt--;
	} else {
		for (; act != NULL; act = next) {
			next = act->dta_next;
			assert(next != NULL || act == ecb->dte_action_last);
			assert(act->dta_refcnt == 1);

			if ((format = act->dta_rec.dtrd_format) != 0)
				dtrace_format_remove(ecb->dte_state, format);

			if ((dp = act->dta_difo) != NULL)
				dtrace_difo_release(dp, vstate);

			if (DTRACEACT_ISAGG(act->dta_kind)) {
				dtrace_ecb_aggregation_destroy(ecb, act);
			} else {
				free(act);
			}
		}
	}

	ecb->dte_action = NULL;
	ecb->dte_action_last = NULL;
	ecb->dte_size = 0;
}

static void
dtrace_ecb_disable(dtrace_ecb_t *ecb)
{
	/*
	 * We disable the ECB by removing it from its probe.
	 */
	dtrace_ecb_t *pecb, *prev = NULL;
	dtrace_probe_t *probe = ecb->dte_probe;

	if (probe == NULL) {
		/*
		 * This is the NULL probe; there is nothing to disable.
		 */
		return;
	}

	for (pecb = probe->dtpr_ecb; pecb != NULL; pecb = pecb->dte_next) {
		if (pecb == ecb)
			break;
		prev = pecb;
	}

	assert(pecb != NULL);

	if (prev == NULL) {
		probe->dtpr_ecb = ecb->dte_next;
	} else {
		prev->dte_next = ecb->dte_next;
	}

	if (ecb == probe->dtpr_ecb_last) {
		assert(ecb->dte_next == NULL);
		probe->dtpr_ecb_last = prev;
	}

	if (probe->dtpr_ecb == NULL) {
		/*
		 * That was the last ECB on the probe; clear the predicate
		 * cache ID for the probe, disable it and sync one more time
		 * to assure that we'll never hit it again.
		 */
		dtrace_provider_t *prov = probe->dtpr_provider;

		assert(ecb->dte_next == NULL);
		assert(probe->dtpr_ecb_last == NULL);
		probe->dtpr_predcache = DTRACE_CACHEIDNONE;
		prov->dtpv_pops.dtps_disable(prov->dtpv_arg,
		    probe->dtpr_id, probe->dtpr_arg);
	} else {
		/*
		 * There is at least one ECB remaining on the probe.  If there
		 * is _exactly_ one, set the probe's predicate cache ID to be
		 * the predicate cache ID of the remaining ECB.
		 */
		assert(probe->dtpr_ecb_last != NULL);
		assert(probe->dtpr_predcache == DTRACE_CACHEIDNONE);

		if (probe->dtpr_ecb == probe->dtpr_ecb_last) {
			dtrace_predicate_t *p = probe->dtpr_ecb->dte_predicate;

			assert(probe->dtpr_ecb->dte_next == NULL);

			if (p != NULL)
				probe->dtpr_predcache = p->dtp_cacheid;
		}

		ecb->dte_next = NULL;
	}
}

static void
dtrace_ecb_destroy(dtrace_ecb_t *ecb)
{
	dtrace_state_t *state = ecb->dte_state;
	dtrace_vstate_t *vstate = &state->dts_vstate;
	dtrace_predicate_t *pred;
	dtrace_epid_t epid = ecb->dte_epid;

	assert(ecb->dte_next == NULL);
	assert(ecb->dte_probe == NULL || ecb->dte_probe->dtpr_ecb != ecb);

	if ((pred = ecb->dte_predicate) != NULL)
		dtrace_predicate_release(pred, vstate);

	dtrace_ecb_action_remove(ecb);

	assert(state->dts_ecbs[epid - 1] == ecb);
	state->dts_ecbs[epid - 1] = NULL;

	free(ecb);
}

static void
dtrace_ecb_enable(dtrace_ecb_t *ecb)
{
	dtrace_probe_t *probe = ecb->dte_probe;

	assert(ecb->dte_next == NULL);

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
		assert(probe->dtpr_ecb_last != NULL);
		probe->dtpr_ecb_last->dte_next = ecb;
		probe->dtpr_ecb_last = ecb;
		probe->dtpr_predcache = 0;
	}
}

static int
dtrace_ecb_resize(dtrace_ecb_t *ecb)
{
	dtrace_action_t *act;
	uint32_t curneeded = UINT32_MAX;
	uint32_t aggbase = UINT32_MAX;

	/*
	 * If we record anything, we always record the dtrace_rechdr_t.  (And
	 * we always record it first.)
	 */
	ecb->dte_size = sizeof (dtrace_rechdr_t);
	ecb->dte_alignment = sizeof (dtrace_epid_t);

	for (act = ecb->dte_action; act != NULL; act = act->dta_next) {
		dtrace_recdesc_t *rec = &act->dta_rec;
		assert(rec->dtrd_size > 0 || rec->dtrd_alignment == 1);

		ecb->dte_alignment = MAX(ecb->dte_alignment,
		    rec->dtrd_alignment);

		if (DTRACEACT_ISAGG(act->dta_kind)) {
			dtrace_aggregation_t *agg = (dtrace_aggregation_t *)act;

			assert(rec->dtrd_size != 0);
			assert(agg->dtag_first != NULL);
			assert(act->dta_prev->dta_intuple);
			assert(aggbase != UINT32_MAX);
			assert(curneeded != UINT32_MAX);

			agg->dtag_base = aggbase;

			curneeded = P2ROUNDUP(curneeded, rec->dtrd_alignment);
			rec->dtrd_offset = curneeded;
			if (curneeded + rec->dtrd_size < curneeded)
				return (EINVAL);
			curneeded += rec->dtrd_size;
			ecb->dte_needed = MAX(ecb->dte_needed, curneeded);

			aggbase = UINT32_MAX;
			curneeded = UINT32_MAX;
		} else if (act->dta_intuple) {
			if (curneeded == UINT32_MAX) {
				/*
				 * This is the first record in a tuple.  Align
				 * curneeded to be at offset 4 in an 8-byte
				 * aligned block.
				 */
				assert(act->dta_prev == NULL ||
				    !act->dta_prev->dta_intuple);
				ASSERT3U(aggbase, ==, UINT32_MAX);
				curneeded = P2PHASEUP(ecb->dte_size,
				    sizeof (uint64_t), sizeof (dtrace_aggid_t));

				aggbase = curneeded - sizeof (dtrace_aggid_t);
				assert(IS_P2ALIGNED(aggbase,
				    sizeof (uint64_t)));
			}
			curneeded = P2ROUNDUP(curneeded, rec->dtrd_alignment);
			rec->dtrd_offset = curneeded;
			if (curneeded + rec->dtrd_size < curneeded)
				return (EINVAL);
			curneeded += rec->dtrd_size;
		} else {
			/* tuples must be followed by an aggregation */
			assert(act->dta_prev == NULL ||
			    !act->dta_prev->dta_intuple);

			ecb->dte_size = P2ROUNDUP(ecb->dte_size,
			    rec->dtrd_alignment);
			rec->dtrd_offset = ecb->dte_size;
			if (ecb->dte_size + rec->dtrd_size < ecb->dte_size)
				return (EINVAL);
			ecb->dte_size += rec->dtrd_size;
			ecb->dte_needed = MAX(ecb->dte_needed, ecb->dte_size);
		}
	}

	if ((act = ecb->dte_action) != NULL &&
	    !(act->dta_kind == DTRACEACT_SPECULATE && act->dta_next == NULL) &&
	    ecb->dte_size == sizeof (dtrace_rechdr_t)) {
		/*
		 * If the size is still sizeof (dtrace_rechdr_t), then all
		 * actions store no data; set the size to 0.
		 */
		ecb->dte_size = 0;
	}

	ecb->dte_size = P2ROUNDUP(ecb->dte_size, sizeof (dtrace_epid_t));
	ecb->dte_needed = P2ROUNDUP(ecb->dte_needed, (sizeof (dtrace_epid_t)));
	ecb->dte_state->dts_needed = MAX(ecb->dte_state->dts_needed,
	    ecb->dte_needed);
	return (0);
}

static dtrace_ecb_t *
dtrace_ecb_create(dtrace_state_t *state, dtrace_probe_t *probe,
    dtrace_enabling_t *enab)
{
	dtrace_ecb_t *ecb;
	dtrace_predicate_t *pred;
	dtrace_actdesc_t *act;
	dtrace_provider_t *prov;
	dtrace_ecbdesc_t *desc = enab->dten_current;

	assert(state != NULL);

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
			assert(act->dta_refcnt > 0);
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
}

/*
 * DTrace Matching Functions
 *
 * These functions are used to match groups of probes, given some elements of
 * a probe tuple, or some globbed expressions for elements of a probe tuple.
 */
static int
dtrace_match_priv(const dtrace_probe_t *prp, uint32_t priv, uid_t uid,
    zoneid_t zoneid)
{
	if (priv != DTRACE_PRIV_ALL) {
		uint32_t ppriv = prp->dtpr_provider->dtpv_priv.dtpp_flags;
		uint32_t match = priv & ppriv;

		/*
		 * No PRIV_DTRACE_* privileges...
		 */
		if ((priv & (DTRACE_PRIV_PROC | DTRACE_PRIV_USER |
		    DTRACE_PRIV_KERNEL)) == 0)
			return (0);

		/*
		 * No matching bits, but there were bits to match...
		 */
		if (match == 0 && ppriv != 0)
			return (0);

		/*
		 * Need to have permissions to the process, but don't...
		 */
		if (((ppriv & ~match) & DTRACE_PRIV_OWNER) != 0 &&
		    uid != prp->dtpr_provider->dtpv_priv.dtpp_uid) {
			return (0);
		}

		/*
		 * Need to be in the same zone unless we possess the
		 * privilege to examine all zones.
		 */
		if (((ppriv & ~match) & DTRACE_PRIV_ZONEOWNER) != 0 &&
		    zoneid != prp->dtpr_provider->dtpv_priv.dtpp_zoneid) {
			return (0);
		}
	}

	return (1);
}

/*
 * dtrace_match_probe compares a dtrace_probe_t to a pre-compiled key, which
 * consists of input pattern strings and an ops-vector to evaluate them.
 * This function returns >0 for match, 0 for no match, and <0 for error.
 */
static int
dtrace_match_probe(const dtrace_probe_t *prp, const dtrace_probekey_t *pkp,
    uint32_t priv, uid_t uid, zoneid_t zoneid)
{
	dtrace_provider_t *pvp = prp->dtpr_provider;
	int rv;

	if (pvp->dtpv_defunct)
		return (0);

	if ((rv = pkp->dtpk_pmatch(pvp->dtpv_name, pkp->dtpk_prov, 0)) <= 0)
		return (rv);

	if ((rv = pkp->dtpk_mmatch(prp->dtpr_mod, pkp->dtpk_mod, 0)) <= 0)
		return (rv);

	if ((rv = pkp->dtpk_fmatch(prp->dtpr_func, pkp->dtpk_func, 0)) <= 0)
		return (rv);

	if ((rv = pkp->dtpk_nmatch(prp->dtpr_name, pkp->dtpk_name, 0)) <= 0)
		return (rv);

	if (dtrace_match_priv(prp, priv, uid, zoneid) == 0)
		return (0);

	return (rv);
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

static int
dtrace_match(const dtrace_probekey_t *pkp, uint32_t priv, uid_t uid,
    zoneid_t zoneid, int (*matched)(dtrace_probe_t *, void *), void *arg)
{
	dtrace_probe_t template, *probe;
	dtrace_hash_t *hash = NULL;
	int len, best = INT_MAX, nmatched = 0;
	dtrace_id_t i;

	/*
	 * If the probe ID is specified in the key, just lookup by ID and
	 * invoke the match callback once if a matching probe is found.
	 */
	if (pkp->dtpk_id != DTRACE_IDNONE) {
		if ((probe = dtrace_probe_lookup_id(pkp->dtpk_id)) != NULL &&
		    dtrace_match_probe(probe, pkp, priv, uid, zoneid) > 0) {
			(void) (*matched)(probe, arg);
			nmatched++;
		}
		return (nmatched);
	}

	template.dtpr_mod = (char *)pkp->dtpk_mod;
	template.dtpr_func = (char *)pkp->dtpk_func;
	template.dtpr_name = (char *)pkp->dtpk_name;

	/*
	 * We want to find the most distinct of the module name, function
	 * name, and name.  So for each one that is not a glob pattern or
	 * empty string, we perform a lookup in the corresponding hash and
	 * use the hash table with the fewest collisions to do our search.
	 */
	if (pkp->dtpk_mmatch == &dtrace_match_string &&
	    (len = dtrace_hash_collisions(dtrace_bymod, &template)) < best) {
		best = len;
		hash = dtrace_bymod;
	}

	if (pkp->dtpk_fmatch == &dtrace_match_string &&
	    (len = dtrace_hash_collisions(dtrace_byfunc, &template)) < best) {
		best = len;
		hash = dtrace_byfunc;
	}

	if (pkp->dtpk_nmatch == &dtrace_match_string &&
	    (len = dtrace_hash_collisions(dtrace_byname, &template)) < best) {
		best = len;
		hash = dtrace_byname;
	}

	/*
	 * If we did not select a hash table, iterate over every probe and
	 * invoke our callback for each one that matches our input probe key.
	 */
	if (hash == NULL) {
		for (i = 0; i < dtrace_nprobes; i++) {
			if ((probe = dtrace_probes[i]) == NULL ||
			    dtrace_match_probe(probe, pkp, priv, uid,
			    zoneid) <= 0)
				continue;

			nmatched++;

			if ((*matched)(probe, arg) != DTRACE_MATCH_NEXT)
				break;
		}

		return (nmatched);
	}

	/*
	 * If we selected a hash table, iterate over each probe of the same key
	 * name and invoke the callback for every probe that matches the other
	 * attributes of our input probe key.
	 */
	for (probe = dtrace_hash_lookup(hash, &template); probe != NULL;
	    probe = *(DTRACE_HASHNEXT(hash, probe))) {

		if (dtrace_match_probe(probe, pkp, priv, uid, zoneid) <= 0)
			continue;

		nmatched++;

		if ((*matched)(probe, arg) != DTRACE_MATCH_NEXT)
			break;
	}

	return (nmatched);
}

/*
 * Return the function pointer dtrace_probecmp() should use to compare the
 * specified pattern with a string.  For NULL or empty patterns, we select
 * dtrace_match_nul().  For glob pattern strings, we use dtrace_match_glob().
 * For non-empty non-glob strings, we use dtrace_match_string().
 */
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

/*
 * Build a probe comparison key for use with dtrace_match_probe() from the
 * given probe description.  By convention, a null key only matches anchored
 * probes: if each field is the empty string, reset dtpk_fmatch to
 * dtrace_match_nonzero().
 */
static void
dtrace_probekey(dtrace_probedesc_t *pdp, dtrace_probekey_t *pkp)
{
	pkp->dtpk_prov = pdp->dtpd_provider;
	pkp->dtpk_pmatch = dtrace_probekey_func(pdp->dtpd_provider);

	pkp->dtpk_mod = pdp->dtpd_mod;
	pkp->dtpk_mmatch = dtrace_probekey_func(pdp->dtpd_mod);

	pkp->dtpk_func = pdp->dtpd_func;
	pkp->dtpk_fmatch = dtrace_probekey_func(pdp->dtpd_func);

	pkp->dtpk_name = pdp->dtpd_name;
	pkp->dtpk_nmatch = dtrace_probekey_func(pdp->dtpd_name);

	pkp->dtpk_id = pdp->dtpd_id;

	if (pkp->dtpk_id == DTRACE_IDNONE &&
	    pkp->dtpk_pmatch == &dtrace_match_nul &&
	    pkp->dtpk_mmatch == &dtrace_match_nul &&
	    pkp->dtpk_fmatch == &dtrace_match_nul &&
	    pkp->dtpk_nmatch == &dtrace_match_nul)
		pkp->dtpk_fmatch = &dtrace_match_nonzero;
}

static int
dtrace_ecb_create_enable(dtrace_probe_t *probe, void *arg)
{
	dtrace_ecb_t *ecb;
	dtrace_enabling_t *enab = arg;
	dtrace_state_t *state = enab->dten_vstate->dtvs_state;

	assert(state != NULL);

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
		assert(pops->dtps_resume == NULL);
		provider->dtpv_pops.dtps_suspend =
		    (void (*)(void *, dtrace_id_t, void *))dtrace_nullop;
		provider->dtpv_pops.dtps_resume =
		    (void (*)(void *, dtrace_id_t, void *))dtrace_nullop;
	}

	provider->dtpv_arg = arg;
	*idp = (dtrace_provider_id_t)provider;
	dtrace_nprovs++;

	if (pops == &dtrace_provider_ops) {
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

/*
 * DTrace Predicate Functions
 */
static dtrace_predicate_t *
dtrace_predicate_create(dtrace_difo_t *dp)
{
	dtrace_predicate_t *pred;

	assert(dp->dtdo_refcnt != 0);

	pred = calloc(1, sizeof (dtrace_predicate_t));
	pred->dtp_difo = dp;
	pred->dtp_refcnt = 1;

	if (!dtrace_difo_cacheable(dp))
		return (pred);

	if (dtrace_predcache_id == DTRACE_CACHEIDNONE) {
		/*
		 * This is only theoretically possible -- we have had 2^32
		 * cacheable predicates on this machine.  We cannot allow any
		 * more predicates to become cacheable:  as unlikely as it is,
		 * there may be a thread caching a (now stale) predicate cache
		 * ID. (N.B.: the temptation is being successfully resisted to
		 * have this cmn_err() "Holy shit -- we executed this code!")
		 */
		return (pred);
	}

	pred->dtp_cacheid = dtrace_predcache_id++;

	return (pred);
}

/*
 * Unregister the specified provider from the DTrace framework.  This should
 * generally be called by DTrace providers in their detach(9E) entry point.
 */
int
dtrace_unregister(dtrace_provider_id_t id)
{
	dtrace_provider_t *old = (dtrace_provider_t *)id;
	dtrace_provider_t *prev = NULL;
	int i, self = 0, noreap = 0;
	dtrace_probe_t *probe, *first = NULL;

	if (old->dtpv_pops.dtps_enable ==
	    (void (*)(void *, dtrace_id_t, void *))dtrace_nullop) {
		/*
		 * If DTrace itself is the provider, we're called with locks
		 * already held.
		 */
		assert(old == dtrace_provider);
		self = 1;

		if (dtrace_provider->dtpv_next != NULL) {
			/*
			 * There's another provider here; return failure.
			 */
			return (EBUSY);
		}
	}

	/*
	 * Attempt to destroy the probes associated with this provider.
	 */
	for (i = 0; i < dtrace_nprobes; i++) {
		if ((probe = dtrace_probes[i]) == NULL)
			continue;

		if (probe->dtpr_provider != old)
			continue;

		if (probe->dtpr_ecb == NULL)
			continue;

		return (EAGAIN);
	}

	/*
	 * All of the probes for this provider are disabled; we can safely
	 * remove all of them from their hash chains and from the probe array.
	 */
	for (i = 0; i < dtrace_nprobes; i++) {
		if ((probe = dtrace_probes[i]) == NULL)
			continue;

		if (probe->dtpr_provider != old)
			continue;

		dtrace_probes[i] = NULL;

		dtrace_hash_remove(dtrace_bymod, probe);
		dtrace_hash_remove(dtrace_byfunc, probe);
		dtrace_hash_remove(dtrace_byname, probe);

		if (first == NULL) {
			first = probe;
			probe->dtpr_nextmod = NULL;
		} else {
			probe->dtpr_nextmod = first;
			first = probe;
		}
	}

	for (probe = first; probe != NULL; probe = first) {
		first = probe->dtpr_nextmod;

		old->dtpv_pops.dtps_destroy(old->dtpv_arg, probe->dtpr_id,
		    probe->dtpr_arg);
		free(probe->dtpr_mod);
		free(probe->dtpr_func);
		free(probe->dtpr_name);
		free_unr(dtrace_arena, probe->dtpr_id);
		free(probe);
	}

	if ((prev = dtrace_provider) == old) {
		dtrace_provider = old->dtpv_next;
	} else {
		while (prev != NULL && prev->dtpv_next != old)
			prev = prev->dtpv_next;

		if (prev == NULL) {
			return (ESRCH);
		}

		prev->dtpv_next = old->dtpv_next;
	}

	free(old->dtpv_name);
	free(old);

	return (0);
}

/*
 * DTrace Probe Management Functions
 *
 * The functions in this section perform the DTrace probe management,
 * including functions to create probes, look-up probes, and call into the
 * providers to request that probes be provided.  Some of these functions are
 * in the Provider-to-Framework API; these functions can be identified by the
 * fact that they are not declared "static".
 */

/*
 * Create a probe with the specified module name, function name, and name.
 */
dtrace_id_t
dtrace_probe_create(dtrace_provider_id_t prov, const char *mod,
    const char *func, const char *name, int aframes, void *arg)
{
	dtrace_probe_t *probe, **probes;
	dtrace_provider_t *provider = (dtrace_provider_t *)prov;
	dtrace_id_t id;

	id = alloc_unr(dtrace_arena);
	probe = calloc(1, sizeof (dtrace_probe_t));
	assert(probe != NULL);

	probe->dtpr_id = id;
	probe->dtpr_gen = dtrace_probegen++;
	probe->dtpr_mod = dtrace_strdup(mod);
	probe->dtpr_func = dtrace_strdup(func);
	probe->dtpr_name = dtrace_strdup(name);
	probe->dtpr_arg = arg;
	probe->dtpr_aframes = aframes;
	probe->dtpr_provider = provider;

	dtrace_hash_add(dtrace_bymod, probe);
	dtrace_hash_add(dtrace_byfunc, probe);
	dtrace_hash_add(dtrace_byname, probe);

	if (id - 1 >= dtrace_nprobes) {
		size_t osize = dtrace_nprobes * sizeof (dtrace_probe_t *);
		size_t nsize = osize << 1;

		if (nsize == 0) {
			assert(osize == 0);
			assert(dtrace_probes == NULL);
			nsize = sizeof (dtrace_probe_t *);
		}

		probes = calloc(1, nsize);
		assert(probes != NULL);

		if (dtrace_probes == NULL) {
			assert(osize == 0);
			dtrace_probes = probes;
			dtrace_nprobes = 1;
		} else {
			dtrace_probe_t **oprobes = dtrace_probes;

			bcopy(oprobes, probes, osize);
			dtrace_membar_producer();
			dtrace_probes = probes;

			free(oprobes);
			dtrace_nprobes <<= 1;
		}

		assert(id - 1 < dtrace_nprobes);
	}

	assert(dtrace_probes[id - 1] == NULL);
	dtrace_probes[id - 1] = probe;

	return (id);
}

static dtrace_probe_t *
dtrace_probe_lookup_id(dtrace_id_t id)
{
	if (id == 0 || id > dtrace_nprobes)
		return (NULL);

	return (dtrace_probes[id - 1]);
}

static int
dtrace_probe_lookup_match(dtrace_probe_t *probe, void *arg)
{
	*((dtrace_id_t *)arg) = probe->dtpr_id;

	return (DTRACE_MATCH_DONE);
}

/*
 * Look up a probe based on provider and one or more of module name, function
 * name and probe name.
 */
dtrace_id_t
dtrace_probe_lookup(dtrace_provider_id_t prid, char *mod,
    char *func, char *name)
{
	dtrace_probekey_t pkey;
	dtrace_id_t id;
	int match;

	pkey.dtpk_prov = ((dtrace_provider_t *)prid)->dtpv_name;
	pkey.dtpk_pmatch = &dtrace_match_string;
	pkey.dtpk_mod = mod;
	pkey.dtpk_mmatch = mod ? &dtrace_match_string : &dtrace_match_nul;
	pkey.dtpk_func = func;
	pkey.dtpk_fmatch = func ? &dtrace_match_string : &dtrace_match_nul;
	pkey.dtpk_name = name;
	pkey.dtpk_nmatch = name ? &dtrace_match_string : &dtrace_match_nul;
	pkey.dtpk_id = DTRACE_IDNONE;

	match = dtrace_match(&pkey, DTRACE_PRIV_ALL, 0, 0,
	    dtrace_probe_lookup_match, &id);

	assert(match == 1 || match == 0);
	return (match ? id : 0);
}

/*
 * Returns the probe argument associated with the specified probe.
 */
void *
dtrace_probe_arg(dtrace_provider_id_t id, dtrace_id_t pid)
{
	dtrace_probe_t *probe;
	void *rval = NULL;

	if ((probe = dtrace_probe_lookup_id(pid)) != NULL &&
	    probe->dtpr_provider == (dtrace_provider_t *)id)
		rval = probe->dtpr_arg;

	return (rval);
}

/*
 * Copy a probe into a probe description.
 */
static void
dtrace_probe_description(const dtrace_probe_t *prp, dtrace_probedesc_t *pdp)
{
	bzero(pdp, sizeof (dtrace_probedesc_t));
	pdp->dtpd_id = prp->dtpr_id;

	(void) strncpy(pdp->dtpd_provider,
	    prp->dtpr_provider->dtpv_name, DTRACE_PROVNAMELEN - 1);

	(void) strncpy(pdp->dtpd_mod, prp->dtpr_mod, DTRACE_MODNAMELEN - 1);
	(void) strncpy(pdp->dtpd_func, prp->dtpr_func, DTRACE_FUNCNAMELEN - 1);
	(void) strncpy(pdp->dtpd_name, prp->dtpr_name, DTRACE_NAMELEN - 1);
}

/*
 * Called to indicate that a probe -- or probes -- should be provided by a
 * specfied provider.  If the specified description is NULL, the provider will
 * be told to provide all of its probes.  (This is done whenever a new
 * consumer comes along, or whenever a retained enabling is to be matched.) If
 * the specified description is non-NULL, the provider is given the
 * opportunity to dynamically provide the specified probe, allowing providers
 * to support the creation of probes on-the-fly.  (So-called _autocreated_
 * probes.)  If the provider is NULL, the operations will be applied to all
 * providers; if the provider is non-NULL the operations will only be applied
 * to the specified provider.  The dtrace_provider_lock must be held, and the
 * dtrace_lock must _not_ be held -- the provider's dtps_provide() operation
 * will need to grab the dtrace_lock when it reenters the framework through
 * dtrace_probe_lookup(), dtrace_probe_create(), etc.
 */
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


#ifdef illumos
/*
 * Iterate over each probe, and call the Framework-to-Provider API function
 * denoted by offs.
 */
static void
dtrace_probe_foreach(uintptr_t offs)
{
	dtrace_provider_t *prov;
	void (*func)(void *, dtrace_id_t, void *);
	dtrace_probe_t *probe;
	dtrace_icookie_t cookie;
	int i;

	for (i = 0; i < dtrace_nprobes; i++) {
		if ((probe = dtrace_probes[i]) == NULL)
			continue;

		if (probe->dtpr_ecb == NULL) {
			/*
			 * This probe isn't enabled -- don't call the function.
			 */
			continue;
		}

		prov = probe->dtpr_provider;
		func = *((void(**)(void *, dtrace_id_t, void *))
		    ((uintptr_t)&prov->dtpv_pops + offs));

		func(prov->dtpv_arg, i + 1, probe->dtpr_arg);
	}

	dtrace_interrupt_enable(cookie);
}
#endif

int
dtrace_init(void)
{
	dtrace_provider_id_t id;
	int err;

	dtrace_arena = new_unrhdr(1, INT_MAX, &dtrace_unr_mtx);

	dtrace_bymod = dtrace_hash_create(offsetof(dtrace_probe_t, dtpr_mod),
	    offsetof(dtrace_probe_t, dtpr_nextmod),
	    offsetof(dtrace_probe_t, dtpr_prevmod));

	dtrace_byfunc = dtrace_hash_create(offsetof(dtrace_probe_t, dtpr_func),
	    offsetof(dtrace_probe_t, dtpr_nextfunc),
	    offsetof(dtrace_probe_t, dtpr_prevfunc));

	dtrace_byname = dtrace_hash_create(offsetof(dtrace_probe_t, dtpr_name),
	    offsetof(dtrace_probe_t, dtpr_nextname),
	    offsetof(dtrace_probe_t, dtpr_prevname));

	err = dtrace_register("dtrace", &dtrace_provider_attr,
	    DTRACE_PRIV_NONE, 0, &dtrace_provider_ops, NULL, &id);

	dtrace_provider = (dtrace_provider_t *) id;
	assert(dtrace_provider != NULL);
	assert((dtrace_provider_id_t) dtrace_provider == id);

	dtrace_probeid_begin = dtrace_probe_create(id, NULL, NULL, "BEGIN", 0, NULL);
	dtrace_probeid_end = dtrace_probe_create(id, NULL, NULL, "END", 0, NULL);
	dtrace_probeid_error = dtrace_probe_create(id, NULL, NULL, "ERROR", 1, NULL);

	return (err);
}

int
dtrace_deinit(void)
{
	/*
	 * XXX: Should we unregister everything here through deinit?
	 */

	int err;
	err = dtrace_unregister((dtrace_provider_id_t) dtrace_provider);

	dtrace_hash_destroy(dtrace_bymod);
	dtrace_hash_destroy(dtrace_byfunc);
	dtrace_hash_destroy(dtrace_byname);

	delete_unrhdr(dtrace_arena);

	return (err);
}

char *
dtrace_providers(size_t *sz)
{
	dtrace_provider_t *pv;
	size_t n;
	char *providers;
	char *p;

	n = 0;
	providers = malloc(dtrace_nprovs * DTRACE_PROVNAMELEN);
	p = providers;

	for (pv = dtrace_provider; pv != NULL; pv = pv->dtpv_next) {
		n++;
		memcpy(p, pv->dtpv_name, DTRACE_PROVNAMELEN);
		p += DTRACE_PROVNAMELEN;
	}

	*sz = n;
	return (providers);
}
