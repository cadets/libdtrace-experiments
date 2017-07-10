#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtrace.h"
#include "dtrace_impl.h"
#include "unr_shim.h"

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
			ASSERT(!((align - (offs & (align - 1))) &
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
				ASSERT(state->dts_ecbs[epid - 1] != NULL);

				size = state->dts_ecbs[epid - 1]->dte_size;
			}

			ASSERT(woffs + size <= buf->dtb_size);
			ASSERT(size != 0);

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
		ASSERT(!((align - (offs & (align - 1))) &
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
				ASSERT(svar != NULL);
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

			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;

			VERIFY(id < vstate->dtvs_nglobals);
			svar = vstate->dtvs_globals[id];
			ASSERT(svar != NULL);
			v = &svar->dtsv_var;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t a = (uintptr_t)svar->dtsv_data;
				size_t lim;

				ASSERT(a != 0);
				ASSERT(svar->dtsv_size != 0);

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

			ASSERT(id < vstate->dtvs_nlocals);
			ASSERT(vstate->dtvs_locals != NULL);

			svar = vstate->dtvs_locals[id];
			ASSERT(svar != NULL);
			v = &svar->dtsv_var;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t a = (uintptr_t)svar->dtsv_data;
				size_t sz = v->dtdv_type.dtdt_size;
				size_t lim;

				sz += sizeof (uint64_t);
				ASSERT(svar->dtsv_size == NCPU * sz);
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

			ASSERT(svar->dtsv_size == NCPU * sizeof (uint64_t));
			tmp = (uint64_t *)(uintptr_t)svar->dtsv_data;
			regs[rd] = tmp[curcpu];
			break;

		case DIF_OP_STLS:
			id = DIF_INSTR_VAR(instr);

			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;
			VERIFY(id < vstate->dtvs_nlocals);

			ASSERT(vstate->dtvs_locals != NULL);
			svar = vstate->dtvs_locals[id];
			ASSERT(svar != NULL);
			v = &svar->dtsv_var;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t a = (uintptr_t)svar->dtsv_data;
				size_t sz = v->dtdv_type.dtdt_size;
				size_t lim;

				sz += sizeof (uint64_t);
				ASSERT(svar->dtsv_size == NCPU * sz);
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

			ASSERT(svar->dtsv_size == NCPU * sizeof (uint64_t));
			tmp = (uint64_t *)(uintptr_t)svar->dtsv_data;
			tmp[curcpu] = regs[rd];
			break;

		case DIF_OP_LDTS: {
			dtrace_dynvar_t *dvar;
			dtrace_key_t *key;

			id = DIF_INSTR_VAR(instr);
			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;
			v = &vstate->dtvs_tlocals[id];

			key = &tupregs[DIF_DTR_NREGS];
			key[0].dttk_value = (uint64_t)id;
			key[0].dttk_size = 0;
			DTRACE_TLS_THRKEY(key[1].dttk_value);
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
			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;
			VERIFY(id < vstate->dtvs_ntlocals);

			key = &tupregs[DIF_DTR_NREGS];
			key[0].dttk_value = (uint64_t)id;
			key[0].dttk_size = 0;
			DTRACE_TLS_THRKEY(key[1].dttk_value);
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
			curthread->t_predcache = 0;

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

		case DIF_OP_LDGAA:
		case DIF_OP_LDTAA: {
			dtrace_dynvar_t *dvar;
			dtrace_key_t *key = tupregs;
			uint_t nkeys = ttop;

			id = DIF_INSTR_VAR(instr);
			ASSERT(id >= DIF_VAR_OTHER_UBASE);
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

		case DIF_OP_STGAA:
		case DIF_OP_STTAA: {
			dtrace_dynvar_t *dvar;
			dtrace_key_t *key = tupregs;
			uint_t nkeys = ttop;

			id = DIF_INSTR_VAR(instr);
			ASSERT(id >= DIF_VAR_OTHER_UBASE);
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
				ASSERT(state->dts_activity ==
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
		ASSERT(tomax != NULL);

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
					ASSERT(cid == pred->dtp_cacheid);
					curthread->t_predcache = cid;
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

			default:
				break;
			}

			dp = act->dta_difo;
			ASSERT(dp != NULL);

			val = dtrace_dif_emulate(dp, &mstate, vstate, state);

			if (*flags & CPU_DTRACE_ERROR)
				continue;

			switch (act->dta_kind) {
			case DTRACEACT_SPECULATE: {
				dtrace_rechdr_t *dtrh;

				ASSERT(buf == &state->dts_buffer[cpuid]);
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
				ASSERT(tomax != NULL);

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

			case DTRACEACT_COMMIT:
				ASSERT(!committed);

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
				    valoffs, (uint64_t) curproc->p_pid);
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
				ASSERT(0);
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
				ASSERT(0);
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
				curthread->t_dtrace_start = 0;
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
			    cpu_core[cpuid].cpuc_dtrace_illval);

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
