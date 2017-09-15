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

#ifndef _DTRACE_API_H_
#define	_DTRACE_API_H_

#ifndef _DTRACE_TESTS
#error _DTRACE_TESTS is not defined.
#endif

struct dtapi_conf;
typedef struct dtapi_conf dtapi_conf_t;

typedef struct dtapi_state {
	int64_t	cc_r;
	uint8_t	cc_c;
	uint8_t	cc_n;
	uint8_t	cc_v;
	uint8_t	cc_z;
} dtapi_state_t;

/*
 * DTrace API initialization and deinitialization
 */
dtapi_conf_t *	dtapi_init_full(size_t, size_t,
             	    uint32_t, const uint64_t *, const char *);
dtapi_conf_t *	dtapi_init(size_t, size_t, uint32_t);
void		dtapi_deinit(dtapi_conf_t *);
void		dtapi_set_textlen(dtapi_conf_t *, uint_t);
dtapi_state_t *	dtapi_getstate(dtapi_conf_t *);

/*
 * Low-level operations
 */
void		dtapi_op_nop(dtapi_conf_t *, int *);
uint_t		dtapi_op_ret(dtapi_conf_t *, int *);
uint64_t	dtapi_op_or(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_xor(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_and(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_sll(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_srl(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_sra(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_sub(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_add(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_mul(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_sdiv(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_udiv(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_srem(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_urem(dtapi_conf_t *, uint64_t, uint64_t, int *);
uint64_t	dtapi_op_not(dtapi_conf_t *, uint64_t, int *);
uint64_t	dtapi_op_mov(dtapi_conf_t *, uint64_t, int *);
void		dtapi_op_cmp(dtapi_conf_t *, uint64_t, uint64_t, int *);
void		dtapi_op_scmp(dtapi_conf_t *, uintptr_t, uintptr_t, int *);
void		dtapi_op_tst(dtapi_conf_t *, uint64_t, int *);
uint_t		dtapi_op_ba(dtapi_conf_t *, uint_t, int *);
uint_t		dtapi_op_be(dtapi_conf_t *, uint_t, int *);
uint_t		dtapi_op_bne(dtapi_conf_t *, uint_t, int *);
uint_t		dtapi_op_bg(dtapi_conf_t *, uint_t, int *);
uint_t		dtapi_op_bgu(dtapi_conf_t *, uint_t, int *);
uint_t		dtapi_op_bge(dtapi_conf_t *, uint_t, int *);
uint_t		dtapi_op_bgeu(dtapi_conf_t *, uint_t, int *);
uint_t		dtapi_op_bl(dtapi_conf_t *, uint_t, int *);
uint_t		dtapi_op_blu(dtapi_conf_t *, uint_t, int *);
uint_t		dtapi_op_ble(dtapi_conf_t *, uint_t, int *);
uint_t		dtapi_op_bleu(dtapi_conf_t *, uint_t, int *);
uint64_t	dtapi_op_ldsb(dtapi_conf_t *, int8_t, int *);
uint64_t	dtapi_op_ldsh(dtapi_conf_t *, int16_t, int *);
uint64_t	dtapi_op_ldsw(dtapi_conf_t *, int32_t, int *);
uint64_t	dtapi_op_ldub(dtapi_conf_t *, uint8_t, int *);
uint64_t	dtapi_op_lduh(dtapi_conf_t *, uint16_t, int *);
uint64_t	dtapi_op_lduw(dtapi_conf_t *, uint32_t, int *);
uint64_t	dtapi_op_ldx(dtapi_conf_t *, uint64_t, int *);
uint64_t	dtapi_op_rldsb(dtapi_conf_t *, int8_t, int *);
uint64_t	dtapi_op_rldsh(dtapi_conf_t *, int16_t, int *);
uint64_t	dtapi_op_rldsw(dtapi_conf_t *, int32_t, int *);
uint64_t	dtapi_op_rldub(dtapi_conf_t *, uint8_t, int *);
uint64_t	dtapi_op_rlduh(dtapi_conf_t *, uint16_t, int *);
uint64_t	dtapi_op_rlduw(dtapi_conf_t *, uint32_t, int *);
uint64_t	dtapi_op_rldx(dtapi_conf_t *, uint64_t, int *);
uint64_t	dtapi_var_args(dtapi_conf_t *, uint64_t [5], uint64_t,
        	    dtrace_id_t, int *);
void		dtapi_var_set_epid(dtapi_conf_t *, uint64_t);
uint64_t	dtapi_var_epid(dtapi_conf_t *, int *);
void		dtapi_set_probe(dtapi_conf_t *, dtrace_id_t);
uint64_t	dtapi_var_id(dtapi_conf_t *, int *);
char *		dtapi_var_probeprov(dtapi_conf_t *, int *);
char *		dtapi_var_probemod(dtapi_conf_t *, int *);
char *		dtapi_var_probefunc(dtapi_conf_t *, int *);
char *		dtapi_var_probename(dtapi_conf_t *, int *);
pid_t		dtapi_var_pid(dtapi_conf_t *, int *);
pid_t		dtapi_var_ppid(dtapi_conf_t *, int *);
uint64_t	dtapi_var_tid(dtapi_conf_t *, int *);
char *		dtapi_var_execname(dtapi_conf_t *, int *);
uid_t		dtapi_var_uid(dtapi_conf_t *, int *);
gid_t		dtapi_var_gid(dtapi_conf_t *, int *);
errno_t		dtapi_var_errno(dtapi_conf_t *, int *);
uint64_t	dtapi_var_arbitrary(dtapi_conf_t *, uint64_t, int *);
uint64_t	dtapi_op_setx(dtapi_conf_t *, uint64_t, int *);
uint64_t	dtapi_op_sets(dtapi_conf_t *, uint64_t, int *);
void		dtapi_op_pushtr(dtapi_conf_t *,
    		    uint8_t, uint64_t, uint64_t, int *);
void		dtapi_op_pushtv(dtapi_conf_t *, uint64_t, int *);
void		dtapi_op_popts(dtapi_conf_t *, int *);
void		dtapi_op_flushts(dtapi_conf_t *, int *);

/*
 * Subroutines
 */
size_t		dtapi_strlen(dtapi_conf_t *, const char *, int *);
void *		dtapi_bcopy(dtapi_conf_t *, const void *,
    		    size_t, int *);
char *		dtapi_strchr(dtapi_conf_t *, const char *, int, int *);
char *		dtapi_strrchr(dtapi_conf_t *, const char *, int, int *);
char *		dtapi_strstr(dtapi_conf_t *, const char *, const char *, int *);
char *		dtapi_strtok(dtapi_conf_t *, char *, const char *, int *);
char *		dtapi_substr(dtapi_conf_t *, const char *,
      		    size_t, size_t, int *);
char *		dtapi_toupper(dtapi_conf_t *, const char *, int *);
char *		dtapi_tolower(dtapi_conf_t *, const char *, int *);
char *		dtapi_strjoin(dtapi_conf_t *, const char *, const char *, int *);
int64_t		dtapi_strtoll(dtapi_conf_t *conf, const char *, int *);
char *		dtapi_lltostr(dtapi_conf_t *conf, int64_t, int *);
uint16_t	dtapi_htons(dtapi_conf_t *, uint16_t, int *);
uint32_t	dtapi_htonl(dtapi_conf_t *, uint32_t, int *);
uint64_t	dtapi_htonll(dtapi_conf_t *, uint64_t, int *);
uint16_t	dtapi_ntohs(dtapi_conf_t *, uint16_t, int *);
uint32_t	dtapi_ntohl(dtapi_conf_t *, uint32_t, int *);
uint64_t	dtapi_ntohll(dtapi_conf_t *, uint64_t, int *);
char *		dtapi_basename(dtapi_conf_t *, const char *, int *);
char *		dtapi_dirname(dtapi_conf_t *, const char *, int *);
char *		dtapi_cleanpath(dtapi_conf_t *, const char *, int *);
uintptr_t *	dtapi_memref(dtapi_conf_t *, uintptr_t, size_t, int *);

#endif /* _DTRACE_API_H_ */
