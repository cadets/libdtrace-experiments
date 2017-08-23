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
