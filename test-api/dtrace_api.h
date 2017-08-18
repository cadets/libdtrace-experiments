#ifndef _DTRACE_API_H_
#define	_DTRACE_API_H_

#include "../libdtrace-core/dtrace.h"
#include "../libdtrace-core/dtrace_impl.h"

#ifndef _DTRACE_TESTS
#error _DTRACE_TESTS is not defined.
#endif

size_t		dtapi_strlen(const char *);
void		dtapi_bcopy(const void *, const void *, size_t);
char *		dtapi_strchr(const char *, int);
char *		dtapi_strrchr(const char *, int);
char *		dtapi_strstr(const char *, const char *);
char *		dtapi_strtok(char *, const char *);
char *		dtapi_substr(const char *, size_t, size_t);
char *		dtapi_toupper(const char *);
char *		dtapi_tolower(const char *);
char *		dtapi_strjoin(const char *, const char *);
long long	dtapi_strtoll(const char *);
char *		dtapi_lltostr(long long);
uint16_t	dtapi_htons(uint16_t);
uint32_t	dtapi_htonl(uint32_t);
uint64_t	dtapi_htonll(uint64_t);
uint16_t	dtapi_ntohs(uint16_t);
uint32_t	dtapi_ntohl(uint32_t);
uint64_t	dtapi_ntohll(uint64_t);
char *		dtapi_basename(const char *);
char *		dtapi_dirname(const char *);
char *		dtapi_cleanpath(const char *);
uintptr_t *	dtapi_memref(uintptr_t);

#endif /* _DTRACE_API_H_ */
