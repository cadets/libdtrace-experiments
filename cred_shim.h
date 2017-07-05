#ifndef _CRED_SHIM_H_
#define _CRED_SHIM_H_

typedef struct ucred cred_t;
typedef struct ucred ucred_t;

#define	crgetuid(cred)		((cred)->cr_uid)
#define	crgetruid(cred)		((cred)->cr_ruid)
#define	crgetgid(cred)		((cred)->cr_gid)
#define	crgetgroups(cred)	((cred)->cr_groups)
#define	crgetngroups(cred)	((cred)->cr_ngroups)
#define	crgetsid(cred, i)	(NULL)
#define	crgetzoneid(_a)	(0)


#endif /* _CRED_SHIM_H_ */
