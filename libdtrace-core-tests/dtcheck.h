#ifndef _DTCHECK_H_
#define _DTCHECK_H_

#define	DTCHECK(expr, message)			\
	do {					\
		if (expr) {			\
			printf message;		\
			return (1);		\
		}				\
	} while (0)

#define	DTCHECKSTR(str1, str2, message)		\
	DTCHECK(strcmp((str1), (str2)) != 0, message)

#endif
