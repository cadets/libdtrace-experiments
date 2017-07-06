#ifndef _UNR_SHIM_H_
#define	_UNR_SHIM_H_

#include <sys/queue.h>
#include <pthread.h>

struct unrhdr {
	TAILQ_HEAD(unrhd,unr)	head;
	u_int			low;	/* Lowest item */
	u_int			high;	/* Highest item */
	u_int			busy;	/* Count of allocated items */
	u_int			alloc;	/* Count of memory allocations */
	u_int			first;	/* items in allocated from start */
	u_int			last;	/* items free at end */
	pthread_mutex_t		*mtx;
	TAILQ_HEAD(unrfr,unr)	ppfree;	/* Items to be freed after mtx
					   lock dropped */
};

#endif

