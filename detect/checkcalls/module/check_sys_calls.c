#include "check_sys_calls.h"

/* The system call's arguments. */
struct checkcalls_args {
    unsigned int command;
    char *args[];
};

/* The system call function. */
static int checkcall_main(struct thread *td, void *syscall_args) {

	struct checkcalls_args *uap;
	uap = (struct checkcalls_args*)syscall_args;
    int retval = 0;


	switch(uap->command){
		case UNLOAD:// Unload
			break;
		case CHECKSYSENT:// Escalate
            retval = checksysent();
			break;
		case CHECKCALLNUM:// File hide
            retval = checkcallnum(
                (unsigned long int)strtoul(uap->args[2], (char **)NULL, 10)
            );
			break;
		case CHECKCALLNUMS:
            checkcallnums(LINUX_SYS_MAXSYSCALL);
			break;
		default:
			uprintf("Bad command\n");
			break;
	}

	return retval;
}

/* The sysent for the new system call. */
static struct sysent checkcall_sysent = {
	2,			/* number of arguments */
	checkcall_main		/* implementing function */
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		//printf("system call loaded at offset %d.\n", offset);
		//sysent[SYS_kldnext].sy_call = (sy_call_t *)sys_kldnext_hook;
		//printf("kldnext hooked\n");
		//sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries_hook;
		//printf("getdirentries hooked\n");
		break;

	case MOD_UNLOAD:
		//printf("system call unloaded from offset %d.\n", offset);
		//sysent[SYS_kldnext].sy_call = (sy_call_t *)sys_kldnext;
		//printf("kldnext unhooked\n");
		//sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;
		//printf("getdirentries unhooked\n");
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return(error);
}

static struct syscall_module_data checkcall_func_mod = {
	load, NULL, &offset, &checkcall_sysent, { 0, NULL }
};

static moduledata_t checkcall_mod = {
	MODULE_NAME,
	syscall_module_handler,
	&checkcall_func_mod
};

DECLARE_MODULE(check_sys_calls, checkcall_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
