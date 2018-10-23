#include "detector.h"

struct node * first_node = NULL;

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

/* The system call function. */
static int main(struct thread *td, void *syscall_args) {

	struct detector_args *uap;
	uap = (struct detector_args *)syscall_args;

	switch(uap->command){
		case 0:
			*(int *)uap->args = offset;
			break;
		case 1:
			*(int *)uap->args = run_all_tests(td, uap, offset);
		default:
			break;
	}

	return(0);
}

/* The sysent for the new system call. */
static struct sysent detector_sysent = {
	2,			/* number of arguments */
	main		/* implementing function */
};

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
	int error = 0;

	switch (cmd) {
		case MOD_LOAD:
			printf("Detector loaded at syscall: %d\n", offset);
			break;
		case MOD_UNLOAD:
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}

	return(error);
}

static struct syscall_module_data detector_func_mod = {
	load, NULL, &offset, &detector_sysent, { 0, NULL }
};

static moduledata_t detector_mod = {
	MODULE_NAME,
	syscall_module_handler,
	&detector_func_mod
};

DECLARE_MODULE(detector, detector_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

