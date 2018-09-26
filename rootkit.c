#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysproto.h>

/* The system call's arguments. */
struct rootkit_args {
};

/* The system call function. */
static int
rootkit_func(struct thread *td, void *syscall_args) {
	struct rootkit_args *uap;
	uap = (struct rootkit_args *)syscall_args;

	return(0);
}

/* The sysent for the new system call. */
static struct sysent sc_example_sysent = {
	0,			/* number of arguments */
	rootkit_func		/* implementing function */
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		uprintf("System call loaded at offset %d.\n", offset);
		break;

	case MOD_UNLOAD:
		uprintf("System call unloaded from offset %d.\n", offset);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return(error);
}

SYSCALL_MODULE(rootkit_func, &offset, &sc_example_sysent, load, NULL);
