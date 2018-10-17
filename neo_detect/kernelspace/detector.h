
#include <sys/stat.h>
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

#include <sys/systm.h>
#include <sys/pcpu.h>
#include <sys/fcntl.h>
#include <sys/file.h>

#define LINKER_FILE "detector.ko"
#define MODULE_NAME "detector"

/* The system call's arguments. */
struct detector_args {
	int command;
	char ** args;
};

int run_all_tests(struct thread * td, struct detector_args * uap);

/* Test functions */
int check_syscalls(void);
int additional_syscalls(void);
