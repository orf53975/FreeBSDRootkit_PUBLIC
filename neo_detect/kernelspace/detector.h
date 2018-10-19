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

#include <sys/nlist_aout.h>

#define LINKER_FILE "detector.ko"
#define MODULE_NAME "detector"

#define PRINTERR(string, ...) do {\
        uprintf(string, __VA_ARGS__);\
        return -1;\
    } while(0)

/* The system call's arguments. */
struct detector_args {
	int command;
	char ** args;
};

typedef __uint64_t kvaddr_t;

struct kvm_nlist {
    const char *n_name;
    unsigned char n_type;
    kvaddr_t n_value;
};

int run_all_tests(struct thread * td, struct detector_args * uap, int offset);

/* Test functions */
int check_syscalls(void);
int additional_syscalls(int offset);
int checkcall(const char *name, unsigned long int callnum);
int checkcallnums(unsigned int max_syscall);
int checksysent(void);
int check_all_syscalls(void);
