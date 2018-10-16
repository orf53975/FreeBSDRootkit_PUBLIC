#define LINKER_FILE "check_sys_calls.ko"
#define MODULE_NAME "check_sys_calls"

#define UNLOAD          0
#define CHECKSYSENT     1
#define CHECKCALLNUM    2
#define CHECKCALLNUMS   3
#define LINUX_SYS_MAXSYSCALL 333

#include <sys/cdefs.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
//#include <sys/kvm.h> //
#include <sys/limits.h> //
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/nlist.h> //
#include <sys/param.h>
//#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
//#include <sys/stdio.h>
//#include <sys/stdlib.h>
//#include <sys/string.h>
//#include <sys/stat.h>
#include <sys/sx.h>
#include <sys/syscall.h>
//#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/types.h>

#define PRINTERR(string, ...) do {\
        printf(string, __VA_ARGS__);\
        exit(-1);\
    } while(0)

struct kvm_nlist {
    const char *n_name;
    unsigned char n_type;
    kvaddr_t n_value;
}

extern struct sx kld_sx;
extern linker_file_list_t linker_files;

int checkcallnum(unsigned int callnum);
void checkcallnums(unsigned int max_syscall);
int checksysent();

