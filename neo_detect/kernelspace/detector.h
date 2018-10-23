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

#include <vm/uma.h>
#include <sys/nlist_aout.h>

// Network includes
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip_encap.h>

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

extern struct protosw inetsw[];

int run_all_tests(struct thread * td, struct detector_args * uap, int offset);

/* Test functions */
int check_syscalls(void);
int additional_syscalls(int offset);
int check_threads(void);
int checkcall(const char *name, unsigned long int callnum);
int checkcallnums(unsigned int max_syscall);
int checksysent(void);
int check_all_syscalls(int offset);
int check_inetsw(void);
