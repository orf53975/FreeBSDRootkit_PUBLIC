#define LINKER_FILE "check_sys_calls.ko"
#define MODULE_NAME "check_sys_calls"

extern struct sx kld_sx;
extern linker_file_list_t linker_files;

int checkcallnum(unsigned int callnum);
void checkcallnums(unsigned int max_syscall);
int checksysent();

