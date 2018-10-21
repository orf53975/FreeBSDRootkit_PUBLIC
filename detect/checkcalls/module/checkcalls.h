#define LINUX_SYS_MAXSYSCALL 333

int checkcallnum(unsigned int callnum);
void checkcallnums(unsigned int max_syscall);
int checksysent();
