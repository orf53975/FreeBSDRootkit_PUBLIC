#include "detector.h"

int run_all_tests(struct thread * td, struct detector_args * uap) {
	int result = 0;

	result = check_syscalls();
	if(result)
		return result;

	result = additional_syscalls();
	if(result)
		return result;

	return 0;
}


int check_syscalls(void) {
	uprintf("Checking syscall table...\n");

	int call_to_check[] = {
		SYS_chdir,
		SYS_chmod,
		SYS_chown,
		SYS_execve,
		SYS_getdirentries,
		SYS_ioctl,
		SYS_kill,
		SYS_kldload,
		SYS_kldnext,
		SYS_kldunload,
		SYS_lstat,
		SYS_open,
		SYS_openat,
		SYS_pread,
		SYS_preadv,
		SYS_pwrite,
		SYS_pwritev,
		SYS_read,
		SYS_readv,
		SYS_rename,
		SYS_rmdir,
		SYS_stat,
		SYS_truncate,
		SYS_unlink,
		SYS_write,
		SYS_writev
	};
	void * func_to_check[] = {
		&sys_chdir,
		&sys_chmod,
		&sys_chown,
		&sys_execve,
		&sys_getdirentries,
		&sys_ioctl,
		&sys_kill,
		&sys_kldload,
		&sys_kldnext,
		&sys_kldunload,
		&sys_lstat,
		&sys_open,
		&sys_openat,
		&sys_pread,
		&sys_preadv,
		&sys_pwrite,
		&sys_pwritev,
		&sys_read,
		&sys_readv,
		&sys_rename,
		&sys_rmdir,
		&sys_stat,
		&sys_truncate,
		&sys_unlink,
		&sys_write,
		&sys_writev
	};
	int num_to_check = 26;

	for(int i = 0; i < num_to_check; i++) {
		if(sysent[call_to_check[i]].sy_call != func_to_check[i]) {
			uprintf("Detected a conflict on syscall %d\n", call_to_check[i]);
			return 1;
		}
	}

	return 0;
}

int additional_syscalls(void) {
	uprintf("Checking for additional syscalls...\n");
	return 0;
}
