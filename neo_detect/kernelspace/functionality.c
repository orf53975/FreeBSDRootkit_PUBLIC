#include "detector.h"
#include "syscalls.h"

int sym_lookup(struct kvm_nlist *nl);

int run_all_tests(struct thread * td, struct detector_args * uap, int offset) {
	int result = 0;

	result = check_syscalls();
	if(result)
		return result;

	result = additional_syscalls(offset);
	if(result)
		return result;

	result = checksysent();
    if(result)
		return result;

	result = check_threads();
	if(result)
		return result;

    // result = checkcallnums(SYS_MAXSYSCALL);
    // result = check_all_syscalls();

	return 0;
}

int check_all_syscalls(void) {

	uprintf("Checking syscall table...\n");

	int max_syscall = sizeof(syscalls) / sizeof(sy_call_t *);

    int rootkit = 0;
	for(int i = 0; i < max_syscall; i++) {
		if(sysent[i].sy_call != syscalls[i]) {
			uprintf("Conflict at sysent[%3d] (%s)\n", i, syscallnames[i]);
			rootkit = 1;
		}
	}

	return rootkit;
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
		SYS_kldsym,
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
		&sys_kldsym,
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
	int num_to_check = sizeof(call_to_check) / sizeof(int);

	for(int i = 0; i < num_to_check; i++) {
		if(sysent[call_to_check[i]].sy_call != func_to_check[i]) {
			uprintf("Detected a conflict on syscall %d\n", call_to_check[i]);
			return 1;
		}
	}

	return 0;
}

int additional_syscalls(int offset) {
	uprintf("Checking for additional syscalls...\n");

	for(int i = 210; i <= 219; i++) {
		if((void *)sysent[i].sy_call != &lkmnosys) {
			if(i != offset) {
				uprintf("Syscall found at id %d\n", i);
				return 1;
			}
		}
	}

	return 0;
}


// extern uma_zone_t thread_zone;

int check_threads(void) {
	// uprintf("%p\n", thread_zone);

	return 0;
}

static int checkcall(const char *name, unsigned long int callnum){

    struct kvm_nlist *nl = { NULL };
    nl[0].n_name = name;
    if (sym_lookup(nl) < 0) PRINTERR("ERROR: Unable to lookup: %s\n", name);

    sy_call_t *sy_call = (sy_call_t*)nl[0].n_value;
    if (!sy_call) PRINTERR("ERROR: %s not found (%p)\n", name, sy_call);

    uprintf(
        "sysent[%3lu].sy_call -> %p (%s) {%d}\n",
        callnum, sysent[callnum].sy_call, name, nl[0].n_type
    );

    if (sysent[callnum].sy_call != sy_call) {
        uprintf("ALERT! It should point to %p instead\n", sy_call);
        return 1;
    }

    return 0;

}

int checkcallnums(unsigned int max_syscall) {
    int retval = 0;
    for (unsigned int i = 0; i < max_syscall; i++) {
        const char *name = syscallnames[i];
        int status = checkcall(name, i);
        if (status) {
            uprintf("'%s' is hooked!", name);
        } else {
            uprintf("'%s' is normal.", name);
        }
        if (status) retval = status;
    }
    return retval;
}

int checksysent(void) {
    //return -1;
    return curproc->p_sysent->sv_table != sysent;
}

int sym_lookup(struct kvm_nlist *nl) {

    struct kvm_nlist *p = nl;
    if (! (p->n_name && p->n_name[0]))
        return -1;

    if (p->n_type != N_UNDF)
        return -1;

    char symname[1024]; //XXX-BZ symbol name length limit?
    const char *prefix = "";
    int error = snprintf(
        symname,
        sizeof(symname),
        "%s%s",
        prefix,
        (prefix[0] != '\0' && p->n_name[0] == '_')
            ? (p->n_name + 1) : p->n_name
    );

    if (error < 0 || error >= (int)sizeof(symname))
        return -1;

    struct kld_sym_lookup lookup;
    lookup.version = sizeof(lookup);
    lookup.symvalue = 0;
    lookup.symsize = 0;
    lookup.symname = symname;

    if (lookup.symname[0] == '_')
        lookup.symname++;

    struct kldsym_args args;
    args.fileid = 0;
    args.cmd = KLDSYM_LOOKUP;
    args.data = &lookup;

    //if (kldsym(0, KLDSYM_LOOKUP, &lookup) != -1) {
    if (sys_kldsym(curthread, &args) != -1) {
        p->n_type = N_TEXT;
        //if (_kvm_vnet_initialized(kd, initialize) &&
        //		strcmp(prefix, VNET_SYMPREFIX) == 0)
        //	p->n_value =
        //		_kvm_vnet_validaddr(kd, lookup.symvalue);
        //else if (_kvm_dpcpu_initialized(kd, initialize) &&
        //		strcmp(prefix, DPCPU_SYMPREFIX) == 0)
        //	p->n_value =
        //		_kvm_dpcpu_validaddr(kd, lookup.symvalue);
        //else
        p->n_value = lookup.symvalue;
    }

    return 0;
}
