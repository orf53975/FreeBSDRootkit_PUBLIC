#include "rootkit.h"

int hook_sys_execve(struct thread *td, struct execve_args *uap) {
	// uprintf("%s\n", uap->fname);
	return sys_execve(td, uap);
}
