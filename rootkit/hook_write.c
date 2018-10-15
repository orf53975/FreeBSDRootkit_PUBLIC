#include "rootkit.h"

// struct write_args {
// 	int	fd;
// 	const void *buf;
// 	size_t	nbyte;
// };

int hook_sys_write(struct thread * td, struct write_args * uap) {
	return sys_write(td, uap);
}
