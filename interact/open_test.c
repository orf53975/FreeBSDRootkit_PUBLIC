#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

int main(int argc, char ** argv)
{
	char buf[256] = {0};
	int fd = syscall(5, "testfile.txt", O_RDONLY);
	printf("%d\n", fd);
	read(fd, buf, 256);
	printf("%s\n", buf);
	close(fd);
}
