#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	int syscall_num = atoi(argv[1]);

	int errcode = syscall(syscall_num, 1, "");

	printf("%d\n", errcode);

	system("/bin/sh");

	return errcode;
}
