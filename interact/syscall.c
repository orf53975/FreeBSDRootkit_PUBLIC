#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/module.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char ** argv)
{
	// ./a.out syscall_num cmd arg
	int syscall_num = atoi(argv[1]);
	int cmd = atoi(argv[2]);
	char ** newArgs = &argv[3];

	int errcode = syscall(syscall_num, cmd, newArgs);

	// system("/bin/sh");

	printf("-> %d\n", errcode);

	return errcode;
}
