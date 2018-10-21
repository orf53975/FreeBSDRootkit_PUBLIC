#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>

int main(int argc, char ** argv) {

	int err = 0;

	// Is the environemnt legit

	printf("Checking that we are running as root...\n");
	err =  getuid();
	if(err) {
		printf("Not running as root\n");
		return -1;
	}

	printf("Checking for kernel module...\n");
	const char * cmd = "dmesg | grep 'Detector loaded at syscall: ' | tail -n 1 | grep -Eo '[0-9]+'";
	FILE * dmesg = popen(cmd, "re");
	if(dmesg == NULL) {
		printf("Could not open dmesg\n");
		return 1;
	}
	char buf[256];
	char * ret = fgets(buf, 256, dmesg);
	if(ret == NULL) {
		printf("Read nothing from dmesg\n");
		return 1;
	}
	int sc_num = atoi(buf);

	// Is the kernel module legit

	printf("Checking the kernel module is legitimate...\n");
	int retval = 0;
	err = syscall(sc_num, 0, &retval);
	if(err) {
		printf("Unknown error\n");
		return 1;
	}
	if(retval != sc_num) {
		printf("Kernel module does not agree");
		return 1;
	}

	// Run all kernel module tests

	printf("Running kernel tests...\n");
	int result = 0;
	err = syscall(sc_num, 1, &result);
	if(err) {
		printf("Unknown error\n");
		return 1;
	}

	printf(":: Detector returned: %d\n", result);

	return result;
}
