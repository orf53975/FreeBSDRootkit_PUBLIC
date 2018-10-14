/*-
 * Copyright (c) 2007 Joseph Kong.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Copyright (c) 2001, Stephanie Wehner <atrak@itsx.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysent.h>

#include <sys/kernel.h>

#define LINUX_SYS_MAXSYSCALL 333

#define PRINTERR(string, ...) do {\
        fprintf(stderr, string, __VA_ARGS__);\
        exit(-1);\
    } while(0)

void usage();
int checkcall(unsigned int callnum);
void checkcalls(unsigned int max_syscall);
int printcall();
void printcalls(unsigned int max_syscall);
int checksysent();

int main(int argc, char *argv[])
{
    /* Check arguments.
    if (argc < 3) {
        usage();
        exit(-1);
    }
    */

    //if (argv[1] && strncmp(argv[1], "-a", 2)) printcalls(LINUX_SYS_MAXSYSCALL);
    if (argv[1] && strncmp(argv[1], "-s", 2)) checksysent();
    if (argv[1] && strncmp(argv[1], "-c", 2)) checkcalls(LINUX_SYS_MAXSYSCALL);

    return 0;
}

int checkcall(unsigned int callnum) {

    char errbuf[_POSIX2_LINE_MAX];
    kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
    if (!kd) PRINTERR("ERROR: %s\n", errbuf);

    struct nlist nl[] = { { NULL }, { NULL }, { NULL }, };

    nl[0].n_name = "sysent";

    printf("Checking system call: %d\n\n", callnum);

    /* Find the address of sysent[]*/
    if (kvm_nlist(kd, nl) < 0) PRINTERR("ERROR: %s\n", kvm_geterr(kd));

    if (nl[0].n_value) {
        printf(
            "%s[] is 0x%x at 0x%lx\n",
            nl[0].n_name,
            nl[0].n_type,
            nl[0].n_value
        );
    } else {
        PRINTERR("ERROR: %s not found (very weird...)\n", nl[0].n_name);
    }

    if (!nl[1].n_value) PRINTERR("ERROR: %s not found\n", nl[1].n_name);

    /* Determine the address of sysent[callnum]. */
    unsigned long sym_call_addr = nl[0].n_value + callnum * sizeof(struct sysent);

    /* Copy sysent[callnum]. */
    struct sysent sym_call;
    if (kvm_read(kd, sym_call_addr, &sym_call, sizeof(struct sysent)) < 0)
        PRINTERR("ERROR: %s\n", kvm_geterr(kd));

    /* Where does sysent[callnum].sy_call point to? */
    printf(
        "sysent[%d] is at 0x%lx and its sy_call member points to "
        "%p\n", callnum, sym_call_addr, sym_call.sy_call
    );

    /* Check if that's correct. */
    int retval;
    if ((uintptr_t)sym_call.sy_call != sysent[callnum]) {
        printf(
            "ALERT! It should point to 0x%lx instead\n",
            nl[1].n_value
        );
        retval = 0;
    } else {
        retval = 1;
    }

    if (kvm_close(kd) < 0) PRINTERR("ERROR: %s\n", kvm_geterr(kd));

    return retval;
}

void checkcalls(unsigned int max_syscall) {
    for (unsigned int i = 0; i < max_syscall; i++)
        printf("syscall %d is %d\n", i, checkcall(i));
}

int printcall(unsigned int callnum) {

    char errbuf[_POSIX2_LINE_MAX];
    kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
    if (!kd) PRINTERR("ERROR: %s\n", errbuf);

    struct nlist nl[] = { { NULL }, { NULL }, { NULL }, };

    unsigned long addr;
    struct sysent call;

    nl[0].n_name = "sysent";

    printf("Checking system call: %d\n\n", callnum);

    /* Find the address of sysent[]*/
    if (kvm_nlist(kd, nl) < 0) PRINTERR("ERROR: %s\n", kvm_geterr(kd));

    if (nl[0].n_value) {
        printf(
            "%s[] is 0x%x at 0x%lx\n",
            nl[0].n_name,
            nl[0].n_type,
            nl[0].n_value
        );
    } else {
        PRINTERR("ERROR: %s not found (very weird...)\n", nl[0].n_name);
    }

    if (!nl[1].n_value) PRINTERR("ERROR: %s not found\n", nl[1].n_name);

    /* Determine the address of sysent[callnum]. */
    addr = nl[0].n_value + callnum * sizeof(struct sysent);

    /* Copy sysent[callnum]. */
    if (kvm_read(kd, addr, &call, sizeof(struct sysent)) < 0)
        PRINTERR("ERROR: %s\n", kvm_geterr(kd));

    /* Where does sysent[callnum].sy_call point to? */
    printf(
        "sysent[%d] is at 0x%lx and its sy_call member points to "
        "%p\n", callnum, addr, call.sy_call
    );

    /* Check if that's correct. */
    if ((uintptr_t)call.sy_call != nl[1].n_value) {
        printf(
            "ALERT! It should point to 0x%lx instead\n",
            nl[1].n_value
        );
    }

    if (kvm_close(kd) < 0) PRINTERR("ERROR: %s\n", kvm_geterr(kd));
}

void printcalls(unsigned int max_syscall) {
    for (unsigned int i = 0; i < max_syscall; i++) printcall(i);
}

int checksysent() {

    char errbuf[_POSIX2_LINE_MAX];
    kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
    if (!kd) PRINTERR("ERROR: %s\n", errbuf);

    struct nlist nl[] = { { NULL }, { NULL }, { NULL }, };

    struct sysent call;

    nl[0].n_name = "sysent";

    printf("Checking sysent addr\n\n");

    /* Find the address of sysent*/
    if (kvm_nlist(kd, nl) < 0) PRINTERR("ERROR: %s\n", kvm_geterr(kd));

    unsigned long sysent_sym_addr = nl[0].n_value;
    if (sysent_sym_addr) {
        printf(
            "%s[] is 0x%x at 0x%lx\n",
            nl[0].n_name,
            nl[0].n_type,
            nl[0].n_value
        );
    } else {
        PRINTERR("ERROR: %s not found (very weird...)\n", nl[0].n_name);
    }

    int retval;
    /* Check if that's correct. */
    if (sysent_sym_addr != sysent) {
        printf(
            "ALERT! It should point to 0x%lx instead\n",
            sysent_sym_addr
        );
        retval = 0;
    } else {
        retval = 1;
    }

    if (kvm_close(kd) < 0) PRINTERR("ERROR: %s\n", kvm_geterr(kd));

    return retval;
}

void usage() {
    fprintf(
        stderr,
        "Usage:\ncheckcall [system call function] [call number] <fix>\n\n"
    );
    fprintf(
        stderr,
        "For a list of system call numbers see "
        "/sys/sys/syscall.h\n"
    );
}
