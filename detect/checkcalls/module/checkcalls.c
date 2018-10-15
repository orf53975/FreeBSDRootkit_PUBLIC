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

#include "checkcalls.h"


#define PRINTERR(string, ...) do {\
        fprintf(stderr, string, __VA_ARGS__);\
        exit(-1);\
    } while(0)

int checkcallnum(unsigned int callnum) {

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
        retval = 1;
    } else {
        retval = 0;
    }

    if (kvm_close(kd) < 0) PRINTERR("ERROR: %s\n", kvm_geterr(kd));

    return retval;
}

int checkcallnums(unsigned int max_syscall) {
    int retval = 0;
    for (unsigned int i = 0; i < max_syscall; i++) {
        int status = checkcallnum(i)
        printf("syscall %d is %d\n", i, status);
        if (status) retval = status;
    }
    return retval;
}

int checksysent() {

    char errbuf[_POSIX2_LINE_MAX];
    //kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
    //if (!kd) PRINTERR("ERROR: %s\n", errbuf);

    //struct nlist nl[] = { { NULL }, { NULL }, { NULL }, };

    struct sysent call;

    //nl[0].n_name = "sysent";
	char *symname = "sysent";

    //printf("Checking sysent addr\n\n");

    /* Find the address of sysent*/
    //if (kvm_nlist(kd, nl) < 0) PRINTERR("ERROR: %s\n", kvm_geterr(kd));


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
        retval = 1;
    } else {
        retval = 0;
    }

    if (kvm_close(kd) < 0) PRINTERR("ERROR: %s\n", kvm_geterr(kd));

    return retval;
}

int sym_lookup(struct nlist *nl) {

	int nvalid;
	int error;
	const char *prefix = "";
	int tried_vnet, tried_dpcpu;


	struct kvm_nlist *p = nl;
	if (! (p->n_name && p->n_name[0]))
		return -1;

	if (p->n_type != N_UNDF)
		return -1;

	char symname[1024]; /* XXX-BZ symbol name length limit? */
	error = snprintf(
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

	if (kldsym(0, KLDSYM_LOOKUP, &lookup) != -1) {
		p->n_type = N_TEXT;
		/*
		if (_kvm_vnet_initialized(kd, initialize) &&
				strcmp(prefix, VNET_SYMPREFIX) == 0)
			p->n_value =
				_kvm_vnet_validaddr(kd, lookup.symvalue);
		else if (_kvm_dpcpu_initialized(kd, initialize) &&
				strcmp(prefix, DPCPU_SYMPREFIX) == 0)
			p->n_value =
				_kvm_dpcpu_validaddr(kd, lookup.symvalue);
		else
		*/
			p->n_value = lookup.symvalue;
	}

	return 0;
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
