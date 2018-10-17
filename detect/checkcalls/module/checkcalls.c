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

#include "check_sys_calls.h"

int sym_lookup(struct kvm_nlist *nl);

int checkcall(const char *name, unsigned long int callnum){

    struct kvm_nlist *nl = { NULL };
    nl[0].n_name = name;
    if (sym_lookup(nl) < 0) PRINTERR("ERROR: Unable to lookup: %s\n", name);

    sy_call_t *sy_call = (sy_call_t*)nl[0].n_value;
    if (!sy_call) PRINTERR("ERROR: %s not found (%p)\n", name, sy_call);

    uprintf(
        "sysent[%3lu].sy_call -> %p (%s) {%d}\n",
        callnum, sysent[callnum].sy_call, name, nl[0].n_type
    );

    if (sysent[callnum].sy_call != sy_call) {
        uprintf("ALERT! It should point to %p instead\n", sy_call);
        return 1;
    }

    return 0;

}

int checkcallnums(unsigned int max_syscall) {
    int retval = 0;
    for (unsigned int i = 0; i < max_syscall; i++) {
        const char *name = syscallnames[i];
        int status = checkcall(name, i);
        if (status) {
            uprintf("'%s' is hooked!", name);
        } else {
            uprintf("'%s' is normal.", name);
        }
        if (status) retval = status;
    }
    return retval;
}

int checksysent(void) {
    return -1;
    //return aout_sysvec.sv_table != sysent;
}

int sym_lookup(struct kvm_nlist *nl) {


    struct kvm_nlist *p = nl;
    if (! (p->n_name && p->n_name[0]))
        return -1;

    if (p->n_type != N_UNDF)
        return -1;

    char symname[1024]; //XXX-BZ symbol name length limit?
    const char *prefix = "";
    int error = snprintf(
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

    struct kldsym_args args;
    args.fileid = 0;
    args.cmd = KLDSYM_LOOKUP;
    args.data = &lookup;

    //if (kldsym(0, KLDSYM_LOOKUP, &lookup) != -1) {
    if (sys_kldsym(curthread, &args) != -1) {
        p->n_type = N_TEXT;
        //if (_kvm_vnet_initialized(kd, initialize) &&
        //		strcmp(prefix, VNET_SYMPREFIX) == 0)
        //	p->n_value =
        //		_kvm_vnet_validaddr(kd, lookup.symvalue);
        //else if (_kvm_dpcpu_initialized(kd, initialize) &&
        //		strcmp(prefix, DPCPU_SYMPREFIX) == 0)
        //	p->n_value =
        //		_kvm_dpcpu_validaddr(kd, lookup.symvalue);
        //else
        p->n_value = lookup.symvalue;
    }

    return 0;
}
