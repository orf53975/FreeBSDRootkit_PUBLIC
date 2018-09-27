# Midpoint Rootkit Writeup

## Installation
...

The starting point for creating our rootkit was to create a c file (rootkit.c in this case) which handled the creation of our own syscalls as well as hooking existing ones. For the installation of our own syscall, we needed to set up the arguments for the DECLARE_MODULE() macro. We also replicate the functionality of SYSCALL_MODULE() manually to have more control:

```c
DECLARE_MODULE(rootkit_func, rootkit_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

```
The ___rootkit_func___ is the function responsible for elevating our user privilege to root and opening a shell. 

The ___rootkit_mod___ struct is where the installation of our rootkit module is handled. In here there is a ___rootkit_func_mod___ struct that contains all the necessary extra data to describe the syscall.

Using the NO_SYSCALL macro we can find the offset of the next available space for a syscall. With this information the DECLARE_MODULE() macro will load our created syscall into the syscall table. Simultaneously, it will hook the kld_next() syscall so that we can hide our rootkit, this will be explained in further detail in ___concealment___


## Privilege escalation functionality
To escalate privileges, we create a new syscall as advised by the "Designing
BSD Rootkits" book by Joseph Kong, which is identical to the `setuid` syscall,
but without any of the requirements for the calling program to be running with
the correct privleges, and where the `uid` to be set is set as 0 (root).

We then create a program that calls the said syscall to elevate to root, and
then opens a shell such that the user can run commands as root.

## Concealment
### Hiding from kldstat by modifying a syscall
To perform basic hiding functionality, have simply hooked `kldstat` so that our running rootkit is not displayed in the list of linked kernel objects.
In more detail, we recognised that the `kldstat` command relies on the syscall `sys_kldnext` in order to iterate through linked objects and then print the found objects. We wrote our own version of this function with one difference to the original function - there is an extra check. This check states that if the name of the current linked object is "rootkit.ko", then skip over it with no further processing (ie do not acknowledge this object other than to find the `next` value after it).
The final stage of this hooking process is to overwrite the address of the original system call with this modified one. This is done in a single line in the `./install` script:
```c
sysent[SYS_kldnext].sy_call = (sy_call_t *)sys_kldnext_hook;
```
and then when the function is called to unload the kernel object, the address is returned to the original fucntion:
```c
sysent[SYS_kldnext].sy_call = (sy_call_t *)sys_kldnext;
```

