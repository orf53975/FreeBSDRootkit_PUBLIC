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
...

## Concealment
...

## Bonus marks
### Remote network root access
...

### Input Keylogging and Exfiltration
...

### Reboot Persistence
...

