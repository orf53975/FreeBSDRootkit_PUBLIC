# Midpoint Rootkit Writeup

## Installation
...

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

