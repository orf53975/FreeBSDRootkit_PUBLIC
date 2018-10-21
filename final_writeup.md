#Group 1337 Rootkit Assignment

##Rootkit 
---

###How The Rootkit Installs Itself


The rootkit is installed as a module with a syscall component, taking advantage of the DECLARE_MODULE macro. There was the option to use the SYSCALL_MODULE macro, but this rootkit opts to do the extra setup manuall to allow for more control. The load() function for the rootkit module also calls some functions to write the new syscall's number to a .txt file so that it can be used later dynamically as opposed to harcoding the number when it is needed.



###How The Rootkit Escalates Privelege/Gets Root Access
---

###How The Rootkit Hides Itself
---

There are a few methods that our rootkit uses to attempt to hide itself from any potential detectors. For file-system related hiding, the syscalls open(), openat(), and getdirentries() are hooked. In the rootkit there is an array which is stored in kernel memory containing structs, each of these structs contains a 'name' and a 'flag' field, which can be edited/added to by use of our created syscall. The mentioned hooked syscalls check these flags to see if they can be read from, written to, or viewed via 'ls.' For example if the rootkit is installed, and the filename 'test' is added to the struct with a R\_FLAG\_READ only flag; any file named 'test' will be unseeable via 'ls', can't be written to, but CAN be read from (such as 'cat test').

The second way that the Rootkit can hide itself is by unlinking the created kernel module from the linker_files list. On load, the kernel module will iterate through the linker files until it finds the one with the 'rootkit.ko' name. It will then call TAILQ_REMOVE() on this link, making it seem as if the rootkit isn't there at all. This prevents it from turning up on things like kldstat or manually cycling through this linker file list.



###Bonus Feature: Keylogger
---


###Design decisions for rootkit detection
---


###Changes since midpoint writeup
---


##Rootkit detector
---


###Design decisions for rootkit detection
---


###Rootkit methods being detected
---
