# Group 1337 Rootkit Assignment

## Rootkit

### Changes since midpoint writeup

Almost every aspect of the original midpoint rootkit has been completely
rewritten: For example the original rootkit hid itself from kldstat by hooking
kldnext, 'skipping' over the kernel module if it had the same name as the
rootkit. This meant that it was still in the kernel module list but it looked
like it wasn't. Now, the kernel module is unlinked from the list entirely.

The new rootkit also has a lot of new features, including being able to hide
multiple files, create files from kernel space, log keystrokes, etc.

### How The Rootkit Installs Itself

The rootkit is installed as a kernel module with a syscall component, taking
advantage of the DECLARE_MODULE macro. There was the option to use the
SYSCALL_MODULE macro, but this rootkit opts to do the extra setup manually to
allow for more control. The `load()` function for the rootkit module also calls
some functions to write the new syscall's number to a _.txt_ file so that it
can be later used dynamically as opposed to harcoding the number when it is
needed. After installation this file (and others like it) will be hidden using
methods explained in the hiding section.

Our rootkit can then be used by calling the syscall and issuing a command:
There is an API structure allowing for interaction with the rootkit. For
example calling the syscall with the argument '1' will load all of the hooked
syscalls into the sysent table, and argument '2' will restore them back to
normal. This API style is used to make script writing easier/more intuitive.

### How The Rootkit Escalates Privelege/Gets Root Access

When executed, the elevate.sh script will grab the syscall number for our
rootkit's syscall from the hidden _syscall\_number.txt_ file. The rootkit uses
a `switch` statement: when the first syscall argument is '3' it will call
`elevate(td)`, a function that calls a series of internal kernel functions
(such as `change_ruid()`, `change_svuid()`) to make it appear that it is
running as `root`. After these IDs are set the function `system("/bin/sh")` is
called to open a shell, which will be a root shell because the IDs are set
accordingly.

### How The Rootkit Hides Itself

There are a few methods that our rootkit uses to attempt to hide itself from
any potential detectors. For file-system related hiding, the syscalls `open()`,
`openat()`, and `getdirentries()` are hooked. In the rootkit there is an array
which is stored in kernel memory containing structs, each of these structs
contains a 'name' and a 'flag' field, which can be edited/added to by use of
our created syscall. The mentioned hooked syscalls check these flags to see if
they can be read from, written to, or viewed via 'ls.' For example if the
rootkit is installed, and the filename 'test' is added to the struct with a
R_FLAG_READ only flag; any file named 'test' will be unseeable via 'ls', can't
be written to, but CAN be read from (such as 'cat test').

The second way that the Rootkit can hide itself is by unlinking the created
kernel module from the linker_files list. On load, the kernel module will
iterate through the linker files until it finds the one with the 'rootkit.ko'
name. It will then call `TAILQ_REMOVE()` on this link, making it seem as if
the rootkit isn't there at all. This prevents it from turning up on things like
`kldstat` or any programs manually cycling through this linker file list.

### Bonus Feature: Keylogger

The keylogger functionality of the rootkit is achieved by hooking the `read()`
syscall. `read()` will do what it usually does, but afterwards it will use
`copyinstr()` to copy what is entered from userspace (stdin) and then store it
in a buffer of size 1.

This buffer is then printed to another hidden file named 'keystrokes.txt' using
the same technique as writing to the syscall_number.txt file on installation.
Inspecting this file will reveal anything a user has entered into stdin.

---

## Rootkit detector

### Design decisions for rootkit detection
Our detector was designed to run as a kernel level syscall so that we can use
all kernel symbols as such as every syscall in the sysent table, including the
sysent table itself. With this access, we can very easily check if any syscalls
in the table are hooked by iterating through the syscall table and checking for
the gloablly defined symbols.

Additionally, by running the detector at the kernel level, we are able to gain
access to the current process, and thus are easily able to check for whether
the sysent table has been replaced by comparing the symbol to the table in the
process. Our syscall has been setup in such a way that it will run a series of
test functions like the above, and only needs to be called from a user program
with the required arguments.

Finally, because of these requirements, we gain additional detection features
as we are required to do a series of tests that check if the detector has been
properly installed and is functioning as expected.

### Rootkit methods being detected
* Hooked Syscalls (Hooked with methods similar to those in the text)
* Shadowed `sysent` table.
* Unable to execute as root.
* Unable to load a kernel module.
* Hooked syscall return values.

---
