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
...
