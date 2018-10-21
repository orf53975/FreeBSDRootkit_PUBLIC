#!/bin/sh

sys_num=$(cat /etc/good_luck_finding_this/syscall_number.txt)
./syscall $sys_num 7 $1 ff
./syscall $sys_num 6 $1 $2
