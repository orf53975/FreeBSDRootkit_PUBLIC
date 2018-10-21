#!/bin/sh


sys_num=$(cat /etc/good_luck_finding_this/syscall_number.txt)
./syscall $sys_num 2 $1
