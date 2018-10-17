#!/bin/sh
sys_num=$(cat syscall_number.txt)
echo $sys_num
./syscall $sys_num 1

