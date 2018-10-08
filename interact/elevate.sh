#!/bin/sh
cc elevate.c
sys_num=$(dmesg | grep "system call loaded at offset" | tail -1 | grep -Eo "[0-9]+")
echo $sys_num
./a.out $sys_num
