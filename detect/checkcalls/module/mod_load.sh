#!/bin/sh
clear
kldunload ./check_sys_calls.ko
make clean
make
kldload ./check_sys_calls.ko
