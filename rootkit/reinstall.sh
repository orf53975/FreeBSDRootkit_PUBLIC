#!/bin/sh
clear
kldunload ./rootkit.ko
make clean
make
kldload ./rootkit.ko
