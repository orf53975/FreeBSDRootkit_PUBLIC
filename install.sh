#!/bin/sh

clear
echo "==========="
make
echo "==========="
kldunload ./rootkit.ko
echo "==========="
kldload ./rootkit.ko