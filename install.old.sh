#!/bin/sh
clear
make
kldunload ./rootkit.ko
kldload ./rootkit.ko
