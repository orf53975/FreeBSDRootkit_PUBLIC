#!/bin/sh
make clean
make
kldload ./rootkit.ko
