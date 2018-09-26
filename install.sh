#!/bin/sh

make
kldunload ./rootkit.ko
kldload ./rootkit.ko
