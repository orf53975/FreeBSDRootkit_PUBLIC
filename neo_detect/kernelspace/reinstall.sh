#!/bin/sh
clear
kldunload ./detector.ko
make clean
make
kldload ./detector.ko
