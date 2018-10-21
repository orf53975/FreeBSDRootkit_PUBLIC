#!/bin/sh
make clean
make
kldload ./detector.ko
