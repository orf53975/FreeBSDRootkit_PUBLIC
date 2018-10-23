#!/bin/sh
cd kernelspace

./install.sh

cd ..

cd userspace

cc u_detector.c -o detector

cd ..
