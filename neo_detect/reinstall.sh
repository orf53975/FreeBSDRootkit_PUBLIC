#!/bin/sh
cd kernelspace

./reinstall.sh

cd ..

cd userspace

cc u_detector.c -o detector

cd ..
