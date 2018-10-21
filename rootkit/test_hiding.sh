cd ../rootkit
sudo ./install.old.sh
cd ../interact
cc syscall.c
echo Before Adding to hide list:
ls
./a.out 210 2 test1
./a.out 210 2 test2
./a.out 210 2 test3
echo After Adding to hide list:
ls
echo Removing test2 from hide list:
./a.out 210 3 test2
ls
