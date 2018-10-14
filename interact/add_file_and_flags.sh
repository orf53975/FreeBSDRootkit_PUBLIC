cc syscall.c
./a.out 210 2 testfile.txt
./a.out 210 5 testfile.txt 255
cc open_test.c
ktrace ./a.out
