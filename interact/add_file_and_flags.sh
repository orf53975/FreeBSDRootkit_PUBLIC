cc syscall.c -o syscall
./syscall 210 2 testfile.txt
./syscall 210 4 testfile.txt ff
cc open_test.c
ktrace ./a.out
