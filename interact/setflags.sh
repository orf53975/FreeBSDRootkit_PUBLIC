sys_num=$(cat /etc/trivial/syscall_number.txt)
./syscall $sys_num 5 $1 ff
./syscall $sys_num 4 $1 $2
