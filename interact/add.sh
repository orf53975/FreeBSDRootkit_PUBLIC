sys_num=$(cat /etc/trivial/syscall_number.txt)
./syscall $sys_num 2 $1
