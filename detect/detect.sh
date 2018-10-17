#!/bin/sh

while read name num
do
    # returning 1 means rootkit, 0 means fine
    echo "Testing [$name] [$num]"
    if  ! ./checkcalls/checkcall/checkcall -c $name $num # idk why but this needs to be inverted
    then
        echo "Detection says... [$name] has been hooked"
        exit 1
    fi
done <syscalls.txt

echo "No syscalls have been hooked"

exit 0