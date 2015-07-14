#!/bin/bash

file="/var/tmp/lockfirewall"
[ $2 ] && pid=$2 || pid=1

function lock () {
    [ -z "$file" ] && return 1;
    lock="$file.lock"
    link="$file.lock.$pid"
    touch $link
    i=0
    while (( $i < 11 ))
    do
          ln -s $link $lock >/dev/null 2>&1 && break
          sleep 1
          i=$(( $i + 1 ))
    done
    if (( $i < 11 ))
    then
       return 0
    else
       rm -f $link 2>/dev/null
       return 1
    fi
}

function unlock () {
    [ -z "$file" ] && return 1;
    lock="$file.lock"
    link="$file.lock.$pid"
    rm -f $lock $link 2>/dev/null
    return 0
}

[ "$1" == "lock" ] && lock || unlock
