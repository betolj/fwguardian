#!/bin/bash
#
# Lock file and call squid-inotify

nrcall=0
logger=$(which logger)

function lock () {
    file="/tmp/sqinotify.$(basename $1)"
    [ -z "$file" ] && return 1;
    lock="$file.lock"
    link="$file.lock.$$"
    touch $link
    i=0
    while (( $i < 15 ))
    do
          ln -s $link $lock >/dev/null 2>&1 && break
          sleep 1
          i=$(( $i + 1 ))
          nrcall=$i
    done
    if (( $i < 15 ))
    then
       return 0
    else
       rm -f $link 2>/dev/null
       return 1
    fi
}

function unlock () {
    file="/tmp/sqinotify.$(basename $1)"
    [ -z "$file" ] && return 1;
    lock="$file.lock"
    link="$file.lock.$$"
    rm -f $lock $link 2>/dev/null
    return 0
}

plog() {
   msg=$@
   msg=$(echo $msg | tr '\n' ' ')
   if [ $(echo $@ | wc -m) -gt 1 ]; then
      $logger -i -p daemon.info -t "squid-inotify" "$msg"
      echo -e "$msg"
   fi
}

# Call squid-inotify only for the first file event
if [ -f /etc/squid/scripts/control/synccall ] || [ -f /tmp/fullsync.lock ]; then
   /etc/squid/scripts/squid-inotify $1
else
   lock "$1" || {
       plog "ERROR: Cannot lock $1"
       exit 2
   }
   [ $nrcall -lt 1 ] && /etc/squid/scripts/squid-inotify $1

   unlock "$1"
fi
