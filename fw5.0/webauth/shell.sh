#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# shellinabox controler
#
#   1. Start a new shellinabox session
#      ./shell.sh start <cookie> <tcp_port> <sess_command>
# 
#   2. Reset all shellinabox sessions
#      ./shell.sh reset
#

PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

sh=$(which bash)
logger=$(which logger)

FW_DIR=$1
shell_cmd=$2
shell_cookie=$3
shift 3
shell_pid="/tmp/sessions/cgisess_$shell_cookie.app.shellinabox"

if [ -f "$shell_pid" ]; then
   kill -9 $(cat $shell_pid) 2>/dev/null >/dev/null
   rm -f $shell_pid 2>&1 >/dev/null
fi

if [ "$shell_cmd" == "start" ] || [ "$shell_cmd" == "starthttp" ]; then
   if [ ! -f "$shell_pid" ]; then
      shell_port=$1
      shell_app=$2
      shift 2

      shell_sesscmd=$@
      shellinabox=$(which shellinaboxd)
      if [ $shell_app == "bandwidth" ]; then
         scert="-t"
         [ -d /usr/share/fwguardian/webauth/control/ssl ] && [ "$shell_cmd" == "start" ] && scert="-c /usr/share/fwguardian/webauth/control/ssl"
         shell_sesscmd="/usr/share/fwguardian/webauth/bandwidth.sh $shell_sesscmd"
         echo $shellinabox --background=$shell_pid $scert --port=$shell_port -s \"/:fwguardian:nogroup:HOME:\"\'/bin/bash -c \"sudo $shell_sesscmd\"\' | $sh -
         $logger -i -p daemon.info -t "fwguardian(webauth):" "Loading shellinabox command *bandwidth*"
      fi
   fi
else
   if [ "$shell_cmd" == "reset" ]; then
      ls /tmp/sessions/cgisess*.shellinabox 2>/dev/null | \
      while read line; do
         if [ -f "$line" ]; then
            kill -9 $(cat $line) 2>/dev/null >/dev/null
            rm -f $line 2>&1 >/dev/null
         fi
      done

      kill -9 $(pidof shellinaboxd) 2>/dev/null >/dev/null
      [ -f /etc/init.d/shellinabox ] && /etc/init.d/shellinabox restart 2>/dev/null >/dev/null
   fi
fi

exit 0
