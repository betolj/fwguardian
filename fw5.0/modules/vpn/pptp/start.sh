#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Simple pptpd service control
#

[ "$1" != "run" ] && exit

cmd=$2;
pptpd=$(which pptpd 2>/dev/null)

stop() {
  if [ -f /var/run/pptpd.pid ]; then
     kill $(cat /var/run/pptpd.pid) 2>/dev/null
     rm -f /var/run/pptpd.pid 2>/dev/null
  fi
  for pid in $(pidof pptpd); do
    kill -9 $pid
  done
 
  rm -f /var/lock/pptpd.lock
  [ "$cmd" == "stop" ] && exit
}

test -f "$pptpd" || {
  echo -e "\t Unable to find pptpd daemon!"
  exit
}

[ -f "/var/tmp/vpn.configureserver" ] && cmd="force"
[ "$cmd" == "stop" ] || [ "$cmd" == "force" ] && stop

### Start pptpd if is not running
if [ ! "$(pidof pptpd)" ] || [ "$cmd" == "force" ]; then
  if [ -f "/usr/share/fwguardian/vpn/pptp/start" ]; then
     $pptpd -c /usr/share/fwguardian/vpn/pptp/pptpd.conf
     touch /var/lock/pptpd.lock
  fi
fi
