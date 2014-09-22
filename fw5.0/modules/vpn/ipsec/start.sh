#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Simples xl2tpd and racoon service control
#

[ "$1" != "run" ] && exit

cmd=$2;
l2tpd=$(which xl2tpd 2>/dev/null)
racoon=$(which racoon 2>/dev/null)


### Find VPN services (racoon and l2tpd)
test -f "$l2tpd" || {
  echo -e "\t Unable to find xl2tpd daemon!\n\tTry to find l2tpd daemon..."
  l2tpd=$(which l2tpd 2>/dev/null)
  test -f "$l2tpd" || {
    echo -e "\t Unable to find any L2TP daemon!"
    exit
  }
}

test -f "$racoon" || {
  echo -e "\t Unable to find racoon daemon!"
  exit
}

stop() {
  if [ -f /var/run/xl2tpd.pid ]; then
     kill $(cat /var/run/xl2tpd.pid) 2>/dev/null
     rm -f /var/run/xl2tpd.pid 2>/dev/null
  fi
  if [ -f /var/run/racoon.pid ]; then
     kill $(cat /var/run/racoon.pid) 2>/dev/null
     rm -f /var/run/racoon.pid 2>/dev/null
  fi

  for pid in $(pidof xl2tpd racoon); do
    kill -9 $pid
  done

  [ -f /var/lock/l2tpd.lock ] && rm -f /var/lock/l2tpd.lock
  [ -f /var/lock/racoon.lock ] && rm -f /var/lock/racoon.lock
  [ "$cmd" == "stop" ] && exit
}


[ -f "/var/tmp/vpn.configureserver" ] && cmd="force"
[ "$cmd" == "stop" ] || [ "$cmd" == "force" ] && stop

### Start l2tpd if is not running
if [ ! "$(pidof $l2tpd)" ] || [ "$cmd" == "force" ]; then
  if [ -f "/usr/share/fwguardian/vpn/ipsec/start" ] && [ -f /usr/share/fwguardian/vpn/ipsec/l2tpd.conf ]; then
     [ ! -d /var/run/xl2tpd ] && mkdir /var/run/xl2tpd

     $l2tpd -c /usr/share/fwguardian/vpn/ipsec/l2tpd.conf
     touch /var/lock/l2tpd.lock
  fi
fi

### Start racoon if is not running
if [ ! "$(pidof racoon)" ] || [ "$cmd" == "force" ]; then
  if [ -f "/usr/share/fwguardian/vpn/ipsec/start" ]; then
     $racoon -4 -f /usr/share/fwguardian/vpn/ipsec/racoon.conf
     touch /var/lock/racoon.lock
  fi
fi

