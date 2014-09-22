#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Reset the route settings
#

ip=$(which ip)
sh=$(which bash)
iptables=$(which iptables)
FW_DIR=$2

[ "$1" != "flush" ] && exit
if [ -f $FW_DIR/build/.table.undo ]; then
  $sh $FW_DIR/build/.table.undo 2>/dev/null >/dev/null
  rm -f $FW_DIR/build/.table.undo
fi

if [ -f $FW_DIR/build/.vpn.undo ]; then
  $sh $FW_DIR/build/.vpn.undo 2>/dev/null >/dev/null
  rm -f $FW_DIR/build/.vpn.undo
fi

## Flush all tables
$ip route ls table all | grep table | grep -v "default\|main\|local\|25[3-5]" | sed "s/table/;/" | cut -d";" -f2 | awk '{print "ip "$1}' | grep -v local | sort | uniq | sed "s/ip/ip route flush table/" | $sh - 

$FW_DIR/modules/bannedfw.mod $FW_DIR routes 1>/dev/null

## Try to flush rules iproute2
if [ "$($ip rule flush 2>&1 | wc -l)" -eq 0 ]; then
  $ip rule add prio 32766 table main 2> /dev/null
  $ip rule add prio 32767 table default 2> /dev/null
else
  echo "WARNING!! I cant flush routing rules!"
fi

## Restore default routing cache params
echo 300 > /proc/sys/net/ipv4/route/gc_timeout
echo 60 > /proc/sys/net/ipv4/route/gc_interval
echo 0 > /proc/sys/net/ipv4/route/gc_min_interval

