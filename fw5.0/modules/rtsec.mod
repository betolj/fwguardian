#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# rtsec module (Routing restriction)
#

ipdyn="$2"
FW_DIR=$(readlink -f "$(dirname $0)"/)
iptables=$(which iptables)

[ "$1" == "" ] && exit 

[ "$ipdyn" == "fixed" ] && lchain="POSTROUTING" || lchain="FORWARD"
if [ "$1" == "create" ]; then
   # standard rules
   $iptables -t mangle -D $lchain -o $1 -j RtSec 1>/dev/null 2>/dev/null
   $iptables -t mangle -X RtSec 1>/dev/null 2>/dev/null
   $iptables -t mangle -F RtSec 1>/dev/null 2>/dev/null
   $iptables -t mangle -N RtSec

   # search the ethernet interfaces
   for iffw in $(ifconfig | awk '/Link encap/ { if (!match($1, ":")) print $1; }');
   do
     # search the IP addr of witch interface
     if [ "$iffw" != "lo" ]; then
       for netsec in $(ip route ls dev $iffw scope link | grep "/" | awk '{print $1}');
       do
          $iptables -t mangle -A RtSec -s $netsec -j RETURN
       done
     fi
   done
   [ -f /usr/share/fwguardian/modules/rtnat.ctl ] && /sbin/iptables -t mangle -I RtSec -m conntrack --ctstate DNAT -j RETURN
else
   $iptables -t mangle -A $lchain -o $1 -j RtSec
fi

