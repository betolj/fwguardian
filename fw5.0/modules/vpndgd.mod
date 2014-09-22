#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# vpndgd module (DGD VPN routing) - Dead Gateway vpn routing Detection (failover)
#

FW_DIR=$1

### Daemon control
[ -f /tmp/vpndgd ] && exit
if [ -f /var/run/vpndgd ]; then
   kill -9 $(cat /var/run/vpndgd) 2>/dev/null
fi
[ ! -d /var/log/fwguardian ] && mkdir /var/log/fwguardian

max=50
ctmax=0
countg=0
[ -f /usr/share/fwguardian/vpn/vpndgd.ctl ] && while read line; do
   ((countg++))
   ctlost[$countg]=0
   dgdrl[$countg]=$(echo $line | awk '{print $1}')
   dgdip[$countg]=$(echo $line | awk '{print $2}')
done < /usr/share/fwguardian/vpn/vpndgd.ctl

### Try to run with daemon
[ "$countg" -lt 1 ] && exit
echo $$ > /var/run/vpndgd
touch /tmp/vpndgd


ctdgd=0
[ "$countg" -gt 1 ] && max=150
while :;
do
   if [ "$ctmax" -gt $max ]; then
      dgd=1
      ((ctdgd++)) 
   else 
      dgd=0
      ctdgd=0
   fi
   for ((i=1; $i<=$countg; i++));
   do
      ### Test lost packets (%100 - link down)
      lost="0%"
      lost=$(LANG=en ping ${dgdip[$i]} -c2 -w2 2>&1 2>/dev/null | grep packet | \
             sed 's/.*received//; s/ packet.*//; s/.* errors, //' | tr -d '[, ]')

      if [ "${dgdrl[$i]}" == 1 ] && [ "$dgd" == 0 ]; then
         if [ "$lost" == "100%" ] || [ "$lost" == "" ]; then
            ((ctlost[$i]++))
            dgd=1
         else 
            ctlost[$i]=0
         fi
         if [ "${ctlost[$i]}" -gt 2 ]; then
            ((ctmax++))
            echo "- $ctmax WARN: VPN restart due ${ctlost[$i]} peer faults(${dgdip[$i]}) at $(date)...." >> /var/log/fwguardian/dgd.log
            $FW_DIR/../fwguardian --reload-vpn 2>&1 >> /var/log/fwguardian/dgd.log
            ctlost[$i]=0
            [ "$ctmax" -gt 20 ] && sleep 20
         fi
      fi
   done
   [ "$ctdgd" -gt 720 ] && dgd=0
   [ "$dgd" == 0 ] && ctmax=0
   sleep 10
done
