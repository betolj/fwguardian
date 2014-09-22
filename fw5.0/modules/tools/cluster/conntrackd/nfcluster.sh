#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Active-active and multicast cluster control
#  - Single IP node in hash-seed 0xffffffff (firewall address)
#  - Cluster node in hash-seed 0xdeadbeef
#

sh=$(which bash)
iptables=$(which iptables)

[ ! -f /usr/share/fwguardian/cluster.heartbeat ] && exit

## Netfilter cluster hash selection
if [ -f /usr/share/fwguardian/cluster.prerules ]; then
   fail=$(find /var/tmp/ -type f -name "keepalived.fail.*" | wc -l)
   $iptables -t mangle -F PreCluster
   [ "$fail" == "0" ] && grep -v -f /usr/share/fwguardian/cluster.vips /usr/share/fwguardian/fw.ipaddr | awk '{ print "iptables -t mangle -A PreCluster -d "$1" -m cluster --cluster-total-nodes 1 --cluster-local-node 1 --cluster-hash-seed 0xffffffff -j RETURN" }' | $sh -

   while read line; do
      vipif=$(echo $line | cut -d' ' -f1)
      lcnode=$(echo $line | cut -d' ' -f2)

      if [ "$fail" == "0" ]; then
         $iptables -t mangle -A PreCluster -i $vipif -m cluster --cluster-total-nodes 2 --cluster-local-node $lcnode --cluster-hash-seed 0xdeadbeef -j RETURN
         $iptables -t mangle -A PreCluster -i $vipif -j DROP
      else
         $iptables -t mangle -A PreCluster -i $vipif -m cluster --cluster-total-nodes 1 --cluster-local-node 1 --cluster-hash-seed 0xffffffff -j RETURN
      fi
   done < /usr/share/fwguardian/cluster.prerules
fi

## Allow multicast conntrackd
count=0
maddr=49
while read line; do
   ((count++))
   ((maddr+=count))
   mif=$(echo $line | cut -d' ' -f1)
   msrcaddr=$(echo $line | cut -d' ' -f3 | sed 's/\/.*//g')
   [ "$msrcaddr" != "any" ] && [ "$msrcaddr" != "0/0" ] && msrcaddr="-s $msrcaddr" || msrcaddr=""
   $iptables -t mangle -I PreCluster -i $mif $msrcaddr -d 224.0.0.0/4 -j RETURN 2>/dev/null
   $iptables -D InCluster -i $mif -p udp $msrcaddr -d 225.0.0.$maddr -j ACCEPT 2>/dev/null
   $iptables -I InCluster $count -i $mif -p udp $msrcaddr -d 225.0.0.$maddr -j ACCEPT
done < /usr/share/fwguardian/cluster.heartbeat

