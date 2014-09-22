#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# ARP config for VMAC support and notify control
#
# Notify control (keelalived call):
#  - Master node
#     Receive MASTER call when occur master notify
#
#  - Slave node
#     Receive MASTERFO call when occur a master notify
#

sh=$(which bash)
ip=$(which ip)
iptables=$(which iptables)
conntrackd=$(which conntrackd)


# Identify the active VIP:  Usefull to your personal scripts or "condition" firewall rules
# Conntrackd updates:       *Accept* only one notify event per time (in the same status)
$ip ne flush dev $2 2>/dev/null
if [ "$3" == "MASTER" ] || [ "$3" == "MASTERFO" ]; then

   # MASTER state
   touch /var/tmp/cluster.vip.$1

   if [ -f "/usr/share/fwguardian/cluster.multicastmac" ]; then
      if [ "$3" == "MASTERFO" ]; then
         touch /var/tmp/keepalived.fail.$1
      else
         [ -f /var/tmp/keepalived.fail.$1 ] && rm -f /var/tmp/keepalived.fail.$1 2>/dev/null

         # Require libio-interface-perl (sending a igmp join)
      cat << EOF | perl - 2>/dev/null
use IO::Socket::Multicast;

my \$s = IO::Socket::Multicast->new(LocalPort=>0);
\$s->mcast_add('224.1.$1.18','$2');
EOF
      fi
      /usr/local/bin/nfcluster.sh
   else
      if [ -f "/usr/share/fwguardian/cluster.use_vmac" ]; then
         arptables=$(which arptables)
         $arptables -I OUTPUT -j DROP 2>/dev/null

         sysctl -w net.ipv4.conf.default.arp_filter=0
         sysctl -w net.ipv4.conf.all.rp_filter=0
         sysctl -w net.ipv4.conf.all.arp_filter=0
         sysctl -w net.ipv4.conf.all.arp_ignore=1
         sysctl -w net.ipv4.conf.all.arp_announce=2

         sysctl -w net.ipv4.conf.$2.rp_filter=0
         sysctl -w net.ipv4.conf.$2.arp_filter=1
         sysctl -w net.ipv4.conf.vrrp/$1.rp_filter=0
         sysctl -w net.ipv4.conf.vrrp/$1.arp_filter=0
         sysctl -w net.ipv4.conf.vrrp/$1.accept_local=1

         $arptables -D OUTPUT -j DROP 2>/dev/null
      else
         sysctl -w net.ipv4.conf.all.arp_filter=1
         sysctl -w net.ipv4.conf.default.arp_filter=1
      fi
      if [ -f "/usr/share/fwguardian/cluster.sync_state" ] && [ ! -f "/usr/share/fwguardian/cluster.nocache" ]; then
         if [ ! -f "/var/tmp/master.vrlock" ]; then
            touch /var/tmp/master.vrlock
            $conntrackd -c -C /etc/conntrackd/conntrackd.conf 2>&1 | logger "conntrackd: -c $(xargs)"
            $conntrackd -f -C /etc/conntrackd/conntrackd.conf 2>&1 | logger "conntrackd: -f $(xargs)"
            $conntrackd -R -C /etc/conntrackd/conntrackd.conf 2>&1 | logger "conntrackd: -R $(xargs)"
            $conntrackd -B -C /etc/conntrackd/conntrackd.conf 2>&1 | logger "conntrackd: -B $(xargs)"
         fi
         [ -f "/var/tmp/slave.vrlock" ] && rm -f /var/tmp/slave.vrlock 2>/dev/null
      fi
   fi

   [ -f "/usr/share/fwguardian/cluster/vip.up" ] && /bin/bash /usr/share/fwguardian/cluster/vip.up $1 $2
else
   [ -f /var/tmp/cluster.vip.$1 ] && rm -f /var/tmp/cluster.vip.$1 2>/dev/null

   if [ "$3" == "BACKUP" ]; then
      # BACKUP state
      if [ -f "/usr/share/fwguardian/cluster.multicastmac" ]; then
         [ -f /var/tmp/keepalived.fail.$1 ] && rm -f /var/tmp/keepalived.fail.$1 2>/dev/null
         /usr/local/bin/nfcluster.sh
      else
         if [ -f "/usr/share/fwguardian/cluster.sync_state" ]; then
            $conntrackd -t -C /etc/conntrackd/conntrackd.conf 2>&1 | logger "conntrackd: -t $(xargs)"
            if [ ! -f "/usr/share/fwguardian/cluster.nocache" ]; then
               if [ ! -f "/var/tmp/slave.vrlock" ]; then
                  touch /var/tmp/slave.vrlock
                  $conntrackd -n -C /etc/conntrackd/conntrackd.conf 2>&1 | logger "conntrackd: -n $(xargs)"
               fi
               [ -f "/var/tmp/slave.vrlock" ] && rm -f /var/tmp/slave.vrlock 2>/dev/null
               [ -f "/var/tmp/master.vrlock" ] && rm -f /var/tmp/master.vrlock 2>/dev/null
            fi
         fi
      fi

      [ -f "/usr/share/fwguardian/cluster/vip.down" ] && /bin/bash /usr/share/fwguardian/cluster/vip.down $1 $2
   else
      # VFAULT state
      [ -f "/usr/share/fwguardian/cluster.sync_state" ] && $conntrackd -t -C /etc/conntrackd/conntrackd.conf 2>&1 | logger "conntrackd: -t $(xargs)"
      exit
   fi
fi

# Default action
ls /sys/class/net | awk '{ if ($1 != "lo") print "ip ne flush dev "$1; }' | $sh - 2>/dev/null
[ -f /usr/local/bin/vrrpupd.sh ] && /usr/local/bin/vrrpupd.sh $1 $3

