#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Redefine the firewall chains sequence
#

[ "$1" != "start" ] && exit

iptables=$(which iptables)

## Removing rules for update sequence
if [ -f "/var/tmp/rtnat.nfchain" ]; then
   $iptables -t nat -D POSTROUTING -j PoNAT 2>/dev/null
   rm -f /var/tmp/rtnat.nfchain 2>/dev/null
fi
if [ -f "/var/tmp/rttables.nfchain" ]; then
   $iptables -t nat -D POSTROUTING -j PoTAB 2>/dev/null
   rm -f /var/tmp/rttables.nfchain 2>/dev/null
fi
if [ -f "/var/tmp/tfstart.nfchain" ]; then
   $iptables -t mangle -D POSTROUTING -j POSTROUTING_QoS 2>/dev/null
   rm -f /var/tmp/tfstart.nfchain 2>/dev/null
fi
if [ -f "/var/tmp/rtfilters.nfchain" ]; then
   $iptables -t nat -D POSTROUTING -j RtRules 2>/dev/null
   rm -f /var/tmp/rtfilters.nfchain 2>/dev/null
fi
if [ -f "/var/tmp/cluster.prenfchain" ] || [ -f "/usr/share/fwguardian/cluster.prerules" ]; then
   $iptables -t mangle -D PREROUTING -j PreCluster 2>/dev/null
   rm -f /var/tmp/cluster.prenfchain 2>/dev/null
fi


## level 3
if [ -f "/usr/share/fwguardian/modules/rtfilters.ctl" ]; then
   $iptables -t nat -I POSTROUTING -j RtRules 2>/dev/null
   touch /var/tmp/rtfilters.nfchain
fi

## level 2
if [ -f "/usr/share/fwguardian/modules/rttables.ctl" ]; then
   $iptables -t nat -I POSTROUTING -j PoTAB 2>/dev/null
   touch /var/tmp/rttables.nfchain
fi

## level 1
if [ -f "/usr/share/fwguardian/modules/rtnat.ctl" ]; then
   $iptables -t nat -I POSTROUTING -j PoNAT 2>/dev/null
   touch /var/tmp/rtnat.nfchain
fi
if [ -f "/usr/share/fwguardian/cluster.prerules" ]; then
   $iptables -t mangle -I PREROUTING -j PreCluster
   touch /var/tmp/cluster.prnfchain
fi


if [ -f "/usr/share/fwguardian/modules/tfstart.ctl" ]; then
   $iptables -t mangle -A POSTROUTING -j POSTROUTING_QoS
   touch /var/tmp/tfstart.nfchain
fi
