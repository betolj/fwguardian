#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# This script prevent SA undeleted records by racoon
#

setkey=$(which setkey 2>/dev/null)
BIND=$(grep 'isakmp ' /usr/share/fwguardian/vpn/ipsec/racoon.conf | awk '{ print $2}')

spi1pos=$(setkey -D | grep -n "^$BIND\[4500\] $REMOTE_ADDR" | cut -d":" -f1)
spi2pos=$(setkey -D | grep -n "^$REMOTE_ADDR\[4500\] $BIND" | cut -d":" -f1)
((spi1pos++));
((spi2pos++));
findspi1=$(setkey -D | tail -n +$spi1pos | head -1 | sed 's/.*spi=\(.*\)/\1/;s/(.*//')
findspi2=$(setkey -D | tail -n +$spi2pos | head -1 | sed 's/.*spi=\(.*\)/\1/;s/(.*//')

echo "delete -4 $BIND[4500] $REMOTE_ADDR[4500] esp-udp $findspi1;" | $setkey -c
echo "delete -4 $REMOTE_ADDR[4500] $BIND[4500] esp-udp $findspi2;" | $setkey -c

