#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Configure multicast mac for active-active setup
#  - This is used by default when active-active mode was enabled
#  - This address is based on vrrp multicast and with inclusion of the vid.
#

[ ! -f /usr/share/fwguardian/cluster.multicastmac ] && exit

ip=$(which ip)
arptables=$(which arptables)

while read line; do
   vipif=$(echo $line | cut -d' ' -f1)
   if [ -f /sys/class/net/$vipif/address ]; then
      macif=$(cat /sys/class/net/$vipif/address)
      macvipid=$(echo $line | cut -d' ' -f2)

      echo $macvipid | grep -q ':' - && setmac=1 || setmac=0
      if [ "$setmac" == "0" ]; then
         [ $macvipid -gt 255 ] && macvipid=255
         macvipid=$(echo "obase=16; $macvipid" | bc)
         macvipid="01:00:5e:01:$macvipid:12"
      fi

      $ip maddr add $macvipid dev $vipif 2>/dev/null
      $arptables -A In_Multicast -i $vipif --h-length  6  --destination-mac $macvipid -j mangle --mangle-mac-d $macif
      $arptables -A Out_Multicast -o $vipif --h-length 6 -j mangle --mangle-mac-s $macvipid
      $ip ne flush dev $vipif 2>/dev/null
   fi
done < /usr/share/fwguardian/cluster.multicastmac

