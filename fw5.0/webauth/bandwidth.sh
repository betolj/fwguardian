#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Bandwidth apps (shellinabox tools)
#  - iftop
#  - pktstat
#  - iptraf
#  - ettercap
#  - tcpdump
#


bif=$1
shift

bpcap=$@

bcmd[0]="iftop"
bcmd[1]="pktstat"
bcmd[2]="iptraf"
bcmd[3]="ettercap"
bcmd[4]="tcpdump"

while :;
do
   clear
   echo
   echo "> Bandwidth MENU"
   echo
   echo "0. iftop"
   echo "1. pktstat"
   echo "2. iptraf"
   echo "3. ettercap"
   echo "4. tcpdump"
   echo "5. Exit"
   echo
   read -p "==> " opc
   clear
   bapp=${bcmd[$opc]}
   bapp=$(which $bapp)
   tcpdump=$(which tcpdump)
   [ ! -x "$bapp" ] && [ $opc -lt 5 ] && opc=4

   case "$opc" in
     0) $bapp -i $bif -f "$bpcap" -n ;;
     1) $bapp -i $bif -w1 -t -T "$bpcap" -n ;;
     2) [ "$bif" != "any" ] && auxif=" -i $bif" || auxif=""
        $bapp $auxif ;;
     3) $bapp -i $bif -u -C -f "$bpcap" ;;
     4) $tcpdump -i $bif "$bpcap" -n  ;;
     *) exit 0 ;;
   esac
done

exit 0
