#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# rtdgd module (DGD routing) - Dead Gateway routing Detection (failover) - rev1
#

[ "$1" == "" ] && exit

export IFS=$'\n'

FW_DIR=$1
ip=$(which ip)
iptables=$(which iptables)
arptables=$(which arptables)
conntrack=$(which conntrack)
sedipt=$(echo $iptables | sed "s/\//\\\\\//g")

if [ -f /var/run/dgdguardian ]; then
  kill -9 $(cat /var/run/dgdguardian) 2>/dev/null
  [ -x $arptables ] && $arptables -F rtdgd 2>/dev/null
fi
[ ! -d /var/log/fwguardian ] && mkdir /var/log/fwguardian

countg=0
for line in $(cat /usr/share/fwguardian/rtdgd.ctl);
do
   ((countg++))
   ctlost[$countg]=0
   ctnolost[$countg]=1
   dgdlink[$countg]=$(echo $line | awk '{print $1}')
   dgdip[$countg]=$(echo $line | awk '{print $2}')

   auxgw=$(echo $line | awk '{print $3}')
   [ "$auxgw" == "auto" ] && auxgw=$(ip route get ${dgdip[$countg]} 2>/dev/null | head -1 | sed 's/.* via //; s/ dev.*//')
   tbgw[$countg]=$auxgw
   tbif[$countg]=$(ip route get ${dgdip[$countg]} 2>/dev/null | head -1 | sed 's/.* dev //' | cut -d' ' -f1)

   echo -e "\t    - Testing link ${dgdlink[$countg]} with ${dgdip[$countg]}"
   [ -f /tmp/tb-${dgdlink[$countg]}.down ] && rm -f /tmp/tb-${dgdlink[$countg]}.down 2>/dev/null
done

### Try to run with daemon
[ "$countg" -lt 1 ] && exit
echo $$ > /var/run/dgdguardian

### Fail-over algorithm
[ "$countg" -gt 2 ] && lbalgo="ja" || lbalgo="lb2"

if [ $lbalgo == "ja" ]; then
  if [ -x $arptables ]; then
    $arptables -N rtdgd 2>/dev/null
    $arptables -F rtdgd 2>/dev/null
    $arptables -D INPUT -p arp -j rtdgd 2>/dev/null
    $arptables -A INPUT -p arp -j rtdgd 2>/dev/null
  else
    echo "ERROR... rtdgd aborted: no arptables support!"
    exit
  fi
fi


sleep 2
countchk=0
use_arptb=0
[ "$lbalgo" == "ja" ] && [ -f "$arptables" ] && use_arptb=1
while :;
do
   ((countchk++))
   for ((i=1; $i<=$countg; i++));
   do
     if [ "$countchk" -le 3 ] || [ "${ctlost[$i]}" -gt 0 ] || [ "${ctnolost[$i]}" -eq 1 ]; then

        ### Allow arp update for ping probes
        [ $use_arptb == 1 ] && [ -f /tmp/tb-${dgdlink[$i]}.down ] && $arptables -I rtdgd -s ${tbgw[$i]} -j RETURN 2>/dev/null

        ### Test lost packets (%100 - link down)
        lost="0%"
        lost=$(LANG=en ping ${dgdip[$i]} -c2 -w2 2>&1 2>/dev/null | grep packet | \
               sed 's/.*received//; s/ packet.*//; s/.* errors, //' | tr -d '[, ]')

        if [ -f /tmp/tb-${dgdlink[$i]}.down ]; then
           [ $use_arptb == 1 ] && $arptables -D rtdgd -s ${tbgw[$i]} -j RETURN 2>/dev/null
           ip ne del ${tbgw[$i]} dev ${tbif[$i]} 2>/dev/null
        fi

        if [ "$lost" == "100%" ] || [ "$lost" == "" ]; then
           ctnolost[$i]=2
           ((ctlost[$i]++))
           [ ! -f /tmp/tb-${dgdlink[$i]}.down ] && \
              echo "$(date) ERR: The link has received a INVALID response from ${dgdip[$i]} (${ctlost[$i]})... table: ${dgdlink[$i]} " >> /var/log/fwguardian/dgd.log
        else 
           ctlost[$i]=0
           if [ -f /tmp/tb-${dgdlink[$i]}.down ]; then
              echo "$(date) WARN: The link has received a valid response from ${dgdip[$i]} (${ctnolost[$i]})... table: ${dgdlink[$i]} " >> /var/log/fwguardian/dgd.log
              if [ "${ctnolost[$i]}" -lt 2 ]; then
                 $iptables -t mangle -D PREROUTING -d ${tbgw[$i]} -j DROP 2>/dev/null

                 if [ "$lbalgo" == "lb2" ]; then
                    ### LB2 algo
                    [ "$i" == "2" ] && lb2tb="${dgdlink[1]}" || lb2tb="${dgdlink[2]}"
                    $ip rule del prio 11 table $lb2tb 2>/dev/null
                 else
                    $arptables -D rtdgd -s ${tbgw[$i]} -j DROP 2>/dev/null
                 fi
                 [ -f /proc/sys/net/ipv4/route/flush ] && echo 1 > /proc/sys/net/ipv4/route/flush || $ip route flush cache
                 echo "$(date) Link UP... table: ${dgdlink[$i]} " >> /var/log/fwguardian/dgd.log
                 rm -f /tmp/tb-${dgdlink[$i]}.down
              fi
           fi

           [ "${ctnolost[$i]}" -gt 0 ] && ((ctnolost[$i]--))
           if [ -f "/tmp/tb-${dgdlink[$i]}.warn" ]; then
              rm -f /tmp/tb-${dgdlink[$i]}.warn 2>/dev/null
              echo "$(date) Link UP (on start)... table: ${dgdlink[$i]} " >> /var/log/fwguardian/dgd.log
           fi
        fi

        if [ "${ctlost[$i]}" -gt 2 ]; then
           if [ ! -f /tmp/tb-${dgdlink[$i]}.down ]; then
              ctnolost[$i]=2
              $iptables -t mangle -D PREROUTING -d ${tbgw[$i]} -j DROP 2>/dev/null
              $iptables -t mangle -I PREROUTING -d ${tbgw[$i]} -j DROP 2>/dev/null
              touch /tmp/tb-${dgdlink[$i]}.down

              if [ "$lbalgo" == "lb2" ]; then
                 ### LB2 algo
                 [ "$i" == "2" ] && lb2tb="${dgdlink[1]}" || lb2tb="${dgdlink[2]}"
                 $ip rule del prio 11 table ${dgdlink[1]} 2>/dev/null
                 $ip rule del prio 11 table ${dgdlink[2]} 2>/dev/null
                 $ip rule add prio 11 table $lb2tb

                 [ -f /tmp/tb-$lb2tb.down ] && rm -f /tmp/tb-$lb2tb.down 2>/dev/null
              else
                 $arptables -A rtdgd -s ${tbgw[$i]} -j DROP 2>/dev/null
                 $ip ne del ${tbgw[$i]} dev ${tbif[$i]} 2>/dev/null
              fi
              [ -f /proc/sys/net/ipv4/route/flush ] && echo 1 > /proc/sys/net/ipv4/route/flush || $ip route flush cache
              echo "$(date) Link DOWN... table: ${dgdlink[$i]} " >> /var/log/fwguardian/dgd.log
              [ -x "$conntrack" ] && conntrack -F conntrack 2>/dev/null >/dev/null
           fi
           ctlost[$i]=0
        fi
     else
        [ -f /tmp/tb-${dgdlink[$i]}.down ] && [ "$lbalgo" == "ja" ] && \
           $ip ne del ${tbgw[$i]} dev ${tbif[$i]} 2>/dev/null
     fi
   done

   sleep 1
   [ "$countchk" -gt 14 ] && countchk=0
done

