#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# rttables module (Advanced routing - Load balance or conditional routing)
#

if [ "$1" == "--help" ] || [ "$1" == "" ] ; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "rttables		Roteamento avançado: Configurações para balanceamento de carga e failover (fwroute.tables)" || \
     echo "rttables		Advanced routing: Settings for load balancing and failover (fwroute.tables)"
  exit
fi

FW_DIR=$1
[ ! -f $FW_DIR/fwroute.tables ] || [ ! -f /usr/share/fwguardian/modules/rttables.ctl ] && exit

ip=$(which ip)
sh=$(which bash)
iptables=$(which iptables)
sedipt=$(echo $iptables | sed "s/\//\\\\\//g")
sedip=$(echo $ip | sed "s/\//\\\\\//g")


echo "# Routing tables" > /usr/share/fwguardian/modules/rttables.ctl

### Flush main chains
$iptables -t mangle -F PrTAB 2>/dev/null
$iptables -t nat -F PoTAB 2>/dev/null
[ -f /usr/share/fwguardian/rttables.prlock ] && mkprt=0 || mkprt=1

echo "### Routing tables (`date`)" | tee -a $FW_DIR/../logs/fwroute.tables.err > $FW_DIR/../build/fwroute.tables
$ip rule del prio 10 2>/dev/null
$ip rule add prio 10 table main 2>/dev/null | tee -a $FW_DIR/../build/fwroute.tables

### Copy include file
for incf in $(ls $FW_DIR/../modules/include/rttables.*.inc); 
do
  md5pass=$($FW_DIR/../modules/chkmd5.mod $incf)
  if [ ! -f /usr/share/fwguardian/include/$(basename $(echo $incf)) ] || [ "$md5pass" -eq 0 ]; then
     cp -a -f $incf /usr/share/fwguardian/include/
  fi
done
rm -f /usr/share/fwguardian/rttables.equalize 2>/dev/null


### Route table file
rulefiles="$FW_DIR/fwroute.tables"

### Cluster file
if [ -f /usr/share/fwguardian/modules/clusterfw.ctl ] && [ -f /var/tmp/gluster.group ]; then
  cldir="$FW_DIR/../cluster/glusterfs"
  clusterdir="$FW_DIR/../cluster/glusterfs/local/fs/routing"
  if [ -f "$clusterdir/fwroute.tables" ] && [ -f $clusterdir/../allow.firewall ]; then
     rulefiles="$clusterdir/fwroute.tables $rulefiles"

     rsync=$(which rsync)
     gl_group=$(cat /var/tmp/gluster.group)
     [ -f /usr/share/fwguardian/cluster/glusterfs.done ] && $rsync -arlp --exclude '*~' --exclude '^.' $cldir/cluster/$gl_group/routing/fwroute.tables $clusterdir/fwroute.tables 2>>$FW_DIR/../logs/cluster.base.err
  fi
  rulefiles="$FW_DIR/../cluster/alias $rulefiles"
else
  [ -f $FW_DIR/../alias ] && rulefiles="$FW_DIR/../alias $rulefiles"
fi
[ -f $FW_DIR/../conditions ] && rulefiles="$FW_DIR/../conditions $rulefiles"

## Making alternatives routing tables
rm -f /usr/share/fwguardian/rtdgd.ctl 2>/dev/null
cat $rulefiles | grep -v "^[#\|;]" | grep "[[:alpha:]]" | igawk -v mkprt=$mkprt '\
  @include /usr/share/fwguardian/include/alias.inc \
  @include /usr/share/fwguardian/include/rttables.id.inc \
  { \
     @include /usr/share/fwguardian/include/rttables.defines.inc \
     @include /usr/share/fwguardian/include/rttables.rules.inc \
  }' | sed "s/ip\ /$sedip\ /g" | tee -a $FW_DIR/../build/fwroute.tables | $sh - 2>>$FW_DIR/../logs/fwroute.tables.err

## Loading lb routing tables
echo "### Loadbalance table" >> $FW_DIR/../logs/fwroute.tables.err
for i in $(ls /usr/share/fwguardian/*.lbtable 2>/dev/null); do
   cat $i | tr -d "\n" | $sh - 2>>$FW_DIR/../logs/fwroute.tables.err
done

## Trie to populate rt_cache
ip route get 200 2>/dev/null >/dev/null
ip route get 201 2>/dev/null >/dev/null
ip route get 202 2>/dev/null >/dev/null
rtcache=$(cat /proc/net/rt_cache | wc -l)

## Making rules for keepalive conntrack sessions
if [ -f /usr/share/fwguardian/keepalive.ctl ] && [ "$rtcache" -lt 2 ]; then
   echo "### Keepalive conntrack rules (`date`)" | tee -a $FW_DIR/../logs/fwroute.tables.kalive.err > $FW_DIR/../build/fwroute.tables.kalive
   $iptables -t mangle -F CNTRACK 2>/dev/null
   $iptables -t mangle -N CNTRACK 2>/dev/null
   $iptables -t mangle -A CNTRACK -o lo -j RETURN
   $iptables -t mangle -A CNTRACK -d 224.0.0.0/4 -j RETURN
   lbeq=1
   if [ ! -f /usr/share/fwguardian/rttables.equalize ]; then
      $iptables -t mangle -N SETMARK 2>/dev/null
      $iptables -t mangle -N GETMARK 2>/dev/null
      $iptables -t mangle -F GETMARK
      $iptables -t mangle -F SETMARK
      $iptables -t mangle -D OUTPUT -j GETMARK 2>/dev/null
      $iptables -t mangle -I OUTPUT -j GETMARK
      $iptables -t mangle -D PREROUTING -m mark --mark 0x0 -j GETMARK 2>/dev/null
      $iptables -t mangle -A PREROUTING -m mark --mark 0x0 -j GETMARK
      lbeq=$(cat /proc/sys/net/ipv4/route/gc_timeout)
   fi
   cat /usr/share/fwguardian/modules/rttables.ctl | awk -v lbeq=$lbeq '{ cncount++; \
       if (cncount > 1 && $2) { \
          if (lbeq == 1) print "iptables -t mangle -A CNTRACK -o "$2" -m mark --mark 0x0 -j CONNMARK --set-mark "$5; \
          else { \
             print "ipset destroy lb_"$1" 2>/dev/null"; \
             print "ipset create lb_"$1" hash:ip,port,ip timeout "lbeq; \
             print "iptables -t mangle -A CNTRACK -o "$2" -j SETMARK"; \
             print "iptables -t mangle -A SETMARK -o "$2" -m mark --mark 0x0 -j CONNMARK --set-mark "$5; \
             print "iptables -t mangle -A SETMARK -m mark --mark "$5" -j SET --add-set lb_"$1" src,dstport,dst --timeout "lbeq" --exist"; \
             print "iptables -t mangle -A GETMARK -m set --match-set lb_"$1" src,dstport,dst -j CONNMARK --set-mark "$5; \
          } \
       } \
   }' | tee -a $FW_DIR/../build/fwroute.tables.kalive | $sh - 2>>$FW_DIR/../logs/fwroute.tables.kalive.err
   $iptables -t mangle -A CNTRACK -m mark ! --mark 0x0 -j CONNMARK --save-mark 2>/dev/null
fi

## Undo rules
cat $FW_DIR/../build/fwroute.tables | grep -v "^###\|echo\|rule del\|route add\|route append\|nexthop\|iptables " | \
    sed "s/rule\ add/rule\ del/g;" > $FW_DIR/../build/.table.undo
[ -f /proc/sys/net/ipv4/route/flush ] && echo 1 > /proc/sys/net/ipv4/route/flush || $ip route flush cache

### Dead gateway detection (work only in kernel with Julians patch)
[ -f /usr/share/fwguardian/rtdgd.ctl ] && $FW_DIR/../modules/rtdgd.mod $FW_DIR & 

