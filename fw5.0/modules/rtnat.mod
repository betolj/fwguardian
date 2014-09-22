#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# rtnat module (SNAT, MASQUERADE, DNAT or MIRROR NAT iptables rules)
#

if [ "$1" == "--help" ] || [ "$1" == "" ] ; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "rtnat			Redirecionamentos (DNAT), tradução de origem (SNAT/MASQUERADE) ou NETMAP (fwroute.nat)" || \
     echo "rtnat			Redirects (DNAT), source translation (SNAT/MASQUERADE) or NETMAP rules (fwroute.nat)"
  exit
fi

FW_DIR=$1
[ ! -f $FW_DIR/fwroute.nat ] || [ ! -f /usr/share/fwguardian/modules/rtnat.ctl ] && exit

sh=$(which bash) 
iptables=$(which iptables)
sedipt=$(echo $iptables | sed "s/\//\\\\\//g")


### Flush NAT chains
$iptables -F FwNAT 2>/dev/null
$iptables -t nat -F PrNAT 2>/dev/null
$iptables -t nat -F PoNAT 2>/dev/null
$iptables -t mangle -F CNTNat 2>/dev/null

### Verify md5 hash in include files
md5pass=$($FW_DIR/../modules/chkmd5.mod $FW_DIR/../modules/include/rtnat.inc)
[ ! -f /usr/share/fwguardian/include/rtnat.inc ] || [ "$md5pass" -eq 0 ] && \
   cp -f $FW_DIR/../modules/include/rtnat.inc /usr/share/fwguardian/include/

[ -f /usr/share/fwguardian/rtablenat.ctl ] && fwr=1 || fwr=0

### PostRouting NAT
$iptables -t nat -F PoNAT 2>/dev/null
$iptables -t nat -D POSTROUTING -j PoNAT 2>/dev/null
grep "^\([ \|\t]with-masq\|set-policy[ \|\t]SNAT\)" $FW_DIR/fwroute.nat >/dev/null && $iptables -t nat -N PoNAT 2>/dev/null


### NAT file
rulefiles="$FW_DIR/fwroute.nat"

### Cluster file
if [ -f /usr/share/fwguardian/modules/clusterfw.ctl ] && [ -f /var/tmp/gluster.group ]; then
  cldir="$FW_DIR/../cluster/glusterfs"
  clusterdir="$FW_DIR/../cluster/glusterfs/local/fs/routing"
  if [ -f "$clusterdir/fwroute.nat" ] && [ -f $clusterdir/../allow.firewall ]; then
     rulefiles="$clusterdir/fwroute.nat $rulefiles"

     rsync=$(which rsync)
     gl_group=$(cat /var/tmp/gluster.group)
     [ -f /usr/share/fwguardian/cluster/glusterfs.done ] && $rsync -arlp --exclude '*~' --exclude '^.' $cldir/cluster/$gl_group/routing/fwroute.nat $clusterdir/fwroute.nat 2>>$FW_DIR/../logs/cluster.base.err
  fi
  rulefiles="$FW_DIR/../cluster/alias $rulefiles"
else
  [ -f $FW_DIR/../alias ] && rulefiles="$FW_DIR/../alias $rulefiles"
fi
[ -f $FW_DIR/../conditions ] && rulefiles="$FW_DIR/../conditions $rulefiles"

echo "Firewall... Loading NAT rules!"
echo "### NAT rules (`date`)" | tee -a $FW_DIR/../logs/fwroute.nat.err > $FW_DIR/../build/fwroute.nat
cat $rulefiles | grep "[[:alpha:]]" | grep -v "^#\|^;" | igawk -v fwr=$fwr '\
  @include /usr/share/fwguardian/include/alias.inc \
  { pproto=""; \
    @include /usr/share/fwguardian/include/rtnat.inc \
  }' | sed "s/iptables/$sedipt/g;" | tee -a $FW_DIR/../build/fwroute.nat | $sh - 2>>$FW_DIR/../logs/fwroute.nat.err

