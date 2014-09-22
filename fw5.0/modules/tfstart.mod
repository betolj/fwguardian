#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# tfstart module (QoS settings - shape.conf)
#

if [ "$1" == "--help" ] || [ "$1" == "" ] ; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "tfstart                 Controle de banda: regras de QoS (tfshape/shape.conf)" || \
     echo "tfstart                 Traffic shape: QoS settings (tfshape/shape.conf)"
  exit
fi

FW_DIR=$1
[ ! -f $FW_DIR/shape.conf ] || [ ! -f /usr/share/fwguardian/modules/tfstart.ctl ] && exit

ip=$(which ip)
tc=$(which tc)
sh=$(which bash)
iptables=$(which iptables)
sedipt=$(echo $iptables | sed "s/\//\\\\\//g")
sedip=$(echo $ip | sed "s/\//\\\\\//g")
sedtc=$(echo $tc | sed "s/\//\\\\\//g")


### Loading QoS modules
QOS_PROBE="sch_cbq sch_htb sch_hfsc sch_prio"
QOS_PROBE="$QOS_PROBE cls_fw cls_route cls_flow"

for module in $QOS_PROBE; do
  err=$(modprobe $module 2>&1 | cut -d":" -f1 | wc -l)
  [ "$err" -eq 1 ] && echo -e "\nTraffic shape... module error: $module - $err"
done

### Probe timer resolution
THZ=$(grep "^[ \|\t]*CONFIG_HZ=" /boot/config-$(uname -r) | sed 's/.*=//')

### Copy include file
for incf in $(ls $FW_DIR/../modules/include/tfshape.*.inc);
do
  md5pass=$($FW_DIR/../modules/chkmd5.mod $incf)
  if [ ! -f /usr/share/fwguardian/include/$(basename $(echo $incf)) ] || [ "$md5pass" -eq 0 ]; then
     cp -a -f $incf /usr/share/fwguardian/include/
  fi
done

echo "Firewall... Loading Traffic Shape!"

### Flush all last CBQ or HTB configuration
$FW_DIR/../modules/tfflush.mod start

for qoschain in PREROUTING FORWARD POSTROUTING; do
   qos_chain=$qoschain"_QoS"
   $iptables -t mangle -F $qos_chain 2>/dev/null
   $iptables -t mangle -D $qoschain -j $qos_chain 2>/dev/null
   $iptables -t mangle -X $qos_chain 2>/dev/null
done

### Flush *script* chains
if [ -f /usr/share/fwguardian/tfstart.chains ]; then
  cat /usr/share/fwguardian/tfstart.chains | awk '{ \
    print "iptables -t mangle -F "$1" 2>/dev/null "; \
    print "iptables -t mangle -X "$1" 2>/dev/null "; \
  }' | sed "s/iptables/$sedipt/g" | $sh - 2>> $FW_DIR/../logs/shape.conf.err
  rm -f /usr/share/fwguardian/tfstart.chains 2>/dev/null
fi

### Setting down ifb interfaces
if [ -f /usr/share/fwguardian/tfstart.ifb ]; then
   cat /usr/share/fwguardian/tfstart.ifb | awk '{ print "ip link set dev "$0" down 2>/dev/null" }' | $sh - 2>> $FW_DIR/../logs/shape.conf.err
   rm -f /usr/share/fwguardian/tfstart.ifb 2>/dev/null
fi


### QoS file
rulefiles="$FW_DIR/shape.conf"

### Cluster file
if [ -f /usr/share/fwguardian/modules/clusterfw.ctl ] && [ -f /var/tmp/gluster.group ]; then
  cldir="$FW_DIR/../cluster/glusterfs"
  clusterdir="$FW_DIR/../cluster/glusterfs/local/fs/tfshape"
  if [ -f "$clusterdir/shape.conf" ] && [ -f $clusterdir/../allow.firewall ]; then
     rulefiles="$clusterdir/shape.conf $rulefiles"
     rulefiles="$FW_DIR/../cluster/alias $rulefiles"

     rsync=$(which rsync)
     gl_group=$(cat /var/tmp/gluster.group)
     [ -f /usr/share/fwguardian/cluster/glusterfs.done ] && $rsync -arlp --exclude '*~' --exclude '^.' $cldir/cluster/$gl_group/tfshape/shape.conf $clusterdir/shape.conf 2>>$FW_DIR/../logs/cluster.base.err
  fi
else
  [ -f $FW_DIR/../alias ] && rulefiles="$FW_DIR/../alias $rulefiles"
fi
[ -f $FW_DIR/../conditions ] && rulefiles="$FW_DIR/../conditions $rulefiles"

echo "### QoS rules...(`date`)" | tee -a $FW_DIR/../logs/shape.conf.err > $FW_DIR/../build/shape.conf
cat $rulefiles | grep "[[:alpha:]]" | grep -v "^#\|^;" | igawk -v THZ=$THZ '\
  @include /usr/share/fwguardian/include/alias.inc \
  @include /usr/share/fwguardian/include/tfshape.burst.inc \
  { \
    @include /usr/share/fwguardian/include/tfshape.split.inc \
    @include /usr/share/fwguardian/include/tfshape.rules.inc \
  } \
  END { \
    lastqos(); \
  }' | sed "s/^iptables /$sedipt /g; s/^tc /$sedtc /g; s/^ip /$sedip /g" | tee -a $FW_DIR/../build/shape.conf | $sh - 2>> $FW_DIR/../logs/shape.conf.err

