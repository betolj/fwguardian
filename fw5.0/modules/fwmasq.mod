#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# fwmasq module (shortcut for proxy and internet settings)
#

if [ "$1" == "--help" ] || [ "$1" == "" ] ; then
  exit
fi

FW_DIR=$1
PRIV_DEF=$2
sh=$(which bash)
iptables=$(which iptables)
sedipt=$(echo $iptables | sed "s/\//\\\\\//g")


### FwMasq files
masqfiles="$FW_DIR/fwmasq.net"
echo > /usr/share/fwguardian/fwmasq.rules
chmod +x /usr/share/fwguardian/fwmasq.rules

[ -f /usr/share/fwguardian/vpop3.natrules ] || [ -f /usr/share/fwguardian/rsquid.natrules ] && \
   rm -rf /usr/share/fwguardian/*.natrules 2>/dev/null

### Verify md5 hash in include files
md5pass=$($FW_DIR/modules/chkmd5.mod $FW_DIR/modules/include/fwmasq.inc)
[ ! -f /usr/share/fwguardian/include/fwmasq.inc ] || [ "$md5pass" -eq 0 ] && \
   cp -f $FW_DIR/modules/include/fwmasq.inc /usr/share/fwguardian/include/

### Cluster file
if [ -f /usr/share/fwguardian/modules/clusterfw.ctl ] && [ -f /var/tmp/gluster.group ]; then
  cldir="$FW_DIR/cluster/glusterfs"
  clusterdir="$FW_DIR/cluster/glusterfs/local/fs"
  if [ -f "$clusterdir/fwmasq.net" ] && [ -f $clusterdir/allow.firewall ]; then
     masqfiles="$clusterdir/fwmasq.net $masqfiles"

     rsync=$(which rsync)
     gl_group=$(cat /var/tmp/gluster.group)
     [ -f /usr/share/fwguardian/cluster/glusterfs.done ] && $rsync -arlp --exclude '*~' --exclude '^.' $cldir/cluster/$gl_group/fwmasq.net $clusterdir/fwmasq.net 2>>$FW_DIR/logs/cluster.base.err
  fi
  masqfiles="$FW_DIR/cluster/alias $masqfiles"
else
  [ -f $FW_DIR/alias ] && masqfiles="$FW_DIR/alias $masqfiles"
fi
[ -f $FW_DIR/conditions ] && masqfiles="$FW_DIR/conditions $masqfiles"

echo "### Basic Internet rules (`date`)" | tee -a $FW_DIR/logs/fwmasq.err > $FW_DIR/build/fwmasq.net
cat $masqfiles | grep "[[:alpha:]]" | grep -v "^#\|^;" | igawk -v defpro=$PRIV_DEF '\
  @include /usr/share/fwguardian/include/alias.inc \
  { \
     @include /usr/share/fwguardian/include/fwmasq.inc \
  }' | sort -r | uniq | sed "s/iptables/$sedipt/g;" | tee -a $FW_DIR/build/fwmasq.net | $sh - 2>>$FW_DIR/logs/fwmasq.err

[ -f /usr/share/fwguardian/vpop3.natrules ] && $sh /usr/share/fwguardian/vpop3.natrules 2>$FW_DIR/logs/fwmasq.err
[ -f /usr/share/fwguardian/rsquid.natrules ] && $sh /usr/share/fwguardian/rsquid.natrules 2>$FW_DIR/logs/fwmasq.err
