#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# infilters module (set INPUT iptables rules)
#

if [ "$1" == "--help" ] || [ "$1" == "" ]; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "infilters		Define a permissão de acesso ao firewall (fwinput)" || \
     echo "infilters		Set the access permission to the firewall sockets (fwinput)"
  exit
fi

FW_DIR=$1
[ ! -f $FW_DIR/fwinput ] || [ ! -f /usr/share/fwguardian/modules/infilters.ctl ] && exit

sh=$(which bash)
iptables=$(which iptables)
sedipt=$(echo $iptables | sed "s/\//\\\\\//g")


### Verify md5 hash in include files
md5pass=$($FW_DIR/modules/chkmd5.mod $FW_DIR/modules/include/infilters.inc)
[ ! -f /usr/share/fwguardian/include/infilters.inc ] || [ "$md5pass" -eq 0 ] && \
   cp -f $FW_DIR/modules/include/infilters.inc /usr/share/fwguardian/include/

echo "Firewall... Loading INPUT rules!"
[ -f /usr/share/fwguardian/enable_tcprst.ctl ] && tcprst=1 || tcprst=0


### Input rule files
rulefiles="$FW_DIR/fwinput"

### Cluster file
if [ -f /usr/share/fwguardian/modules/clusterfw.ctl ] && [ -f /var/tmp/gluster.group ]; then
  cldir="$FW_DIR/cluster/glusterfs"
  clusterdir="$FW_DIR/cluster/glusterfs/local/fs"
  if [ -f "$clusterdir/fwinput" ] && [ -f $clusterdir/allow.firewall ]; then
     rulefiles="$clusterdir/fwinput $rulefiles"

     rsync=$(which rsync)
     gl_group=$(cat /var/tmp/gluster.group)
     [ -f /usr/share/fwguardian/cluster/glusterfs.done ] && $rsync -arlp --exclude '*~' --exclude '^.' $cldir/cluster/$gl_group/fwinput $clusterdir/fwinput 2>>$FW_DIR/logs/cluster.base.err
  fi
  rulefiles="$FW_DIR/cluster/alias $rulefiles"
else
  [ -f $FW_DIR/alias ] && rulefiles="$FW_DIR/alias $rulefiles"
fi
[ -f $FW_DIR/conditions ] && rulefiles="$FW_DIR/conditions $rulefiles"

echo "### INPUT rules (`date`)" | tee -a $FW_DIR/logs/fwinput.err > $FW_DIR/build/fwinput
cat $rulefiles 2>/dev/null | grep -v "^#\|^;" | grep "[[:alpha:]]" | igawk -v tcprst=$tcprst --re-interval '\
  @include /usr/share/fwguardian/include/alias.inc \
  { pproto=""; \
    @include /usr/share/fwguardian/include/infilters.inc \
  }' | sed "s/iptables/$sedipt/g" | tee -a $FW_DIR/build/fwinput | $sh - 2>>$FW_DIR/logs/fwinput.err

