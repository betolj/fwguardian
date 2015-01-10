#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# profile module (control firewall profiles - new chains) - rev1
#

if [ "$1" == "--help" ] || [ "$1" == "" ] ; then
  exit
fi

FW_DIR=$1
sh=$(which bash)
iptables=$(which iptables)
sedipt=$(echo $iptables | sed "s/\//\\\\\//g")

rload=$2
[ ! "$rload" ] && exit 0

### Verify md5 hash in include files
md5pass=$($FW_DIR/../modules/chkmd5.mod $FW_DIR/../modules/include/profile.inc)
[ ! -f /usr/share/fwguardian/include/profile.inc ] || [ "$md5pass" -eq 0 ] && \
   cp -f $FW_DIR/../modules/include/profile.inc /usr/share/fwguardian/include/

# Making profile rules
echo "Firewall... Loading profiles!"

# Reading profile.def for "Profiles" difinitions
if [ $rload == "profile" ]; then
   rload=".*"
   $iptables -t nat -F vpop3 2>/dev/null
   $iptables -t nat -F rsquid 2>/dev/null
else
   $iptables -F $rload 2>/dev/null
fi

# Define maxsyn to max htable
maxconn=$(sysctl net.netfilter.nf_conntrack_max | cut -d " " -f 3)
[ "$maxconn" == "" ] || [ "$maxconn" -lt 65536 ] && maxconn=65536
maxsyn=$((maxconn / 4))

[ "$maxsyn" -lt 30000 ] && maxsyn=30000

### Profile files
profiles="$FW_DIR/profile.def"

### Cluster file
if [ -f /usr/share/fwguardian/modules/clusterfw.ctl ] && [ -f /var/tmp/gluster.group ]; then
  cldir="$FW_DIR/../cluster/glusterfs"
  clusterdir="$FW_DIR/../cluster/glusterfs/local/fs/profile"
  if [ -f "$clusterdir/profile.def" ] && [ -f $clusterdir/../allow.firewall ]; then
     profiles="$clusterdir/profile.def $profiles"

     rsync=$(which rsync)
     gl_group=$(cat /var/tmp/gluster.group)
     [ -f /usr/share/fwguardian/cluster/glusterfs.done ] && $rsync -arlp --exclude '*~' --exclude '^.' $cldir/cluster/$gl_group/profile/profile.def $clusterdir/profile.def 2>>$FW_DIR/../logs/cluster.base.err
  fi
fi
[ -f $FW_DIR/../conditions ] && profiles="$FW_DIR/../conditions $profiles"

echo "### Profiles (`date`)" | tee -a $FW_DIR/../logs/profile.err > $FW_DIR/../build/profile.def
cat $profiles | grep -v "^#\|^;" | grep "[[:alpha:]]" | igawk -v rload=$rload -v maxsyn=$maxsyn '\
  @include /usr/share/fwguardian/include/alias.inc \
  { \
     ### Target alias
     if (match($5,"^(BYPASS|%BP|%A|%D|%R)$")) { \
       sub("(BYPASS|%BP)","RETURN",$5); \
       sub("%A","ACCEPT",$5); \
       sub("%D","DROP",$5); \
       sub("%R","RETURN",$5); \
     } \
    @include /usr/share/fwguardian/include/profile.inc \
  }' | sed "s/iptables/$sedipt/g" | tee -a $FW_DIR/../build/profile.def | $sh - 2>>$FW_DIR/../logs/profile.err

