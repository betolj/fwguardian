#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Glusterfs server (settings and firewall rules)
#

[ "$1" == "" ] && exit

PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

gluster=$(which gluster)
[ ! -f "$gluster" ] && exit

FW_DIR=$1
iptables=$(which iptables)
CL_DIR=$FW_DIR/modules/tools/cluster

# Flush InGlusterfs (gluster peers)
$iptables -F InGlusterfs 2>/dev/null
cat /usr/share/fwguardian/cluster/glusterfs.done | \
while read line; do
   $iptables -A InGlusterfs -s $line -j ACCEPT 2>>$FW_DIR/logs/cluster.base.err
done

if [ ! -f /tmp/glusterfs.lock ]; then
#   echo "(re)Starting gluster at: `date`" 2>&1 >>$FW_DIR/logs/cluster.base.err
#   $CL_DIR/glusterfs/glusterfs-server restart 2>&1 >>$FW_DIR/logs/cluster.base.err

   # Mount gluster volume
   gluster=$(which gluster)
   $gluster volume info | grep Name | grep gl_ | \
   while read line; do
      gfile=$(echo $line | sed 's/.*://; s/\s\+//;')
      [ ! -d "$FW_DIR/cluster/glusterfs/cluster/$gfile" ] && mkdir -p $FW_DIR/cluster/glusterfs/cluster/$gfile 2>/dev/null || \
                                                             umount -f -l $FW_DIR/cluster/glusterfs/cluster/$gfile 2>/dev/null

      [ -f "/var/tmp/cluster.manager" ] && $gluster volume start $gfile 2>&1 >>$FW_DIR/logs/cluster.base.err
      #$gluster volume quota $gfile enable 2>&1 >>$FW_DIR/logs/cluster.base.err
      #$gluster volume quota $gfile limit-usage / 400MB 2>&1 >>$FW_DIR/logs/cluster.base.err
      mount -t glusterfs -o rw /etc/glusterd/vols/$gfile/$gfile-fuse.vol $FW_DIR/cluster/glusterfs/cluster/$gfile 2>&1 >>$FW_DIR/logs/cluster.base.err
   done
   touch /tmp/glusterfs.lock
fi

