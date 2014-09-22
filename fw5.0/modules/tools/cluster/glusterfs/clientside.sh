#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Glusterfs client (clusterfs mount and local sync)
#

[ "$1" == "" ] && exit

PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

FW_DIR=$1
rsync=$(which rsync)
gfile=$(cat /var/tmp/gluster.group)

# Uniq client glusterfs
if [ -f "/var/tmp/gluster.server" ] && [ ! -f "/usr/share/fwguardian/cluster/glusterfs.done" ] && [ ! -f "/tmp/glusterfs.lock" ]; then
   gserver=$(cat /var/tmp/gluster.server)
   [ ! -d "$FW_DIR/cluster/glusterfs/cluster/$gfile" ] && mkdir -p $FW_DIR/cluster/glusterfs/cluster/$gfile 2>/dev/null || \
                                                       umount -f -l $FW_DIR/cluster/glusterfs/cluster/$gfile 2>/dev/null

   mount -t glusterfs -o ro $gserver:/$gfile $FW_DIR/cluster/glusterfs/cluster/$gfile 2>&1 >>$FW_DIR/logs/cluster.base.err
   touch /tmp/glusterfs.lock
fi

# Sync cluster directory with local directory
if [ -f "$FW_DIR/cluster/glusterfs/cluster/$gfile/allow.firewall" ]; then
   [ ! -d "$FW_DIR/cluster/glusterfs/local/$gfile" ] && mkdir -p $FW_DIR/cluster/glusterfs/local/$gfile 2>/dev/null
   $rsync -arlp $FW_DIR/cluster/glusterfs/cluster/$gfile $FW_DIR/cluster/glusterfs/local/ 2>>$FW_DIR/logs/cluster.base.err >/dev/null
fi

