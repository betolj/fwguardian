#!/bin/bash

[ "$1" == "" ] && exit

FW_DIR=$1

[ -f /usr/share/fwguardian/cluster/glusterfs.done ] && $FW_DIR/modules/tools/cluster/glusterfs/serverside.sh $FW_DIR
[ -f /var/tmp/gluster.group ] && $FW_DIR/modules/tools/cluster/glusterfs/clientside.sh $FW_DIR
