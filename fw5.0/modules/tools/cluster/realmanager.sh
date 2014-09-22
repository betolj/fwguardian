#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Fix the real manager address (short prio and ip addr)
# You can redefine rebuilding cluster base or removing /opt/fw5.0/modules/tools/cluster/master.addr
#

FW_DIR=$1
shift

member_id=$@

if [ -f "$FW_DIR/master.addr" ]; then
   canch=1
   mpeer=$(cat $FW_DIR/master.addr | tr -d '\n')
   [ "$mpeer" == "$member_id" ] && canch=0

   if [ $canch == 1 ]; then
      auxmpeer=$(cat $FW_DIR/master.addr /usr/share/fwguardian/cluster/cluster.clid | sort -k1,2 -n | head -1 | tr -d '\n')
      if [ "$auxmpeer" != "" ]; then
         grep -q "^$auxmpeer$" $FW_DIR/master.addr || echo $auxmpeer > $FW_DIR/master.addr
      fi
   fi
else
   echo $member_id > $FW_DIR/master.addr
fi
