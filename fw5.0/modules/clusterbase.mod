#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Define cluster settings (--configure-cluster)
#

sh=$(which bash)
FW_DIR=$1
CL_DIR=$FW_DIR/../modules/tools/cluster
if [ ! -f $FW_DIR/cluster.conf ] || [ ! -f /usr/share/fwguardian/modules/clusterfw.ctl ]; then
   [ -f $CL_DIR/conntrackd/conntrackd ] && $CL_DIR/conntrackd/conntrackd run stop 2>&1 >/dev/null
   exit
fi

gluster=$(which gluster)
svcontrol="debian"
[ ! -f "/etc/debian_version" ] && svcontrol="redhat"

### Removing all cluster support
rm -f /usr/share/fwguardian/cluster\.* 2>/dev/null
rm -f /var/tmp/keepalived.fail\.* 2>/dev/null

### Verify md5 hash in include files
md5pass=$($FW_DIR/../modules/chkmd5.mod $FW_DIR/../modules/include/cluster.base.inc)
[ ! -f /usr/share/fwguardian/include/cluster.base.inc ] || [ "$md5pass" -eq 0 ] && \
   cp -f $FW_DIR/../modules/include/cluster.base.inc /usr/share/fwguardian/include/


rulefiles="$FW_DIR/cluster.conf"
[ -f $FW_DIR/../conditions ] && rulefiles="$FW_DIR/../conditions $rulefiles"

# Conntrackd support
ctsupport=0
if [ -d /etc/conntrackd ]; then
   ctsupport=1
   cp -f $CL_DIR/conntrackd/conntrackd.conf /etc/conntrackd/ 2>/dev/null
   [ ! -f /etc/conntrackd/primary-backup.sh ] && cp -f $CL_DIR/conntrackd/primary-backup.sh /etc/conntrackd/ 2>/dev/null
fi


echo "Firewall... Building Cluster mode and VIP rules!"
if [ -d "/etc/keepalived" ]; then
  echo "### Building Cluster mode and VIP rules (`date`)" >> $FW_DIR/../logs/cluster.base.err
  cat $rulefiles | grep -v "^#\|^;" | grep "[[:alpha:]]" | igawk -v ctsup=$ctsupport '\
  @include /usr/share/fwguardian/include/alias.inc \
  @include /usr/share/fwguardian/include/cluster.base.inc \
  END { \
    if (usevmac) system("touch /usr/share/fwguardian/cluster.use_vmac"); \
    for (i=1; i<3; i++) { \
       if (vipname[i-1, 0]) { \
          print "\nvrrp_sync_group FwG"i" {"; \
          print "    group {"; \
          if (i == 1) auxcount=masterct; \
          else auxcount=backupct; \
          for (j=0; j<auxcount; j++) print "        VIP_"vipname[i-1, j]; \
          print "    }"; \
          if (!prback || (master == backup)) system("touch /usr/share/fwguardian/cluster.nocache"); \
          print "}"; \
       } \
    } \
    for (i=0; i<vipcount; i++) { \
       print ""; \
       for (j=0; j<20+vipinop[i]; j++) { \
          print vipi[i,j]; \
          if (j == (13-vmacdif)) for (k in trackif) print "       "trackif[k]; \
          if (j == (15-vmacdif)) for (k=0; k<vipaddrcount[i]; k++) { \
             print "       "vipaddr[i, k]; \
             system("echo "vipaddr[i, k]" | sed \"s/ .*//\" >> /usr/share/fwguardian/cluster.vips");
          } \
       } \
    } \
  } ' >/etc/keepalived/keepalived.conf 2>>$FW_DIR/../logs/cluster.base.err
fi

# Disable keepalived, conntrackd and glusterfs-server daemons
if [ -f "/etc/init.d/keepalived" ]; then
   [ "$svcontrol" == "debian" ] && update-rc.d -f keepalived remove || chkconfig keepalived off
   #rm -f /etc/init.d/keepalived 2>/dev/null
fi
if [ -f "/etc/init.d/conntrackd" ]; then
   [ "$svcontrol" == "debian" ] && update-rc.d -f conntrackd remove || chkconfig conntrackd off
   #rm -f /etc/init.d/conntrackd 2>/dev/null
fi
if [ -f "/etc/init.d/glusterfs-server" ]; then
   [ "$svcontrol" == "debian" ] && update-rc.d -f glusterfs-server remove || chkconfig glusterfs-server off
   #rm -f /etc/init.d/glusterfs-server 2>/dev/null
fi

# Conntrackd daemon
[ -f /usr/share/fwguardian/cluster.sync_state ] && $CL_DIR/conntrackd/mkconntrack.sh 2>>$FW_DIR/../logs/cluster.base.err || $CL_DIR/conntrackd/conntrackd run stop 2>/dev/null

# Keepalived settings
if [ -f /usr/share/fwguardian/cluster.vrrp ]; then
   cp -f $CL_DIR/vrrp/vmac_tweak.sh /usr/local/bin/ 2>/dev/null
   cp -f $CL_DIR/conntrackd/nfcluster.sh /usr/local/bin/ 2>/dev/null
fi

# Reset Gluster confs
if [ -f /usr/share/fwguardian/cluster.glusterfs-server ]; then
   killall -9 glusterfsd 2>/dev/null
   $CL_DIR/glusterfs/glusterfs-server restart 2>&1 >>$FW_DIR/../logs/cluster.base.err
fi
if [ -f /usr/share/fwguardian/cluster/glusterfs.done ]; then
   if [ -f /var/tmp/cluster.manager ] && [ -x "$gluster" ]; then
      # umount and remove by volume info
      $gluster volume info | grep Name | grep gl_ | \
      while read line; do
         gfile=$(echo $line | sed 's/.*://; s/\s\+//;')

         umount -l -f $FW_DIR/glusterfs/cluster/$gfile 2>/dev/null
         rm -f $FW_DIR/glusterfs/cluster/$gfile 2>/dev/null
         [ -d "$FW_DIR/glusterfs/local/$gfile" ] && rm -rf $FW_DIR/glusterfs/local/$gfile 2>/dev/null

         echo $line | sed 's/.*:/echo y | gluster volume stop /' | awk '{ print $0" force "; }' | $sh - 2>>$FW_DIR/../logs/cluster.base.err
         echo $line | sed 's/.*:/echo y | gluster volume delete /' | $sh - 2>>$FW_DIR/../logs/cluster.base.err
         [ -d "/etc/glusterd/vols/$gfile" ] && rm -rf /etc/glusterd/vols/$gfile 2>/dev/null
      done

      # Detach peers
      $gluster peer status | grep Hostname | \
      while read line; do
         ghost=$(echo $line | sed 's/.*://; s/\s\+//;')
         [ -f "/usr/share/fwguardian/cluster/allowed/$ghost" ] && $gluster peer detach $ghost 2>>$FW_DIR/../logs/cluster.base.err
      done
   fi

   # Force umount by export directory
   [ -d "$FW_DIR/glusterfs/export" ] && fsdir="$FW_DIR/glusterfs/export/" || fsdir="$FW_DIR/glusterfs/cluster/"
   ls $fsdir | \
   while read line; do
      umount -l -f $FW_DIR/glusterfs/cluster/$line 2>/dev/null
      [ -d "/etc/glusterd/vols/$line" ] && rm -rf /etc/glusterd/vols/$line 2>/dev/null
   done 
   rm -f /usr/share/fwguardian/cluster/glusterfs.done
fi
rm -f /tmp/glusterfs.lock 2>/dev/null

# Kill clusterctl
if [ -f "/var/tmp/cluster.pid" ]; then
   kill $(cat /var/tmp/cluster.pid 2>/dev/null) 2>/dev/null
   rm -f /var/tmp/cluster.pid 2>/dev/null
fi

rm -rf /usr/share/fwguardian/cluster 2>/dev/null
rm -f /var/tmp/cluster.manager 2>/dev/null
rm -f /tmp/clusterbase.lock 2>/dev/null

# Setting ssh permissions
[ ! -d /root/.ssh ] && mkdir /root/.ssh
chown -R root.root /root/.ssh
chmod -R 600 /root/.ssh
