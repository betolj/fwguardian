#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Cluster module
#

if [ "$1" == "--help" ] || [ "$1" == "" ] ; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "clusterfw               Ativa funções de cluster (cluster/cluster.conf)" || \
     echo "clusterfw               Enable Cluster functions (cluster/cluster.conf)"
  exit
fi

[ ! -f /usr/share/fwguardian/modules/clusterfw.ctl ] && exit

FW_DIR=$1
CL_DIR=$FW_DIR/modules/tools/cluster
ip=$(which ip 2>/dev/null)
sh=$(which bash 2>/dev/null)
iptables=$(which iptables)


echo "Firewall... Loading Cluster settings"
$iptables -F InCluster 2>/dev/null
$iptables -N InCluster 2>/dev/null
$iptables -F InGlusterfs 2>/dev/null
[ -f /usr/share/fwguardian/cluster.glusterfs-server ] && $iptables -N InGlusterfs 2>/dev/null

ctmc=0
maddr=49
declare -A mb_dev
syncport=$(cat /usr/share/fwguardian/cluster/ssh)
ip route del 225.1.1.12 2>/dev/null
$iptables -F IFVMAC 2>/dev/null
$iptables -N IFVMAC 2>/dev/null
if [ -f /usr/share/fwguardian/cluster.use_vmac ]; then
   $iptables -A IFVMAC -i vrrp+ -j ACCEPT
   $iptables -A INPUT -i vrrp+ -d 225.1.1.12 -j InCluster
fi
if [ -f /var/tmp/cluster.sync.peers ]; then
   while read line; do
      mbsrc=$(echo $line | cut -d ' ' -f1)
      mbdev=$(echo $line | cut -d ' ' -f2)
      mbnet=$(ip route ls | grep "proto kernel" | grep "src $mbsrc" | cut -d' ' -f1 | head -1)

      if [ "$mbnet" != "" ]; then
         ((ctmc++))
         [ $ctmc == 1 ] && $ip route add 225.1.1.12 dev $mbdev src $mbsrc 2>&1 >>$FW_DIR/logs/cluster.base.err 
         $iptables -A INPUT -i $mbdev -s $mbnet -j InCluster 2>&1 >>$FW_DIR/logs/cluster.base.err
         $iptables -A InCluster -s $mbnet -m multiport -p tcp --sport 5353,5858,24007 -j IFVMAC 2>&1 >>$FW_DIR/logs/cluster.base.err
         $iptables -A InCluster -s $mbnet -m multiport -p tcp --dport 5353,5858,24007:24207,49150:49350 -j IFVMAC 2>&1 >>$FW_DIR/logs/cluster.base.err
         $iptables -A InCluster -i $mbdev -s $mbnet -p vrrp -j ACCEPT 2>&1 >>$FW_DIR/logs/cluster.base.err
         $iptables -A InCluster -i $mbdev -s $mbnet -p tcp --dport $syncport -j ACCEPT 2>&1 >>$FW_DIR/logs/cluster.base.err

         [ "${mb_dev[$mbdev]}" == "" ] && $iptables -A IFVMAC -i $mbdev -s $mbnet -j ACCEPT 2>/dev/null
         mb_dev[$mbdev]=$mbdev

         ((maddr++))
         $ip route del 225.0.0.$maddr 2>/dev/null
         $ip route add 225.0.0.$maddr dev $mbdev src $mbsrc
      fi
   done < /var/tmp/cluster.sync.peers
fi

[ ! -f /var/tmp/gluster.server ] && $iptables -A INPUT -m multiport -p tcp --dport 24007:24207,49150:49350 -j InGlusterfs
$iptables -A INPUT -d 224.0.0.1 -j InCluster 2>&1 >>$FW_DIR/logs/cluster.base.err
$iptables -A InCluster -p igmp -j ACCEPT 2>&1 >>$FW_DIR/logs/cluster.base.err
$iptables -A InCluster -d 224.0.0.0/4 -p icmp -j ACCEPT 2>&1 >>$FW_DIR/logs/cluster.base.err
$iptables -A InCluster -d 225.1.1.12 -p udp --dport 5858 -j ACCEPT 2>&1 >>$FW_DIR/logs/cluster.base.err

if [ -f /usr/share/fwguardian/cluster.vrrp ]; then
   $iptables -A INPUT -d 224.0.0.18 -j InCluster 2>/dev/null
   cat /usr/share/fwguardian/cluster.vrrp | awk '{ \
       print "iptables -A InCluster -i "$1" -d 224.0.0.18 -p vrrp -j ACCEPT"; \
   }' | $sh - 2>&1 >>$FW_DIR/logs/cluster.base.err

   [ ! -f /usr/share/fwguardian/cluster.nocache ] && rm -f /var/tmp/*.vrlock 2>/dev/null
fi

if [ -f /usr/share/fwguardian/cluster.prerules ] || [ -f /usr/share/fwguardian/cluster.heartbeat ]; then
   if [ -f /usr/share/fwguardian/cluster.prerules ]; then
      $iptables -t mangle -N PreCluster 2>/dev/null
      $iptables -t mangle -I PREROUTING -j PreCluster
   fi

   $iptables -A INPUT -d 225.0.0.50 -j InCluster 2>/dev/null
   /usr/local/bin/nfcluster.sh 2>&1 >>$FW_DIR/logs/cluster.base.err
fi


# Start Glusterfs daemon
if [ -f /usr/share/fwguardian/cluster.glusterfs-server ] && [ ! -f /tmp/glusterfs.lock ]; then
   echo "(re)Starting gluster at: `date`" 2>&1 >>$FW_DIR/logs/cluster.base.err
   $CL_DIR/glusterfs/glusterfs-server restart 2>&1 >>$FW_DIR/logs/cluster.base.err
fi

# Start keepalived and conntrackd daemons
if [ ! -f /tmp/clusterbase.lock ]; then
   # disable send icmp_redirects
   for i in $(ls /proc/sys/net/ipv4/conf/*/send_redirects); do
     echo 0 > $i
   done

   if [ -f /usr/share/fwguardian/cluster.sync_state ]; then
      echo 0 > /proc/sys/net/netfilter/nf_conntrack_tcp_loose
      echo 1 > /proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal
      modprobe nf_conntrack
      modprobe nf_conntrack_ipv4
      $CL_DIR/conntrackd/conntrackd run restart 2>&1 >>$FW_DIR/logs/cluster.base.err
   fi

   if [ -f /usr/share/fwguardian/cluster.vrrp ]; then
      echo "            Waiting for network VIP settings (3s)"
      arptables=$(which arptables)
      [ -f /usr/share/fwguardian/cluster.defaultgw ] && $ip route del default 2>/dev/null
      if [ -f "$arptables" ]; then
         $arptables -F
         $arptables -X
         if [ -f /usr/share/fwguardian/cluster.multicastmac ]; then
            $arptables -N In_Multicast 2>/dev/null
            $arptables -N Out_Multicast 2>/dev/null
            cat /usr/share/fwguardian/cluster.vips 2>/dev/null | awk '{ print "arptables -A INPUT -d "$1" -j In_Multicast"; print "arptables -A OUTPUT -s "$1" -j Out_Multicast"; }' | $sh - 2>&1 >>$FW_DIR/logs/cluster.base.err
            $CL_DIR/vrrp/multicastmac.sh /usr/share/fwguardian/cluster.multicastmac 2>&1 >>$FW_DIR/logs/cluster.base.err
         fi
      fi

      rm -f /var/tmp/cluster.vip.* 2>/dev/null
      $CL_DIR/vrrp/keepalived run restart 2>&1 >>$FW_DIR/logs/cluster.base.err

      sleep 3
      [ -f /proc/sys/net/ipv4/route/flush ] && echo 1 > /proc/sys/net/ipv4/route/flush || $ip route flush cache
   fi
fi

touch /tmp/clusterbase.lock
[ -f /proc/sys/net/ipv4/route/flush ] && echo 1 > /proc/sys/net/ipv4/route/flush
[ -d /usr/share/fwguardian/cluster/sshkey ] && chmod -R 600 /usr/share/fwguardian/cluster/sshkey

