#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
#
# Interface settings 
#   Interface   mac         mtu    vlan        rp_filter   arp_filter  qlen   CPUs
#   eth0        auto        auto   1           0           0           5000   6,7
#

if [ "$1" == "--help" ] || [ "$1" == "" ]; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "interfaces              Aplica configurações de interface de rede (interfaces)" || \
     echo "interfaces              Apply network interface settings (interfaces)"
  exit
fi


FW_DIR=$1
[ ! -f $FW_DIR/interfaces ] || [ ! -f /usr/share/fwguardian/modules/interfaces.ctl ] && exit

sh=$(which bash)
ip=$(which ip)
brctl=$(which brctl)
logger=$(which logger)


set_vlan() {
   ifname=$1
   shift
   brname=$1
   shift

   # VLAN Support
   vconfig=$(which vconfig)
   [ ! -f /proc/net/vlan/config ] && modprobe 8021q

   # Setup bridge interface
   [ "$brname" != "auto" ] && [ $brname != "none" ] && setbrd=1 || setbrd=0
   br_name="$brname"

   if [ -f "$vconfig" ] && [ -f /proc/net/vlan/config ]; then
      for i in $(echo $@);
      do
         # Setup vlan interface
         upd=$(grep "^$ifname.$i\b" /proc/net/vlan/config >/dev/null && echo 0 || echo 1)
         if [ "$upd" == 1 ]; then
            $vconfig add $ifname $i 2>/dev/null >/dev/null
            $ip link set $ifname.$i up 2>/dev/null
         fi

         # Setup bridge interface
         if [ "$setbrd" == "1" ] && [ -f $brctl ]; then
            [ "$brname" == "use_vlanid" ] && br_name="br_vl$i"
            if [ ! -f /sys/class/net/$br_name/brforward ]; then
               $brctl addbr $br_name
               $ip link set $br_name up 2>/dev/null
               echo "$br_name" >> /var/tmp/fw.mybridges
            fi
            [ ! -d "/sys/class/net/$br_name/lower_$ifname.$i" ] && $brctl addif $br_name $ifname.$i
         fi
      done
   else
      logger "fwguardian: sorry, no VLAN interface support!"
   fi
}

set_interface() {
   ifname=$1

   ifdisp=0
   for i in $(echo $@); do
      ((ifcount++))
      [ $i != "auto" ] && [ $i != "none" ] && [ $ifcount -lt 10 ] && ifdisp=1
   done

   if [ -f "/sys/class/net/$ifname/dev_id" ]; then
      ifirq=0
      irqdata=$(grep " $ifname$" /proc/interrupts | tr -d '\n')
      ifirq=$(echo $irqdata | sed s/:.*//)

      # Create /tmp/interfaces.update to force firewall interfaces reconfigure
      # Usefull in /etc/rc.local
      ifnet=""
      upd=$(grep "up" /sys/class/net/$ifname/operstate >/dev/null && echo 0 || echo 1)
      updif=$upd
      [ -f /tmp/interfaces.update ] && upd=1

      if [ "$upd" == "1" ]; then
         # Setup MAC addr and MTU length (if no auto)
         [ "$2" != "auto" ] && $ip link set dev $ifname addr $2 2>/dev/null
         [ "$3" != "auto" ] && $ip link set dev $ifname mtu $3 2>/dev/null
         [ "$8" != "auto" ] && $ip link set dev $ifname qlen $8 2>/dev/null
         if [ "$updif" == "1" ]; then
            $ip link set dev $ifname up 2>/dev/null
            irqdata=$(grep " $ifname$" /proc/interrupts | tr -d '\n')
            ifirq=$(echo $irqdata | sed s/:.*//)
         fi

         # Setup Bridge, VLANs and qlen (queue length)
         if [ "$4" != "auto" ] && [ "$4" != "1" ]; then
            lstVlan=$(echo $4 | tr ',' ' ')
            set_vlan $ifname $5 $lstVlan
         else
            # Setup Bridge Interface
            if [ "$5" != "auto" ] && [ "$5" != "none" ] && [ -f $brctl ]; then
               if [ ! -f /sys/class/net/$5/brforward ]; then
                  $brctl addbr $5
                  $ip link set $5 up 2>/dev/null
                  echo "$5" >> /var/tmp/fw.mybridges
               fi
               $brctl addif $5 $ifname
            fi
         fi
      fi

      # Setup a new IRQ Affinity and isolate CPU (works better with grub - including isolcpus)
      ifnet="CPU *auto*"
      if [ -f /proc/irq/$ifirq/smp_affinity ]; then
         ifdisp=1
         cpulst=$9
         [ "$cpulst" != "auto" ] && echo $cpulst > /proc/irq/$ifirq/smp_affinity_list
         ifnet="CPU *$cpulst*"
      fi
      ifnet="mac $2, mtu $3, qlen $8, rp_filter $6, arp_filter $7, $ifnet"

      # Enable|disable rp_filter and arp_filter
      [ "$6" != "auto" ] && echo $6 > /proc/sys/net/ipv4/conf/$ifname/rp_filter
      [ "$7" != "auto" ] && echo $7 > /proc/sys/net/ipv4/conf/$ifname/arp_filter

      [ $ifdisp == 1 ] && echo "            Interface $ifname: IRQ $ifirq, $ifnet"
   fi
}

# Setup network interfaces
echo "Firewall... Setup network interfaces!"
if [ -f /tmp/interfaces.update ] && [ -f /var/tmp/fw.mybridges ]; then
   cat /var/tmp/fw.mybridges | awk '{ \
      print "ip link set dev "$1" down 2>/dev/null"; \
      print "brctl delbr "$1" 2>/dev/null"; \
   }' | $sh -
   rm -f /var/tmp/fw.mybridges
fi
cat $FW_DIR/interfaces | grep -v "^[\s]*#" | \
while read line; do
   set_interface $line
done

[ -f /tmp/interfaces.update ] && rm -f /tmp/interfaces.update

