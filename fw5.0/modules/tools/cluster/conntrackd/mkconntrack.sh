#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Make a proper conntrackd.conf
#  - Disable ExternalCache when active-active mode
#  - Configure multicast address to conntrackd updates
#

[ ! -f /usr/share/fwguardian/cluster.heartbeat ] && exit

## Setting initial configuration (Mode FTFW)
if [ -f /usr/share/fwguardian/cluster.nocache ]; then
   cat << EOF > /etc/conntrackd/conntrackd.conf
Sync {
    Mode NOTRACK {
        DisableInternalCache On
        DisableExternalCache On
    }

EOF
else
   cat << EOF > /etc/conntrackd/conntrackd.conf
Sync {
    Mode FTFW {
        DisableExternalCache Off
        CommitTimeout 1800
    }

EOF
fi

## Setting the multicast group
count=0
maddr=49
mgrp=3779
while read line; do
   ((count++))
   ((mgrp+=count))
   ((maddr+=count))
   mif=$(echo $line | cut -d' ' -f1)
   msrcaddr=$(echo $line | cut -d' ' -f2 | sed 's/\/.*//g')
   [ "$count" == "0" ] && mcast="Default" || mcast=""
cat << EOF >> /etc/conntrackd/conntrackd.conf

    Multicast $mcast {
        IPv4_address 225.0.0.$maddr
        Group $mgrp
        IPv4_interface $msrcaddr
        Interface $mif
        SndSocketBuffer 1249280
        RcvSocketBuffer 1249280
        Checksum on
    }
EOF
done < /usr/share/fwguardian/cluster.heartbeat

## Finish configuration
cat << EOF >> /etc/conntrackd/conntrackd.conf
}


General {

        Nice -20

        # Number of buckets in the caches: hash table
        HashSize 32768

        # Maximum number of conntracks: 
        # it must be >= $ cat /proc/sys/net/ipv4/netfilter/ip_conntrack_max or /proc/sys/net/netfilter/nf_conntrack_max
        HashLimit 131072

        # Logfile: on (/var/log/conntrackd.log), off, or a filename
        #LogFile on
        #Syslog off

        # Lockfile
        LockFile /var/lock/conntrackd.lock

        # Unix socket configuration
        UNIX {
                Path /var/run/conntrackd.sock
                Backlog 20
        }

        # Netlink socket buffer size
        #
        # SocketBufferSize 262142
        # SocketBufferSizeMaxGrown 655355
        NetlinkBufferSize 2097152
        NetlinkBufferSizeMaxGrowth 8388608


        Filter From Userspace {
                Protocol Accept {
                        TCP
                        UDP
                        ICMP
                }

                Address Ignore {
                        IPv4_address 127.0.0.1 # loopback
EOF
if [ -f /usr/share/fwguardian/fw.ipaddr ]; then
   while read line; do
      [ "$line" != "127.0.0.1" ] && echo "                        IPv4_address $line" >> /etc/conntrackd/conntrackd.conf
   done < /usr/share/fwguardian/fw.ipaddr
fi
cat << EOF >> /etc/conntrackd/conntrackd.conf
                }
        }
}
EOF
