#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# bannedfw module (blacklist settings)
#

if [ "$1" == "--help" ] || [ "$1" == "" ] ; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "bannedfw		Lista negra simples: Rotas proibitivas ou controle de acesso básico (bannedroutes/bannedaccess)" || \
     echo "bannedfw		Simple blacklist: Prohibited routes or basic access control (bannedroutes/bannedaccess)"
  exit
fi

[ ! -f /usr/share/fwguardian/modules/bannedfw.ctl ] && exit

FW_DIR=$1
ip=$(which ip)
sh=$(which bash)
BTYPE=$2
iptables=$(which iptables)
sedipt=$(echo $iptables | sed "s/\//\\\\\//g")


### Banned files
banrt="$FW_DIR/accesslist/bannedroutes"
banac="$FW_DIR/accesslist/bannedaccess"

### Cluster file
if [ -f /usr/share/fwguardian/modules/clusterfw.ctl ] && [ -f /var/tmp/gluster.group ]; then
   cldir="$FW_DIR/cluster/glusterfs"
   clusterdir="$FW_DIR/cluster/glusterfs/local/fs"
   if [ -f "$clusterdir/allow.firewall" ]; then
      rsync=$(which rsync)
      gl_group=$(cat /var/tmp/gluster.group)

      if [ -f "$clusterdir/accesslist/bannedroutes" ]; then
         banrt="$clusterdir/accesslist/bannedroutes $banrt"
         [ -f /usr/share/fwguardian/cluster/glusterfs.done ] && $rsync -arlp --exclude '*~' --exclude '^.' $cldir/cluster/$gl_group/accesslist/bannedroutes $clusterdir/accesslist/bannedroutes 2>>$FW_DIR/logs/cluster.base.err
      fi
      if [ -f "$clusterdir/accesslist/bannedaccess" ]; then
         banac="$clusterdir/accesslist/bannedaccess $banac"
         [ -f /usr/share/fwguardian/cluster/glusterfs.done ] && $rsync -arlp --exclude '*~' --exclude '^.' $cldir/cluster/$gl_group/accesslist/bannedaccess $clusterdir/accesslist/bannedaccess 2>>$FW_DIR/logs/cluster.base.err
      fi
   fi
fi

## Remove prohibit routes
echo "### Banned rules (`date`)" | tee -a $FW_DIR/logs/blacklists.err > $FW_DIR/build/blacklists
if [ "$BTYPE" == "routes" ]; then
  $ip route ls | grep prohibit | \
      sed "s/prohibit/ip\ route\ del\ prohibit/" | tee -a $FW_DIR/build/blacklists | $sh - 2>>$FW_DIR/logs/blacklists.err
  [ ! -f /usr/share/fwguardian/modules/bannedfw.ctl ] && exit

  ## Re-adding prohibit routes
  echo "Firewall... Loading Banned Routes rules"
  cat $banrt | grep "[[:digit:]]" | grep -v "^#\|^;" | awk '{print "ip "$1}' | \
      sed -e "s/ip/ip route add prohibit/" | tee -a $FW_DIR/build/blacklists | $sh - 2>>$FW_DIR/logs/blacklists.err
else
  if [ "$BTYPE" == "access" ]; then
    ### Making DROP rules for each routing network interface
    echo "Firewall... Loading Banned Access rules"
    $iptables -t mangle -F AcBanned 2>/dev/null
    cat $banac | grep "^[ \|\t]*\(port\|net\|resolv\)" | awk '{ \
      if ($1=="port") { \
          OD=" -p "$2" --dport "$3; \
          if ($2 == "tcp") OD=OD" --syn"; \
          if (match($0,"(tcp|udp)( |\t)+([0-9a-zA-Z-])+[:]*([0-9a-zA-Z-])*,")) OD="-m multiport "OD" "; \
          print "iptables -t mangle -A AcBanned "OD" -j DROP"; \
      } else 
        { if ($1=="net") print "iptables -t mangle -A AcBanned -d "$2" -j DROP"; \
          else if ($1=="resolv") { \
          if (match($2, ".")) {
            fdns=""; auxpar=""; \
            split($2, auxparam, "."); \
            for (i in auxparam) { \
              if (i > 1) { \
                 auxpar=length(auxparam[i]); \
                 if (length(auxpar) < 2) auxpar="0"auxpar; \
                 fdns=fdns""auxpar; \
              } \
              cmd="echo "auxparam[i]" | tr -d \"\\n\" | xxd -ps | tr -d \"\\n\""; \
              cmd | getline auxpar; close (cmd); \
              fdns=fdns""auxpar; \
            } \
            print "iptables -t mangle -A AcBanned -m string --hex-string \"|"fdns"|\" --algo bm -p udp --dport 53 -m comment --comment \""$2"\" -j DROP"; \
          } else print "iptables -t mangle -A AcBanned -m string --string \""$2"\" --algo bm -p udp --dport 53 -j DROP"; \
          } \
    } }' | sed "s/iptables/$sedipt/g; s/intnet/$i/" | tee -a $FW_DIR/build/blacklists | $sh - 2>>$FW_DIR/logs/blacklists.err 
  fi
fi
