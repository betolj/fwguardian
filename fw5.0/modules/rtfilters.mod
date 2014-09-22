#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# rtfilters module (FORWARD or/and MASQUERADE iptables rules)
#

if [ "$1" == "--help" ] || [ "$1" == "" ] ; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "rtfilters		Permissões de roteamento: controle de pacotes (fwroute.rules)" || \
     echo "rtfilters		Routing permissions: packet control (fwroute.rules)"
  exit
fi

FW_DIR=$1
[ ! -f $FW_DIR/fwroute.rules ] || [ ! -f /usr/share/fwguardian/modules/rtfilters.ctl ] && exit

ip=$(which ip)
sh=$(which bash)
iptables=$(which iptables)
sedipt=$(echo $iptables | sed "s/\//\\\\\//g")


### Verify md5 hash in include files
md5pass=$($FW_DIR/../modules/chkmd5.mod $FW_DIR/../modules/include/rtfilters.inc)
[ ! -f /usr/share/fwguardian/include/rtfilters.inc ] || [ "$md5pass" -eq 0 ] && \
   cp -f $FW_DIR/../modules/include/rtfilters.inc /usr/share/fwguardian/include/

md5pass=$($FW_DIR/../modules/chkmd5.mod $FW_DIR/../modules/include/rtfilters.define.inc)
[ ! -f /usr/share/fwguardian/include/rtfilters.define.inc ] || [ "$md5pass" -eq 0 ] && \
   cp -f $FW_DIR/../modules/include/rtfilters.define.inc /usr/share/fwguardian/include/


echo "Firewall... Loading FORWARD rules!"
$iptables -F RtRules 2>/dev/null
$iptables -t nat -F RtRules 2>/dev/null
$iptables -t raw -F RtRules 2>/dev/null
$iptables -t raw -D PREROUTING -j RtRules 2>/dev/null
$iptables -t raw -X RtRules 2>/dev/null

if [ -f /usr/share/fwguardian/rtfilters.rtsec ]; then
   $iptables -t mangle -D RtSec -j RtSecRules 2>/dev/null
   $iptables -t mangle -F RtSecRules 2>/dev/null
   $iptables -t mangle -X RtSecRules 2>/dev/null
   rm -f /usr/share/fwguardian/rtfilters.rtsec
fi

[ -f /usr/share/fwguardian/enable_tcprst.ctl ] && tcprst=1 || tcprst=0
[ -f /usr/share/fwguardian/rtfilters.frtlock ] && mkfrt=0 || mkfrt=1


### Flush *filter* chains
if [ -f /usr/share/fwguardian/rtfilters.chains ]; then
  cat /usr/share/fwguardian/rtfilters.chains | awk '{ \
    print "iptables -F "$1" 2>/dev/null "; \
    print "iptables -X "$1" 2>/dev/null "; \
  }' | sed "s/iptables/$sedipt/g" | $sh - 2>>$FW_DIR/../logs/fwroute.err
  rm -f /usr/share/fwguardian/rtfilters.chains 2>/dev/null
fi

### Flush *webauth* chains (Remove group and users chains)
if [ -f /usr/share/fwguardian/rtwebauth.chains ]; then
  cat /usr/share/fwguardian/rtwebauth.chains | awk '{ \
    print "iptables -F "$1" 2>/dev/null "; \
    print "iptables -X "$1" 2>/dev/null "; \
  }' | sed "s/iptables/$sedipt/g" | $sh - 2>>$FW_DIR/../logs/fwroute.err
  rm -f /usr/share/fwguardian/rtwebauth.chains 2>/dev/null
fi

### Webserver chains
if [ -f /usr/share/fwguardian/webserver.ctl ]; then
  ## Flush and remove all users auth and Webauth chains 
  $iptables -t nat -D PREROUTING -j WebAuth 2>/dev/null
  $iptables -t nat -F WebAuth 2>/dev/null
  $iptables -t nat -X WebAuth 2>/dev/null
else
  rm -f /usr/share/fwguardian/webauth/control/OPEN_ADDRESSES 2>/dev/null
fi
[ -f /usr/share/fwguardian/rtfilters.authmap.ctl ] && rm -f /usr/share/fwguardian/rtfilters.authmap.ctl 2>/dev/null

### Routing rule files
rulefiles="$FW_DIR/fwroute.rules"

### Cluster file
if [ -f /usr/share/fwguardian/modules/clusterfw.ctl ] && [ -f /var/tmp/gluster.group ]; then
  cldir="$FW_DIR/../cluster/glusterfs"
  clusterdir="$FW_DIR/../cluster/glusterfs/local/fs/routing"
  if [ -f "$clusterdir/fwroute.rules" ] && [ -f $clusterdir/../allow.firewall ]; then
     rulefiles="$clusterdir/fwroute.rules $rulefiles"

     rsync=$(which rsync)
     gl_group=$(cat /var/tmp/gluster.group)
     [ -f /usr/share/fwguardian/cluster/glusterfs.done ] && $rsync -arlp --exclude '*~' --exclude '^.' $cldir/cluster/$gl_group/routing/fwroute.rules $clusterdir/fwroute.rules 2>>$FW_DIR/../logs/cluster.base.err
  fi
  rulefiles="$FW_DIR/../cluster/alias $rulefiles"
else
  [ -f $FW_DIR/../alias ] && rulefiles="$FW_DIR/../alias $rulefiles"
fi
[ -f $FW_DIR/../conditions ] && rulefiles="$FW_DIR/../conditions $rulefiles"

### Make the routing rules
webport=$(grep "^[\s]*bind\.http\b" $FW_DIR/../webauth/webauth.conf | sed 's/.*://' || echo 0)
[ -f /usr/share/fwguardian/sproxy.forward.ctl ] && $sh /usr/share/fwguardian/sproxy.forward.ctl 2>>$FW_DIR/../logs/fwroute.err
echo "### Routing rules (`date`)" | tee -a $FW_DIR/../logs/fwroute.err > $FW_DIR/../build/fwroute.rules
cat $rulefiles 2>/dev/null | \
  grep -v "^#\|^;" | grep "[[:alpha:]]" | igawk -v webport=$webport -v mkfrt=$mkfrt -v tcprst=$tcprst '\
  @include /usr/share/fwguardian/include/alias.inc \
  { pproto=""; \
    @include /usr/share/fwguardian/include/rtfilters.define.inc \
    @include /usr/share/fwguardian/include/rtfilters.inc \
  }' | sed "s/iptables/$sedipt/g" | tee -a $FW_DIR/../build/fwroute.rules | $sh - 2>>$FW_DIR/../logs/fwroute.err


### route auth support
if [ -f /usr/share/fwguardian/rtauth.ctl ]; then
  ### Bypass firewall address in netfilter raw table and webauth redir
  cat /usr/share/fwguardian/fw.ipaddr | awk '\
  { countauth++;
    print "iptables -t raw -I RtRules "countauth" -d "$0" -j RETURN 2>/dev/null"; \
    print "iptables -t nat -I WebAuth "countauth" -d "$0" -j RETURN 2>/dev/null"; \
  }' | sed "s/iptables/$sedipt/g" | tee -a $FW_DIR/../build/fwroute.rules | $sh - 2>>$FW_DIR/../logs/fwroute.err

  ### Restore webauth rules
  [ ! -f "/usr/share/fwguardian/webauth/control/reset" ] && /usr/share/fwguardian/webauth/webctl.sh restore 2>/dev/null 1>/dev/null &
fi

