#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# vpnfw module (VPN settings)
#

if [ "$1" == "--help" ] || [ "$1" == "" ] ; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
  echo "vpnfw                   Configurações de VPN (vpn.conf)" || \
  echo "vpnfw                   VPN settings (vpn.conf)"
  exit
fi

FW_DIR=$1
VPNCMD=$2
VPNOPC=$3
ip=$(which ip)
sh=$(which bash)
setkey=$(which setkey 2>/dev/null)
iptables=$(which iptables)
sedip=$(echo $ip | sed "s/\//\\\\\//g")
sedipt=$(echo $iptables | sed "s/\//\\\\\//g")


### PAP|CHAP permitions
chown root.root /etc/ppp/{chap-secrets,pap-secrets}
chmod 600 /etc/ppp/{chap-secrets,pap-secrets}
chmod 600 $FW_DIR/../modules/vpn/ipsec/psk.txt

### Copy include file
for incf in $(ls $FW_DIR/../modules/include/vpn.*.inc);
do
  md5pass=$($FW_DIR/../modules/chkmd5.mod $incf)
  if [ ! -f /usr/share/fwguardian/include/$(basename $(echo $incf)) ] || [ "$md5pass" -eq 0 ]; then
     cp -a -f $incf /usr/share/fwguardian/include/
  fi
done

md5pass=$($FW_DIR/../modules/chkmd5.mod $FW_DIR/../modules/include/rttables.id.inc)
if [ ! -f /usr/share/fwguardian/include/rttables.id.inc ] || [ "$md5pass" -eq 0 ]; then
   cp -a -f $FW_DIR/../modules/include/rttables.id.inc /usr/share/fwguardian/include/
fi

### Remove VPN interfaces (all or only one)
if [ "$VPNCMD" == "init" ]; then
   if [ "$VPNOPC" == "all" ]; then
      for iftun in $($ip tunn ls | cut -d":" -f1); 
      do
         $ip link set $iftun down 2>/dev/null
         $ip tunn del $iftun 2>/dev/null
      done
   else
      if [ "$VPNOPC" ]; then
         $ip link set $VPNOPC down 2>/dev/null
         $ip tunn del $VPNOPC 2>/dev/null
      fi
   fi
else
   if [ "$VPNCMD" == "stop" ]; then
      /usr/share/fwguardian/vpn/pptp/start.sh run stop >&2 2>/dev/null
      /usr/share/fwguardian/vpn/ipsec/start.sh run stop >&2 2>/dev/null
      exit
   fi
fi

[ ! -f "/usr/share/fwguardian/modules/vpnfw.ctl" ] && exit


### Flush VPN Rules
$iptables -F FwVpn 2>/dev/null
$iptables -t mangle -nL RtSec | grep ssh_ | \
    awk '{ uid=$1; gsub("ssh_", "", uid); print "iptables -t mangle -D RtSec -m owner --uid-owner "uid" -j "$1" "; }' | $sh - 2>>$FW_DIR/../logs/vpn.err

### IPSec SAD and SPD flush
test ! -f "$setkey" || {
   $setkey -F
   $setkey -FP
}

### Flush vpn routing tables and disable icmp_redirects
cat /etc/iproute2/rt_tables | grep tbvpn | sed 's/.*tbvpn_/ip route flush table tbvpn_/' | $sh - 2>/dev/null
for i in $(ls /proc/sys/net/ipv4/conf/*/send_redirects); do
  echo 0 > $i
done

echo "Firewall... Loading VPN config!"


### VPN file
rulefiles="$FW_DIR/vpn.conf"

### Cluster file
if [ -f /usr/share/fwguardian/modules/clusterfw.ctl ] && [ -f /var/tmp/gluster.group ]; then
  cldir="$FW_DIR/../cluster/glusterfs"
  clusterdir="$FW_DIR/../cluster/glusterfs/local/fs/vpn"
  if [ -f "$clusterdir/vpn.conf" ] && [ -f $clusterdir/../allow.firewall ]; then
     rulefiles="$clusterdir/vpn.conf $rulefiles"

     rsync=$(which rsync)
     gl_group=$(cat /var/tmp/gluster.group)
     [ -f /usr/share/fwguardian/cluster/glusterfs.done ] && $rsync -arlp --exclude '*~' --exclude '^.' $cldir/cluster/$gl_group/vpn/vpn.conf $clusterdir/vpn.conf 2>>$FW_DIR/../logs/cluster.base.err
  fi
  rulefiles="$FW_DIR/../cluster/alias $rulefiles"
else
  [ -f $FW_DIR/../alias ] && rulefiles="$FW_DIR/../alias $rulefiles"
fi

### Pre-configs for VPN RoadWarrior Servers
vserver=0
if [ -f /var/tmp/vpn.configureserver ]; then
   rm -f /etc/ppp/options.l2tpd 2>/dev/null
   rm -f /etc/ppp/options.pptpd 2>/dev/null
   rm -rf /usr/share/fwguardian/vpn 2>/dev/null
   mkdir -p /usr/share/fwguardian/vpn/{tmp,pptp,ipsec,ssl}

   # PPTP Server files
   cp -a -f $FW_DIR/../modules/vpn/pptp/* /usr/share/fwguardian/vpn/pptp/

   # IPSec Server files
   cp -a -f $FW_DIR/../modules/vpn/ipsec/psk.txt /usr/share/fwguardian/vpn/ipsec/
   cp -a -f $FW_DIR/../modules/vpn/ipsec/l2tpd.setk /usr/share/fwguardian/vpn/ipsec/
   cp -a -f $FW_DIR/../modules/vpn/ipsec/start.sh /usr/share/fwguardian/vpn/ipsec/

   cp -a -f $FW_DIR/../modules/vpn/ipsec/racoon.conf /usr/share/fwguardian/vpn/ipsec/
   cp -a -f $FW_DIR/../modules/vpn/ipsec/removesa.sh /usr/share/fwguardian/vpn/ipsec/
   cp -a -f $FW_DIR/../modules/vpn/ipsec/racoon.{psk,cert} /usr/share/fwguardian/vpn/tmp/
   cp -a -f $FW_DIR/../modules/vpn/ipsec/l2tpd.conf /usr/share/fwguardian/vpn/tmp/
   chmod +x /usr/share/fwguardian/vpn/ipsec/removesa.sh 2>/dev/null

   # Allow server reconfigure
   vserver=1

   # Disable default system control
   service pptpd stop 2>/dev/null >/dev/null
   service racoon stop 2>/dev/null >/dev/null
   if [ -f /etc/init.d/pptpd ]; then
      cat $FW_DIR/../modules/vpn/pptp/options.pptpd.ini > /etc/ppp/options.pptpd
      [ -f /etc/debian_version ] && update-rc.d -f pptpd remove 2>/dev/null >/dev/null || chkconfig pptpd off 2>/dev/null >/dev/null
   fi
   if [ -f /etc/init.d/racoon ]; then
      if [ -f /etc/modprobe.d/blacklist.conf ]; then
         sed -i '/[\s]*blacklist\sgeode_aes/ d' /etc/modprobe.d/blacklist.conf
         echo "blacklist geode_aes" >> /etc/modprobe.d/blacklist.conf
      fi
      if [ -f /etc/racoon/racoon.conf ] && [ ! -f /etc/racoon/racoon.conf.ori ]; then
         mv /etc/racoon/racoon.conf /etc/racoon/racoon.conf.ori
         ln -sf /usr/share/fwguardian/vpn/ipsec/racoon.conf /etc/racoon/
      fi
      [ -f /etc/debian_version ] && update-rc.d -f racoon remove 2>/dev/null >/dev/null || chkconfig racoon off 2>/dev/null >/dev/null
   fi
   if [ -f /etc/init.d/xl2tpd ]; then
      cp -f $FW_DIR/../modules/vpn/ipsec/options.l2tpd /etc/ppp/
      [ -f /etc/debian_version ] && update-rc.d -f xl2tpd remove 2>/dev/null >/dev/null || chkconfig xl2tpd off 2>/dev/null >/dev/null
   fi
fi

### Configure a VPN interface
echo "### VPN rules (`date`)" | tee -a $FW_DIR/../logs/vpn.err > $FW_DIR/../build/vpn.conf
cat $rulefiles | grep "[[:alpha:]]" | grep -v "^\(#\|;\)" | igawk --re-interval -v vserver=$vserver ' \
 @include /usr/share/fwguardian/include/alias.inc \
 @include /usr/share/fwguardian/include/rttables.id.inc \
 @include /usr/share/fwguardian/include/vpn.srvipsec.inc \
 @include /usr/share/fwguardian/include/vpn.srvpptp.inc \
 { vpndir="/usr/share/fwguardian/vpn/"; \
   @include /usr/share/fwguardian/include/vpn.defines.inc \
 } \
 END { \
   if (bind["PPTP"] && cfg["PPTP"]) configurePPTPServer(); \
   if (bind["IPSEC"] && cfg["IPSEC"]) configureIPSECServer(); \
 } ' | sed "s/ip\ route/$sedip\ route/g; s/ip\ rule/$sedip\ rule/g; s/iptables\ /$sedipt\ /g" | \
	 tee $FW_DIR/../build/vpn.conf | $sh - 2>>$FW_DIR/../logs/vpn.err

cat $FW_DIR/../build/vpn.conf | grep "\(ip rule\|iptables\) " | \
    sed "s/rule\ add/rule\ del/g; s/iptables -A /iptables -D /g; s/iptables -t mangle -I /iptables -t mangle -D /g" > $FW_DIR/../build/.vpn.undo

### Try to restart servers
[ -f /usr/share/fwguardian/vpn/pptp/pptpd.conf ] && [ -f /etc/ppp/options.pptpd ] && /usr/share/fwguardian/vpn/pptp/start.sh run >&2 2>/dev/null
if [ -f /usr/share/fwguardian/vpn/ipsec/racoon.conf ]; then
   if [ -f $FW_DIR/racoon.adminsock ]; then
      sockdir=$(strings $(which racoonctl) | grep racoon.sock)
      sockdir=$(echo $sockdir | sed "s/\//\\\\\//g")
      sed -i "/adminsock/ s/adminsock disabled/adminsock \"$sockdir\" \"root\" \"operator\" 0660/" /usr/share/fwguardian/vpn/ipsec/racoon.conf
      rm -f $FW_DIR/racoon.adminsock 2>/dev/null
   fi
   [ -f /etc/ppp/options.l2tpd ] && /usr/share/fwguardian/vpn/ipsec/start.sh run >&2 2>/dev/null
fi

### Removing the server control file
[ -f /var/tmp/vpn.configureserver ] && rm -f /var/tmp/vpn.configureserver 2>/dev/null

### Peer VPN Dead gateway detection
$FW_DIR/../modules/vpndgd.mod $FW_DIR &
