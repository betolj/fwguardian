#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# fwhost module (host profile and MAC control)
#

if [ "$1" == "--help" ] || [ "$1" == "" ] ; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "fwhosts                 Permite redefinir perfil de acesso e controle MAC (fwhosts)" || \
     echo "fwhosts                 Redefine access profile and MAC control (fwhosts)"
  exit
fi

FW_DIR=$1
[ -f $FW_DIR/fwusu ] && mv $FW_DIR/fwusu $FW_DIR/fwhosts 2>&1 >/dev/null
[ ! -f $FW_DIR/fwhosts ] || [ ! -f /usr/share/fwguardian/modules/fwhosts.ctl ] && exit

sh=$(which bash)
iptables=$(which iptables)
sedipt=$(echo $iptables | sed "s/\//\\\\\//g")


# Set the protect line number
pcount=$(iptables -t mangle -nL PREROUTING | wc -l)
[ "$pcount" -gt 2 ] && pcount=1 || pcount=0

echo "Firewall... Loading Hosts profile!"
$iptables -t mangle -F Protect 2>/dev/null
$iptables -t mangle -nL PREROUTING --line-numbers | grep "\(\b\)Protect\(\b\)" | sort -n -r -k1 |\
  while read line; do
     echo $line | cut -d' ' -f1 > /var/tmp/fwhosts.protect
     echo $line | awk {'print "iptables -t mangle -D PREROUTING "$1;'} | $sh - 2>>$FW_DIR/logs/fwhosts.err
  done

# Restore the last protect line number
if [ -f /var/tmp/fwhosts.protect ]; then
   pcount=$(cat /var/tmp/fwhosts.protect)
   rm -f /var/tmp/fwhosts.protect 2>/dev/null

   [ $pcount > 1 ] && ((pcount--))
fi
$iptables -t mangle -X Protect 2>/dev/null

### Flush fwhosts chain
$iptables -F FwHosts 2>/dev/null
if [ -f /usr/share/fwguardian/protect.chains ]; then
  cat /usr/share/fwguardian/protect.chains | awk '{ \
    print "iptables -t mangle -F "$1; \
    print "iptables -t mangle -X "$1; \
  }' | sed "s/iptables/$sedipt/g" | $sh - 2>>$FW_DIR/logs/fwhosts.err
  rm -f /usr/share/fwguardian/protect.chains 2>/dev/null
fi 

### Verify md5 hash in include files
md5pass=$($FW_DIR/modules/chkmd5.mod $FW_DIR/modules/include/fwhosts.inc)
[ ! -f /usr/share/fwguardian/include/fwhosts.inc ] || [ "$md5pass" -eq 0 ] && \
   cp -f $FW_DIR/modules/include/fwhosts.inc /usr/share/fwguardian/include/


### Fwhosts file
rulefiles="$FW_DIR/fwhosts"

### Cluster file
if [ -f /usr/share/fwguardian/modules/clusterfw.ctl ] && [ -f /var/tmp/gluster.group ]; then
  cldir="$FW_DIR/cluster/glusterfs"
  clusterdir="$FW_DIR/cluster/glusterfs/local/fs"
  if [ -f "$clusterdir/fwhosts" ] && [ -f $clusterdir/allow.firewall ]; then 
     rulefiles="$clusterdir/fwhosts $rulefiles"

     rsync=$(which rsync)
     gl_group=$(cat /var/tmp/gluster.group)
     [ -f /usr/share/fwguardian/cluster/glusterfs.done ] && $rsync -arlp --exclude '*~' --exclude '^.' $cldir/cluster/$gl_group/fwhosts $clusterdir/fwhosts 2>>$FW_DIR/logs/cluster.base.err
  fi
  rulefiles="$FW_DIR/cluster/alias $rulefiles"
else
  [ -f $FW_DIR/alias ] && rulefiles="$FW_DIR/alias $rulefiles"
fi
[ -f $FW_DIR/conditions ] && rulefiles="$FW_DIR/conditions $rulefiles"

echo "### FWHOSTS (`date`)" | tee -a $FW_DIR/logs/fwhosts.err > $FW_DIR/build/fwhosts
cat $rulefiles | grep "[[:alpha:]]" | grep -v "^#\|^;" | igawk -v pcount=$pcount '\
  @include /usr/share/fwguardian/include/alias.inc \
  {\
     @include /usr/share/fwguardian/include/fwhosts.inc \
  }' | sed "s/iptables/$sedipt/g;" | tee -a $FW_DIR/build/fwhosts | $sh - 2>>$FW_DIR/logs/fwhosts.err

cat $FW_DIR/build/fwhosts | grep AcBanned | sed 's/-I/-D/; s/AcBanned[ \|\t]\+[0-9]\+/AcBanned/' > $FW_DIR/build/.fwhosts.undo

