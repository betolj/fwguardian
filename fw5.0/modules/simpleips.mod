#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# simpleIPS module - Make dynamic ip blacklist for web attack
#
# Based in:
# http://spamcleaner.org/en/misc/w00tw00t.html
#

if [ "$1" == "--help" ] || [ "$1" == "" ]; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "simpleips               Ativa lista negra para tentativas de intrusão" || \
     echo "simpleips               Enable intrusion attempts blacklist"
  exit
fi

FW_DIR=$1
[ ! -f /usr/share/fwguardian/modules/simpleips.ctl ] || [ ! -f $FW_DIR/securityaddon/config ] && exit

sh=$(which bash)
iptables=$(which iptables)


# Try to load TARPIT xt extension
modprobe xt_TARPIT 2>/dev/null

# Make 6h blacklist
$iptables -N DropIPS 2>/dev/null
$iptables -A DropIPS -m limit --limit 1/s -j LOG --log-level info --log-prefix " DROP profile SimpleIPS "
$iptables -A DropIPS -m recent --name checkips --remove
$iptables -A DropIPS -m recent --set --name dropips -p tcp -j REJECT --reject-with tcp-reset

# Slowloris
$iptables -N SlowLoris 2>/dev/null
$iptables -A SlowLoris -m recent --name slowloris --remove -m string --algo kmp --string 'X-a: b' --to 60 -j DropIPS

# Check IPS - PSH,ACK packets after tcp handshake
$iptables -N CheckIPS 2>/dev/null
$iptables -N CheckStrIPS 2>/dev/null
[ $(lsmod | grep xt_TARPIT | wc -l) -gt 0 ] && $iptables -A CheckIPS -p tcp -m recent --name dropips --update --seconds 21600 --reap -j TARPIT
$iptables -A CheckIPS -m recent --name dropips --update --seconds 21600 --reap -j DROP
$iptables -A CheckIPS -m recent --name checkips -p tcp --tcp-flags ALL SYN --set -j RETURN
$iptables -A CheckIPS -m recent --name checkips -p tcp --tcp-flags PSH,SYN,ACK ACK --update -j RETURN
$iptables -A CheckIPS -m recent --name checkips -p tcp --tcp-flags PSH,ACK PSH,ACK --update -m string --to 700 --algo bm --string "GET " -j CheckStrIPS
$iptables -A CheckIPS -m recent --name checkips -p tcp --tcp-flags PSH,ACK PSH,ACK --update -m string --to 700 --algo bm --string "POST " -j CheckStrIPS
$iptables -A CheckIPS -m recent --name slowloris --update --hitcount 4 -p tcp --tcp-flags PSH,ACK PSH,ACK -j SlowLoris
$iptables -A CheckIPS -m recent --name checkips -p tcp --tcp-flags PSH,ACK PSH,ACK --remove -j RETURN

# Detection String
$iptables -A CheckStrIPS -m string --algo bm --to 62 --string 'GET /w00tw00t.at.' -j DropIPS
$iptables -A CheckStrIPS -m string --algo bm --to 49 --string 'POST' -m string --string 'netsparker@example.com' --algo kmp -j DropIPS
$iptables -A CheckStrIPS -m string --algo kmp --string 'select' -m string --algo kmp --string 'substring' -j DropIPS
$iptables -A CheckStrIPS -m string --algo kmp --string 'select' -m string --algo kmp --string '+from+' -j DropIPS
$iptables -A CheckStrIPS -m string --algo kmp --string 'update users set name %3D' -j DropIPS
$iptables -A CheckStrIPS -m string --algo kmp --string 'update' -m string --algo kmp --string '+set+' -j DropIPS
$iptables -A CheckStrIPS -m string --algo bm --to 49 --string "POST " -j RETURN
$iptables -A CheckStrIPS -m recent --name slowloris --set
cat $FW_DIR/securityaddon/greylist $FW_DIR/securityaddon/config | gawk -v ipt=$iptables '{ \
   if ($1 == "user-agent") { \
      if (match($0, "nospace")) print ipt" -A CheckStrIPS -m string --algo kmp --to 700 --string \"User-Agent\" -m string --algo kmp --to 740 --string \""$2"\" -j DropIPS"; \
      else print ipt" -A CheckStrIPS -m string --algo kmp --to 700 --string \"User-Agent\" -m string --algo kmp --to 740 --string \" "$2"\" -j DropIPS"; \
   } \
   else if ($1 == "check-ports" && $3 == "simpleips") { \
      print ipt" -A INPUT -m multiport -p tcp --dport "$2" -j CheckIPS"; \
      print ipt" -A OUTPUT -m multiport -p tcp --sport "$2" --tcp-flags PSH,SYN,ACK SYN,ACK -m recent --name checkips --update"; \
      print ipt" -A FORWARD -m multiport -p tcp --dport "$2" -j CheckIPS"; \
      print ipt" -A FORWARD -m multiport -p tcp --sport "$2" --tcp-flags PSH,SYN,ACK SYN,ACK -m recent --name checkips --update"; \
   } \
   else if ($1 == "src-ip" || $1 == "dst-ip") { \
      if ($3 == "simpleips" || !$3) { \
        countips++; \
        if ($1 == "src-ip") ipaddr=" -s "$2; \
        else ipaddr=" -d "$2; \
        print ipt" -I CheckIPS "countips,ipaddr" -j RETURN"; \
      } \
   } \
}' | $sh - 2>>$FW_DIR/logs/simpleips.err 

