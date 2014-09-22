#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# msnctl module (MSN account control - will be deprecated)
#

[ "$1" == "" ] && exit

if [ "$1" == "--help" ] || [ "$1" == "" ] ; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "msnctl                  Contas autorizadas para login no MSN (fwmsn)" || \
     echo "msnctl                  Authorized accounts for MSN login (fwmsn)"
  exit
fi

FW_DIR=$1
[ ! -f $FW_DIR/fwmsn ] && exit

sh=$(which bash)
iptables=$(which iptables)

### Test modules
[ $($iptables -m recent 2>&1 | grep -i "cannot open" | wc -l) -eq 1 ] || \
[ $($iptables -m string 2>&1 | grep -i "cannot open" | wc -l) -eq 1 ] && exit


### LOG MSN Drops
$iptables -t mangle -N MSNDrop 2>/dev/null
$iptables -t mangle -F MSNDrop 2>/dev/null
$iptables -t mangle -A MSNDrop -m hashlimit --hashlimit-mode srcip --hashlimit 1/s --hashlimit-burst 1 --hashlimit-name msndrops \
    -j LOG --log-level info --log-prefix "MSN DROPs: "
$iptables -t mangle -A MSNDrop -j DROP

### MSN check phases (Request + Login)
$iptables -t mangle -N MSN-Login 2>/dev/null
$iptables -t mangle -F MSN-Login 2>/dev/null
#$iptables -t mangle -A MSN-Login -m recent --update --name MSNPHASE1
$iptables -t mangle -A MSN-Login -p tcp --dport 1863 --syn -m recent --set --name MSNPHASE1 \
    -j LOG --log-level info --log-prefix "MSN request: "

$iptables -t mangle -N MSN-PHASE2 2>/dev/null
$iptables -t mangle -F MSN-PHASE2 2>/dev/null
$iptables -t mangle -A MSN-PHASE2 -m recent --name MSNPHASE1 --remove
$iptables -t mangle -A MSN-PHASE2 -m recent --name MSNPHASE2 --set
$iptables -t mangle -A MSN-PHASE2 -j LOG --log-prefix "MSN login: "

$iptables -t mangle -N MSN-PHASE3 2>/dev/null
$iptables -t mangle -F MSN-PHASE3 2>/dev/null
$iptables -t mangle -A MSN-PHASE3 -m recent --name MSNPHASE2 --remove
$iptables -t mangle -A MSN-PHASE3 -j ACCEPT

### Remove last RtSec rules
$iptables -t mangle -nL RtSec --line-numbers | grep '\(\b\)MSN-Login\(\b\)' | \
     sort -k1 -n -r  | awk '{print "iptables -t mangle -D RtSec "$1}' | $sh - >/dev/null 2>/dev/null

### Authorized users x IP
acount=0
icount=0
pcount=0
msnports[$pcount]="--dport 1863"
((pcount++));

echo "Firewall... Loading MSN login control!"
grep "[[:alpha:]]" $FW_DIR/fwmsn | grep -v "^\(#\|;\)\|\(\(\s\)disabled\(\s\)*\)" | \
while read line;
do
  msncmd=$(echo $line | awk '{print $1}')
  msndstip=$(echo $line | awk '{print $2}')
  msnemail=$(echo $line | awk '{print $3}')
  force=$(echo $line | grep '\(\s\)force\(\s\)*' | wc -l)

  case "$msncmd" in
     check.addr|check.address)
        ((acount++))
        $iptables -t mangle -A MSN-Login -p tcp -d $msndstip --syn -m recent --set --name MSNPHASE1
        $iptables -t mangle -I RtSec $acount -d $msndstip -j MSN-Login
     ;;

     check.proxy)
        declare -a PROXYARR
        PROXYARR=(`echo ${msndstip//:/ }`)
        msnproxy[$pcount]="${PROXYARR[0]}"
        msnports[$pcount]="${PROXYARR[1]}"
        [ ${msnports[$pcount]} ] && msnports[$pcount]="--dport ${msnports[$pcount]}"
        ((pcount++))
     ;;

     allow.login)
        ### Check if exist IP control
        ipfind=0
        for ((i=0; i<=$icount; i++));
        do
          if [ "${MsnHost[$i]}" == "$msndstip" ]; then
             ipfind=1
          fi
        done

       ### Make rules by IP
       if [ "$ipfind" -eq 0 ]; then
          ((icount++))
          MsnHost[$icount]=$msndstip
          $iptables -t mangle -A MSN-Login -p tcp -s $msndstip -m recent --rcheck --seconds 5 --name MSNPHASE2 -j MSN-PHASE3

          for ((i=0; i<$pcount; i++)); do
             j=i
             ((j++))
             [ "${msnports[$i]}" == "" ] && msnports[$i]="-m multiport --dport 80,3128,8080,1863"

             if [ "${msnproxy[$i]}" != "" ]; then
                [ $icount -lt 2 ] && \
                  $iptables -t mangle -I RtSec $j -p tcp ${msnports[$i]} -d ${msnproxy[$i]} -j MSN-Login
             else
                [ $acount -lt 1 ] || [ $force -eq 1 ] && $iptables -t mangle -I RtSec $j -p tcp --dport 1863 -s $msndstip -j MSN-Login
             fi
          done
        fi

        ### Check users account
        $iptables -t mangle -A MSN-Login -p tcp -s $msndstip -m string --string "SSO I $msnemail" --algo kmp \
           -m recent --rcheck --name MSNPHASE1 -j MSN-PHASE2
     ;;
  esac
done

### DROP others
$iptables -t mangle -A MSN-Login -p tcp -m string --string " SSO I " --algo kmp \
	-m recent --rcheck --name MSNPHASE1 -j MSNDrop

$iptables -t mangle -A MSN-Login -p tcp -m string --string " TWN I " --algo kmp \
        -m recent --rcheck --name MSNPHASE1 -j MSNDrop

