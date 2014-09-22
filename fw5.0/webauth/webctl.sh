#!/bin/bash
#
# Module based on HORATIO project
# http://www.cs.utexas.edu/users/mcguire/software/horatio/
#


FW_DIR="/usr/share/fwguardian"
CURFILE="/usr/share/fwguardian/webauth/control/CUR_USERS"

iptables=$(which iptables)
logger=$(which logger)
arp=$(which arp)
fping=$(which fping)
tail=/usr/bin/tail
awk=$(which gawk)

command=$1
address=$2
username=$3
cookie=$4
isrcall=0
if [ "$username" == "null" ] || [ "$username" == "__rollcall__" ]; then
  [ "$username" == "__rollcall__" ] && isrcall=1;

  username=$(grep " $address\$" $CURFILE | cut -d' ' -f2)
  [ "$username" == "" ] && username="null" 
fi

[ -n "$address" \
  -o $command == "rollcall" \
  -o $command == "restore" ] || {
	echo "Usage: webctl.sh enter|leave|query <ip address>" 1>&2
	echo "       webctl.sh rollcall" 1>&2
	echo "       webctl.sh restore" 1>&2
	exit 1
}

function log () {
	level=$1
	mesg=$2
	$logger -i -p daemon.$level -t "fwguardian(webauth):" $mesg
}

function lock () {
	file=$1
	[ -z "$file" ] && return 1;
	lock="$file.lock"
	link="$file.lock.$$"
	touch $link
	i=0
	while (( $i < 15 ))
	do
		ln -s $link $lock >/dev/null 2>&1 && break
		sleep 1
		i=$(( $i + 1 ))
	done
	if (( $i < 15 ))
	then
		return 0
	else
		rm -f $link
		return 1
	fi
}

function unlock () {
	file=$1
	[ -z "$file" ] && return 1;
	lock="$file.lock"
	link="$file.lock.$$"
	rm -f $lock $link
	return 0
}

function open () {
        user=$2
        addr=$3

        if [ -f $CURFILE ]; then
           $iptables -A FRtRules -s "$addr" -j "gpuser_$user" 2>/dev/null
           $iptables -t nat -I WebAuth -s "$addr" -j RETURN 2>/dev/null
           hw=$($arp $addr | $tail -1 | $awk '{print $3}')
           $arp -s $addr $hw >/dev/null 2>&1
        fi
}

function close () {
	user=$1
        addr=$2

        [ "$user" != "null" ] && $iptables -D FRtRules -s "$addr" -j "gpuser_$user" 2>/dev/null
        $iptables -t nat -D WebAuth -s "$addr" -j RETURN 2>/dev/null
	$arp -d $addr >/dev/null 2>&1
        rm -f $FW_DIR/webauth/control/$addr.redir 2>/dev/null
}

function add () {
        cook=$1
	user=$2
        addr=$3

        ### Add user maps to curusers
	echo "$cook $user $addr" >> $CURFILE

        ### Update rules
	open "null" $user $addr
}

function delete () {
	user=$1
        addr=$2

        ### Update rules
	close $user $addr

        ### Remove user maps from curusers
	$logger -i -p daemon.info -t "fwguardian(webauth):" "Revoke login from host $addr ($user)"
	if [ -f $CURFILE ]; then

           # Remove session control (if exist)
           sess=$(grep "\\b$user $addr\\b" /usr/share/fwguardian/webauth/control/CUR_USERS | cut -d ' ' -f1)
           [ -f /tmp/sessions/cgisess_$sess ] && rm -f /tmp/sessions/cgisess_$sess >/dev/null 2>&1
           unset sess

	   echo -e ",g/.* $user $addr\$/d\nw\nq" | ed "$CURFILE" >/dev/null 2>&1
        fi
}

if [ "$command" != "query" ]; then
   lock "$CURFILE" || {
	echo "Cannot lock $CURFILE" >&2
	exit 2
   }
fi
[ -f "$CURFILE" ] || touch "$CURFILE"

### Convert to proper address (authmap rules)
addrconv() {
IFS='
'
  addraux=""
  cookie=$2
  username=$3
  address=$4

  filectl="/usr/share/fwguardian/rtfilters.authmap.ctl"
  filemap="/usr/share/fwguardian/rtfilters.mapaddr.ctl"

  countctl=0
  if [ $1 == "add" ]; then
     if [ -f "$filectl" ]; then
        [ ! -f $filemap ] && touch $filemap
        for addraux in $(cat $filectl | grep "^$username " | cut -d" " -f2); do
           if [ "$(echo $addraux | wc -m )" -gt 7 ]; then
              mapaddr="$addraux $address $username"
              grep -q "^$mapaddr\$" "$filemap" || echo "$mapaddr" >> $filemap
           fi
           grep -q " $addraux\$" "$CURFILE" || add $cookie $username $addraux
	   ((countctl++))
        done
     fi
     if [ $countctl == 0 ]; then
        grep -q " $address\$" "$CURFILE" || add $cookie $username $address
     fi
  else
    if [ -f "$filectl" ]; then
       [ ! -f $filemap ] && touch $filemap
       [ $isrcall == 1 ] && isrcall="^$address " || isrcall=" $address "
       for line in $(cat $filemap | grep "$isrcall" | awk '{print $1" "$3}'); do
          addraux=$(echo $line | cut -d" " -f1)
          myduser=$(echo $line | cut -d" " -f2)
          grep -q " $addraux\$" "$CURFILE" && delete $myduser $addraux
	   ((countctl++))
       done
       echo -e ",g/$isrcall/d\nw\nq" | ed "$filemap" >/dev/null 2>&1
    fi
    if [ $countctl == 0 ]; then
       grep -q " $address\$" "$CURFILE" && delete $username $address 2>/dev/null
    fi
  fi
unset IFS
}

case $command in
	enter) addrconv add $cookie $username $address ;;
	leave) addrconv del "null" $username $address ;;
	query) if grep -q " $address\$" "$CURFILE"
		then echo "allowed"
		else echo "denied"
		fi
		;;
	restore) log info "restoring firewall"
		log info "breaking locks"
		rm -f "$CURFILE.lock"*
		cat "$CURFILE" | \
		while read cdata
		do
                    auxaddr=$(echo $cdata | sed 's/.* //')
                    close "null" $auxaddr
                    open $cdata
                    log info "Restore firewall rules: $cdata"
		done
		;;
	rollcall) cat "$CURFILE" | $fping -u 2>/dev/null | \
		while read cdata
		do 
                    auxaddr=$(echo $cdata | sed 's/.* //')
                    echo "Removing: $auxaddr"
                    delete $auxaddr
                    log info "$auxaddr logout by rollcall"
		done
		;;
	*) echo "Why you called with $command?" >&2 ;;
esac
unset auxaddr
unlock "$CURFILE"
exit 0
