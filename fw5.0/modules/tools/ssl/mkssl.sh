#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Webauth (HTTPS)
# - Make SSL cert and key
#

FW_DIR=$1
SSLDIR="/usr/share/fwguardian/webauth/control/ssl/"
openssl=$(which openssl)

test -f "$openssl" || {
  clear
  echo -e '\n\E[48;31m'"\033[1m ERROR: I cant make certifies!!!\033[0m"
  echo -e "\n\tI can't find the openssl binary!"
  exit
}

[ ! -d $SSLDIR ] && mkdir -p $SSLDIR

mypass=$(for i in 1 2 3; do echo $RANDOM; done)
mypass=$(echo $mypass | tr -d ' ')
cat $FW_DIR/openssl.cnf | sed "s/<fw_mypass>/$mypass/g" > $SSLDIR/openssl.cnf

$openssl req -new -x509 -days 99999 -config $SSLDIR/openssl.cnf -batch \
	-keyout $SSLDIR/webauth.pem \
	-out    $SSLDIR/webauth.cert \
	-subj '/CN=FwGuardian/CN=Webauth' 2>&1 >/dev/null

echo "Firewall... THE PASSWORD FOR HTTPS QUESTION IS: $mypass"
$openssl rsa -passin pass:$mypass -in $SSLDIR/webauth.pem -out $SSLDIR/webauth.key

