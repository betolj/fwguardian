#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# global_ips - Enable suricata IPS per network interface
#

if [ "$1" == "--help" ] || [ "$1" == "" ]; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "global_ips              Habilita a inspeção do IPS Suricata por interface de rede (vide fw5.0/interfaces)" || \
     echo "global_ips              Enable Suricata IPS inspection per network interface (see fw5.0/interfaces)"
  exit
fi

