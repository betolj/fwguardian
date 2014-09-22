#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# global_ipp2p - Enable IPP2P per network interface
#

if [ "$1" == "--help" ] || [ "$1" == "" ]; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "global_ipp2p            Habilita o controle restritivo de aplicações P2P por interface (vide fw5.0/interfaces)" || \
     echo "global_ipp2p            Enable a restrictive P2P application control by interface (see fw5.0/interfaces)"
  exit
fi

