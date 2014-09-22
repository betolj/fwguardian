#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# shellinabox - bandwidth tools
#

if [ "$1" == "--help" ] || [ "$1" == "" ]; then
  [ -f "$(readlink -f $(dirname $0))/../webauth/html/admin/pt_BR.weblang" ] && \
     echo "bwshell                 Habilita o serviço shellinabox para visualizar a banda consumida (shell)" || \
     echo "bwshell                 Enable shellinabox service to view the network bandwidth (shell)"
  exit
fi

