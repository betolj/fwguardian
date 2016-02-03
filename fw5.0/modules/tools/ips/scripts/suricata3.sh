#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Suricata 2.0 Install
#

FW_DIR=$(readlink -f "$(dirname $0)"/)

sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get -y update
sudo apt-get -y install suricata
sudo apt-get -y install oinkmaster
sudo apt-get -y install conntrack

sudo cp -f $FW_DIR/oinkmaster.conf /etc/
mkdir /var/log/suricata
