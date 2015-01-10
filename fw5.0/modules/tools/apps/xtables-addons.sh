#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# xtables-addons/geoip Install
#

# - Install xtables-addons
sudo apt-get -y install unzip geoip-bin
sudo apt-get -y install xtables-addons-common


# - For debian support
#sudo apt-get -y install module-assistant
#sudo module-assistant auto-install xtables-addons

# - Install GeoIP libs and database
sudo aptitude install libtext-csv-xs-perl
sudo /usr/lib/xtables-addons/xt_geoip_dl
sudo mkdir /usr/share/xt_geoip
sudo /usr/lib/xtables-addons/xt_geoip_build -D /usr/share/xt_geoip *.csv
