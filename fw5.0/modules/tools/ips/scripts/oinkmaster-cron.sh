#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# IPS rules update
# - Copy this file to /etc/cron.daily/
# 

/usr/sbin/oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules/
