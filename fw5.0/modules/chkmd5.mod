#!/bin/bash
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Calc and check md5 hash of firewall modules (include updates)
#

fname=$(basename $1)
md5sum=$(which md5sum)
md5now="/usr/share/fwguardian/include/$fname"

md5inc=$(md5sum $1 | cut -d" " -f1)
md5now=$(md5sum $md5now 2>/dev/null | cut -d" " -f1)

[ "$md5inc" == "$md5now" ] && echo 1 || echo 0
