#!/bin/bash
#
# You can use cron service to do this:
# ln -sf /etc/squid/scripts/flushcache.sh /etc/cron.monthly/flushcache

squid=$(which squid)

# Stop squid and move spool dir
killall -9 qlproxyd squid 2>/dev/null
service squid3 stop 2>/dev/null >/dev/null
mv /var/spool/squid /var/spool/squidold

# Rebuild spool dir
mkdir /var/spool/squid
chown -R proxy.proxy /var/spool/squid
$squid -z

# Services restart
sleep 2
/etc/init.d/qlproxy restart
service squid3 restart
rm -rf /var/spool/squidold &
