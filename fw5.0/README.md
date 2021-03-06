# FWGUARDIAN 5.0 (2014)
#
# - Read the docs/ChangeLog for more details!
#
# - Suggestions?
#   betolj@gmail.com

<a href="https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=4KDWWS2B2GBGQ&lc=BR&item_name=betolj%40gmail%2ecom" target="_blank"><img src="https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif" border="0" alt="PayPal — The safer, easier way to pay online."></a>


Many firewall features will be seen with module (disabled by default):
   - use "--show-modules" to view all supported modules
   - use "--enable" or "--disable" to enable|disable a firewall module

   Example1 (enable):
     ./fwguardian --enable infilters

   Example2 (enable and restart):
     ./fwguardian --enable infilters now 

The perl webserver can be used for admin firewall changes:
   - Configure webserver:
     vim fw5.0/webauth/webauth.conf

   - Starting webserver:
     ./fwguardian --web-start

   - url for admin access:
     http://<server>:<port>/admin
     https://<server>:8443/admin


New GeoIP support
   - Now, you can set this with "src_geoip" or "dst_geoip" profile type
   - You can use geoiplookup to country lookup or http://www.infosniper.net/index.php


New SYNPROXY support (this need kernel support)
   - Enable this in fwguardian.conf with:
     syn_cookie yes
     tcp_dos_protect yes


Reserved mark (NEW):
   - Traffic shape (CBQ or HTB): class based (from 101[n...] at ...)
   - Advanced routed: from 301 at ...


Routing *prio* more flexible (RPDB - ip rule)
     <init.mark.prio> <init.link.prio> <init.rules.prio>
     **Default**:
       - initial mark and routing rules: 50 (by set-policy order)
       - initial link rules: 1031
       - lb tables: 5000

Comments into config files:
   - All strings starting with ";" or "#"


Command line options:
	fwguardian --reload-profile Fdba
        fwguardian --reload-rules
	fwguardian --reload-banned access/routes
        fwguardian --help

