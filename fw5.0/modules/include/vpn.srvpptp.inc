function configurePPTPServer() {
   vpnpol="PPTP";
   if (mppe[vpnpol]) {
      cmd="strings $(which /usr/sbin/pppd) | grep require-mppe-128 | wc -l";
      cmd | getline reqmppe; close(cmd);
      if (reqmppe==1) print "echo \"require-mppe-128\" >> /etc/ppp/options.pptpd";
      else print "echo \"mppe required\" >> /etc/ppp/options.pptpd";
   }
   for (i in pptpdns) print "echo \"ms-dns "pptpdns[i]"\" >> /etc/ppp/options.pptpd";
   for (i in pptpwins) print "echo \"ms-wins "pptpwins[i]"\" >> /etc/ppp/options.pptpd";
   if (proxyarp[vpnpol]) print "echo \"proxyarp\" >> /etc/ppp/options.pptpd";
   print "echo \"mru 1460\" >> /etc/ppp/options.pptpd";
   print "echo \"mtu 1460\" >> /etc/ppp/options.pptpd";
   print "cat /usr/share/fwguardian/vpn/pptp/options.pptpd.end >> /etc/ppp/options.pptpd 2>/dev/null";
   if (!defaultgw[vpnpol]) print "echo \"nodefaultroute\" >> /etc/ppp/options.pptpd";
   if (winbind[vpnpol]) {
      print "echo \"auth\" >> /etc/ppp/options.pptpd";
      print "echo \"plugin winbind.so\" >> /etc/ppp/options.pptpd";
      if (winbindgrp[vpnpol] == "any") print "echo \"ntlm_auth-helper \\\"/usr/bin/ntlm_auth --helper-protocol=ntlm-server-1\\\" \" >> /etc/ppp/options.pptpd";
      else print "echo \"ntlm_auth-helper \\\"/usr/bin/ntlm_auth --helper-protocol=ntlm-server-1 --require-membership-of="winbindgrp[vpnpol]"\\\" \" >> /etc/ppp/options.pptpd";
   }
   print "touch /usr/share/fwguardian/vpn/pptp/start";

   print "echo \"listen\" "bind[vpnpol]" >> /usr/share/fwguardian/vpn/pptp/pptpd.conf";
   if (local[vpnpol]) print "echo \"localip\" "local[vpnpol]" >> /usr/share/fwguardian/vpn/pptp/pptpd.conf";
   if (pool[vpnpol])  print "echo \"remoteip\" "pool[vpnpol]" >> /usr/share/fwguardian/vpn/pptp/pptpd.conf";
}
