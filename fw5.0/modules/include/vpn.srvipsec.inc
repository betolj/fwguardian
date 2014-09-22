function configureIPSECServer() {
   vpnpol="IPSEC";
   print "echo \"listen {\n\tisakmp "bind[vpnpol]" [500];\n\tisakmp_natt "bind[vpnpol]" [4500];\n\tadminsock disabled;\n}\n\" >> "vpndir"/ipsec/racoon.conf ";
   if (l2tpena) print "cat "vpndir"/ipsec/l2tpd.setk | sed \"s/<bind>/"bind[vpnpol]"/g\" | setkey -c";

   if (ipseckey == "psk") print "cat "vpndir"/tmp/racoon.psk >> "vpndir"/ipsec/racoon.conf";
   else print "cat "vpndir"/tmp/racoon.cert >> "vpndir"/ipsec/racoon.conf";
   //# for (i in ipsecpsk) print "cat "vpndir"/tmp/racoon.psk | sed \"s/<remote>/"ipsecpsk[i]"/g\" >> "vpndir"/ipsec/racoon.conf";

   if (mppe[vpnpol]) {
      cmd="strings $(which /usr/sbin/pppd) | grep require-mppe-128 | wc -l";
      cmd | getline reqmppe; close(cmd);
      if (reqmppe==1) print "echo \"require-mppe-128\" >> /etc/ppp/options.l2tpd";
      else print "echo \"mppe required\" >> /etc/ppp/options.l2tpd";
   }
   for (i in ipsecdns) print "echo \"ms-dns "ipsecdns[i]"\" >> /etc/ppp/options.l2tpd";
   for (i in ipsecwins) print "echo \"ms-wins "ipsecwins[i]"\" >> /etc/ppp/options.l2tpd";
   if (proxyarp[vpnpol]) print "echo \"proxyarp\" >> /etc/ppp/options.l2tpd";
   print "echo \"mru 1460\" >> /etc/ppp/options.l2tpd";
   print "echo \"mtu 1460\" >> /etc/ppp/options.l2tpd";
   if (!defaultgw[vpnpol]) print "echo \"nodefaultroute\" >> /etc/ppp/options.l2tpd";
   if (winbind[vpnpol]) {
      print "echo \"auth\" >> /etc/ppp/options.l2tpd";
      print "echo \"plugin winbind.so\" >> /etc/ppp/options.l2tpd";
      if (winbindgrp[vpnpol] == "any") print "echo \"ntlm_auth-helper \\\"/usr/bin/ntlm_auth --helper-protocol=ntlm-server-1\\\" \" >> /etc/ppp/options.l2tpd";
      else print "echo \"ntlm_auth-helper \\\"/usr/bin/ntlm_auth --helper-protocol=ntlm-server-1 --require-membership-of="winbindgrp[vpnpol]"\\\" \" >> /etc/ppp/options.l2tpd";
   }
   print "touch /usr/share/fwguardian/vpn/ipsec/start";

   if (l2tpena) {
      print "echo \"[global]\"> "vpndir"/ipsec/l2tpd.conf";
      print "echo \"force userspace = yes\" >> "vpndir"/ipsec/l2tpd.conf";
      //# print "echo \"ipsec saref = yes\" >> "vpndir"/ipsec/l2tpd.conf";
      print "echo \"listen-addr = "bind[vpnpol]"\" >> "vpndir"/ipsec/l2tpd.conf";
      if (local[vpnpol]) print "echo \"port = 1701\" >> "vpndir"/ipsec/l2tpd.conf";
      print "cat "vpndir"/tmp/l2tpd.conf  >> "vpndir"/ipsec/l2tpd.conf";
      if (local[vpnpol]) print "echo \"local ip\" = "local[vpnpol]" >> "vpndir"/ipsec/l2tpd.conf";
      if (pool[vpnpol])  print "echo \"ip range\" = "pool[vpnpol]"  >> "vpndir"/ipsec/l2tpd.conf";
   }
}
