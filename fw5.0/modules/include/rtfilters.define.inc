#!/bin/igawk
{
  if (match($1,"^((set-(policy|condition|auth)|alias)$)")) {
    if ($1 == "alias") fwalias("make", "fwroute");
    else {
      rtsec=0;
      usegp=0;
      intoch=0;
      authpol=0;
      authtype="";
      if (match($1,"^set-(policy|auth)$")) {
         disabled=0;
         disabledpol=0;
         disabledpol=fwalias("chkperm", "fwroute");
         if ($1 == "set-auth") { 
            authpol=1;
            authtype=$2;
         }
         if (!disabledpol && !authpol) {
            if (match($2, "^auth:")) {
               usegp=1;
               split($2, auxparam, ":");
               gp=auxparam[2];
               countfrt++;
               if (countfrt == 1) {
                  print "iptables -N FRtRules 2>/dev/null";
                  print "iptables -D FORWARD -j FRtRules 2>/dev/null"; 
                  print "iptables -I FORWARD -j FRtRules";
               }
               countnat++;
               if (countnat == 1) print "iptables -t nat -N RtRules 2>/dev/null";

               if (!allow_auth) {
                  allow_auth=1;
                  print "iptables -t nat -N WebAuth 2>/dev/null";
                  print "iptables -t nat -I PREROUTING -j WebAuth 2>/dev/null";
                  system("touch /usr/share/fwguardian/rtauth.ctl");
               }

               print "iptables -N AuthGP"gp" 2>/dev/null";
               print "iptables -F AuthGP"gp" 2>/dev/null";
               system("echo AuthGP_"gp" >> /usr/share/fwguardian/rtwebauth.chains");
            }
            else {
               if (match($2, "^(filter|rtsec):")) {
                  split($2, nchain, ":");
                  if (nchain[1] == "filter") {
                     intoch=1;
                     print "iptables -N filter_"nchain[2]" 2>/dev/null";
                     system("echo filter_"nchain[2]" >> /usr/share/fwguardian/rtfilters.chains");
                  }
                  else {
                     rtsec=1;
                     rtsecpol++;
                     if (rtsecpol == 1) {
                        print "iptables -t mangle -N RtSecRules 2>/dev/null";
                        print "iptables -t mangle -I RtSec -j RtSecRules 2>/dev/null";
                        system("touch /usr/share/fwguardian/rtfilters.rtsec");
                     }
                  }
               }
            }
         }
      }
      else if ($1 == "set-condition") fwalias("mkperm", "fwroute");
    }
  }
  else {
     if (!disabledpol) disabled=0;
     disabled=fwalias("chkperm", "fwroute");
  }
}
