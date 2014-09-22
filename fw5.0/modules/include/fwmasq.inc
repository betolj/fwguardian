#!/bin/igawk
{
   if (match($1, "^(alias|set-condition)$")) {
      if ($1 == "alias") fwalias("make", "fwmasq");
      else fwalias("mkperm", "fwmasq");
   }
   else {
     ### Check conditions for fwmasq rules
     disabled = 0;
     fwalias("chkperm", "fwmasq");

     ### Disable inversion rules
     if (match($1, "!") || match($2, "^!")) disabled = 1;

     if (!disabled) {
       if (alcont) fwalias("apply", "fwmasq");

       print "echo Firewall... Loading Internet Sharing: "$2"!";
       split($1,ifmasq,"->");
       ifin=ifmasq[1]; ifout=ifmasq[2];
       if ($2 == "any") $2 = "0/0";

       # Make default profile rules
       fwdefpro=defpro;
       if (match($0,"defprof=")) {
          split($0,dprof,"defprof="); split(dprof[2], dprof, "[ |\t]+");
          fwdefpro=dprof[1];
       }
       if (!fwdefpro) fwdefpro="ACCEPT";
       print "echo iptables -A FORWARD -i "ifin" -o "ifout" -s "$2" -j "fwdefpro" >> /usr/share/fwguardian/fwmasq.rules";

       # Make NAT rules
       if (!match($0,"[ |\t](nomasq|autosnat)($|[ |\t])")) print "iptables -t nat -A POSTROUTING -o "ifout" -s "$2" -j MASQUERADE";
       else {
          if (match($0,"[ |\t]autosnat($|[ |\t])") && ($2 != "0/0")) {
             autosnat="";
             rtcmd="ip route get "$2" dev "ifout" | sed \"/ src / s/.* src/src/\" | head -1 | cut -d \" \" -f 2";
             rtcmd | getline autosnat; close(rtcmd);
             if (autosnat) print "iptables -t nat -A POSTROUTING -o "ifout" -s "$2" -j SNAT --to "autosnat" 2>/dev/null";
          }
       }

       # Deny HTTP requests
       if (match($0,"[ |\t]denyhttp($|[ |\t])") && !match ($0,"[ |\t]redirect($|[ |\t])")) print "iptables -A FORWARD -i "ifin" -o "ifout" -s "$2" -p tcp --dport 80 -j DROP";

       # Configure p3scan rules if defined p3scan option
       if (match($0,"[ |\t]p3scan=")) {
          contp++; 
          if (contp == 1) print "iptables -t nat -N vpop3 2>/dev/null";
          split($0,p3port,"[ |\t]p3scan="); split(p3port[2],p3port," |\t");

          print "iptables -t nat -A PREROUTING -i "ifin" -p tcp --dport 110 -j vpop3";
          print "echo \"iptables -t nat -A vpop3 -i "ifin" -s "$2" -p tcp -j REDIRECT --to-port "p3port[1]"\" >> /usr/share/fwguardian/vpop3.natrules";
          print "iptables -A INPUT -i "ifin" -s "$2" -p tcp --dport "p3port[1]" -j ACCEPT";
       }

       # Limiter profiles
       if (match($0,"[ |\t]limitprof=")) {
          split($0,limit,"[ |\t]limitprof=");
          if (match($0,"limitprof=[a-zA-Z0-9]+(,)")) { 
             split(limit[2],limit," |\t"); 
             split(limit[1],limit,",");
          }
          else {
             split(limit[2],limitaux," |\t");
             delete limit;
             limit[1]=limitaux[1];
          }
          for (i in limit) print "iptables -A FORWARD -i "ifin" -o "ifout" -s "$2" -j "limit[i]" 2>/dev/null";
       }

       # Configure HTTP proxy rules if defined proxyport option
       if (match($0,"[ |\t]proxyport=")) {
          split ($0,proxy,"[ |\t]proxyport="); split (proxy[2],proxy," |\t");
          print "iptables -A INPUT -i "ifin" -s "$2" -p tcp --dport "proxy[1]" -j ACCEPT";

          if (match($0,"[ |\t]redirect($|[ |\t])")) {
             print "iptables -t nat -N rsquid 2>/dev/null";
             print "iptables -t nat -A PREROUTING -i "ifin" -s "$2" -p tcp --dport 80 -j rsquid";
             print "echo \"iptables -t nat -A rsquid -i "ifin" -s "$2" -p tcp -j REDIRECT --to-port "proxy[1]"\" >> /usr/share/fwguardian/rsquid.natrules";
          }
       }
     }
   }
}
