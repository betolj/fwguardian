#!/bin/igawk
{
   if (match($1,"^((set-(policy|condition)|alias)$)")) {
      if ($1 == "alias") fwalias("make", "rtnat");
      else {
        if ($1 == "set-policy") {
           natpol="";
           disabled=0;
           disabledpol=0;
           disabledpol=fwalias("chkperm", "rtnat");
           if (!disabledpol) {
              if ($2 == "DNAT") natpol="DNAT";
              else if ($2 == "SNAT") natpol="SNAT";
              else if ($2 == "NETMAP") natpol="NETMAP";
              else disabledpol=1;
           }
        }
        else if ($1 == "set-condition") fwalias("mkperm", "rtnat");
     }
   } 
   else {
     if (!disabledpol) disabled=0;
     disabled=fwalias("chkperm", "rtnat");

     if (!disabledpol && !disabled) {
        ### Apply alias
        if (alcont > 0) fwalias("apply", "rtnat");

        ### Find interfaces
        ifin=""; ifout="";
        srcip=""; dstip="";
        srcaux=""; dstaux="";

        if ($2 != "0/0" && $2 != "any") {
           srcip=$2;
           srcaux = " -s ";
           if (match($2, "!")) {
              sub("!","", srcip);
              srcaux = " ! -s ";
           }
        }
        if ($3 != "0/0" && $3 != "any") {
           dstip=$3;
           dstaux = " -d ";
           if (match(dstip, "!")) {
              sub("!","", dstip);
              dstaux = " ! -d ";
           }
        }
        else if (match(natpol, "^(DNAT|NETMAP)$")) dstaux = " -d ";

        ### Define main ports
        pproto=""; rproto=""; auxproto="";
        if (match($0,"[ |\t](port|dport|sport)=")) {
           if (match($0, "[ |\t](port|dport)=")) {
              split($0,dproto,"[ |\t]port=|[ |\t]dport=");
              split(dproto[2],dproto," |\t"); split(dproto[1],dproto,"/");
              if (dproto[1] && rproto == "") rproto=dproto[1];
              if (dproto[2] && match(dproto[1], "^(tcp|udp)$")) {
                 if (match(dproto[2],"([0-9a-zA-Z-])+[:]*([0-9a-zA-Z-])*,")) pproto=pproto"-m multiport --dport "dproto[2]" ";
                 else pproto=pproto"-m "rproto" --dport "dproto[2]" ";
              }
           }

           if (match($0, "[ |\t]sport=")) {
              split($0,sproto,"[ |\t]sport=");
              split(sproto[2],sproto," |\t"); split(sproto[1],sproto,"/");
              if (sproto[1] && rproto == "") rproto=sproto[1];
              if (sproto[2] && match(sproto[1], "^(tcp|udp)$")) {
                 if (match(sproto[2],"([0-9a-zA-Z-])+[:]*([0-9a-zA-Z-])*,")) pproto=pproto"-m multiport --dport "sproto[2]" ";
                 else pproto=pproto"-m "rproto" --sport "sproto[2]" ";
              }
           }

           # Include protocol
           if (rproto != "") {
              pproto = " -p "rproto" "pproto;
              auxproto=pproto;
           }
           else pproto="";
        }

        if (match(natpol, "^(SNAT|DNAT|NETMAP)$")) {
           split($1,ifrt,"->");
           rtint=""; 

           ### Direct interface
           if (match(ifrt[1], "^!")) {
              sub("!","", ifrt[1]);
              rtinaux="! -i ";
           }
           else rtinaux="-i ";

           if (match(ifrt[2], "^!")) {
              sub("!","", ifrt[2]);
              rtoutaux="! -o ";
           }
           else rtoutaux="-o ";

           if ($1 != "any") {
              if (ifrt[1] && ifrt[1]!="any") {
                 ifin = rtinaux""ifrt[1];
                 rtint=rtint""rtinaux""ifrt[1]" ";
              }
              if (ifrt[2] && ifrt[2]!="any") {
                 ifout = rtoutaux""ifrt[2];
                 rtint=rtint""rtoutaux""ifrt[2]" ";
              }
              if (!ifrt[2]) ifrt[2]=ifrt[1];
              if ((natpol == "SNAT") && !ifout) ifout = rtoutaux""ifrt[2];
           }

           if (srcaux != "") srcaux=srcaux" "srcip;

           if (natpol == "DNAT") {
               natch="PrNAT ";

               # - dstredir[1] destination ip address in DNAT
               # - dstredir[2] destination port adress in DNAT
               split($4,dstredir,":");
           }
           else natch="PoNAT ";

           # Making logs
           if (match($0,"[ |\t]log-desc=")) {
              split($0,logg,"[ |\t]log-desc="); split($0,logg,"\"");
              print "iptables -t nat -A "natch,ifin,srcaux,dstaux,dstip,pproto"-j LOG --log-level info --log-prefix \"["logg[2]"]: \" ";
           }

           # NAT rules
           if (natpol == "DNAT" || natpol == "NETMAP") {
              if ($4 == "IGNORE") tnat="RETURN";
              else {
                 redir=0;
                 tnat=natpol" --to "$4;
                 if (natpol == "DNAT" && dstredir[1] == "127.0.0.1") {
                    tnat = "";
                    if (dstredir[2] || dproto[2]) {
                       redir=1;
                       if (dstredir[2]) tnat="REDIRECT --to-port "dstredir[2];
                       else tnat="REDIRECT --to-port "dproto[2];
                    }
                 }
              }
              if (tnat != "") {
                 if (dstip != "") print "iptables -t nat -A PrNAT "ifin,srcaux,dstaux,dstip,pproto"-j "tnat;
                 else print "iptables -t nat -A PrNAT "ifin,srcaux,pproto"-j "tnat;
              }
              if (natpol == "DNAT" && $4 != "IGNORE") {
                 ## DNAT for local IP address and working with multipath routes
                 ## Multpath is present when "fwr=1" (exist /usr/share/fwguardian/modules/rttables.ctl)
                 if (redir == 0) {
                    findgw=0;
                    if (fwr==1 && !match(ifrt[1], "^(none|any)$")) {
                       gmark="";
                       for (i in devgw) {
                          if (devgw[i] == ifrt[1]) {
                             if (fmark[i]) { findgw=1; gmark=fmark[i]; }
                             break;
                          }
                       }
                       if (findgw==0) {
                          natcmd="cat /usr/share/fwguardian/modules/rttables.ctl | grep \" "ifrt[1]" \" | head -1 | sed \"s/.*0x/0x/\" ";
                          natcmd | getline gmark; close(natcmd);
                          if (gmark != "") {
                             contgw++;
                             devgw[contgw]=ifrt[1];
                             fmark[contgw]=gmark; findgw=1;
                          }
                       }
                       if (findgw==1) {
                          if (contgw < 2) print "iptables -t mangle -N PrTAB 2>/dev/null";
                          print "iptables -t mangle -I PrTAB "rtint,srcaux,dstaux,dstip,pproto" -m conntrack --ctstate NEW -j CONNMARK --set-mark "gmark;
                       }
                    }

                    ## Define define target ports (exist a specified socket port?) and make mark rules if findgw equals "1".
                    if (dstredir[2]) {
                       if (match($0,"[ |\t](port|dport)=")) {
                          pproto="-p "dproto[1];
                          if (match(dstredir[2],"([0-9a-zA-Z-])+[:]*([0-9a-zA-Z-])*,")) pproto=pproto" -m multiport --dport "dstredir[2];
                          else pproto=pproto" --dport "dstredir[2];
                       }
                       else pproto="";
                       auxproto=pproto;
                       getsrc=dstredir[1];
                    }
                    else getsrc=$4;
                    if (findgw==1) print "iptables -t mangle -A CNTNat "rtint,dstaux,getsrc,auxproto" -m conntrack --ctstate DNAT -j CONNMARK --set-mark "gmark;

                    if (!match($0, "[ |\t]only-dnat($|[ |\t])")) {
                       dstaux=dstaux" "getsrc;
                       if (match($0,"[ |\t]with-masq($|[ |\t])")) print "iptables -t nat -A PoNAT "ifout,srcaux,dstaux,auxproto" -m conntrack --ctstate DNAT -j MASQUERADE";

                       ## Making FORWARD permitions
                       print "iptables -A FwNAT "rtint,srcaux,dstaux,auxproto" -j ACCEPT";
                    }
                 }
              }
           }
           else {
              if (natpol == "SNAT") {
                 if (dstaux != "") dstaux=dstaux" "dstip;
                 if ($4 == "AUTO" || $4 == "MASQ") {
                   tnat="";
                   if ($4 == "MASQ") tnat="MASQUERADE";
                   else {
                      rtcmd="ip route get "$3" | sed \"/ src / s/.* src/src/\" | head -1 | cut -d \" \" -f 2";
                      rtcmd | getline tnat; close(rtcmd);
                      if (!tnat || tnat == "") tnat="MASQUERADE";
                      else tnat="SNAT --to "tnat;
                   }
                   print "iptables -t nat -A PoNAT "ifout,srcaux,dstaux,pproto"-j "tnat;
                 }
                 else {
                   if ($4 == "IGNORE") print "iptables -t nat -A PoNAT "ifout,srcaux,dstaux,pproto"-j RETURN ";
                   else print "iptables -t nat -A PoNAT "ifout,srcaux,dstaux,pproto"-j SNAT --to "$4;
                 }
              }
           }
        }
     }
   }
}
