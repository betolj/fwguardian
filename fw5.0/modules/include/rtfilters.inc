#!/bin/igawk
{
  if (!(match($1,"^(set-(policy|condition|auth)|alias)$")) && !disabledpol && !disabled) {
    ### Apply alias
    fwalias("apply", "fwroute");

    ### Routing and auth rules
    if (authpol) {
       if (allow_auth == 1) {
          split($3,auxparam," |,");
          if (authtype == "authmaps") {
             if ($1 == "mapuser") {
                gp=$3;
                split($2,auxparam," |,");
                for ( i in auxparam ) {
                   if (auxparam[i]) {
                      print "iptables -N gpuser_"auxparam[i]" 2>/dev/null";
                      print "iptables -A gpuser_"auxparam[i]" -j AuthGP"gp" 2>/dev/null";
                      system("echo gpuser_"auxparam[i]" >> /usr/share/fwguardian/rtwebauth.chains");
                   }
                }
             }
             else if ($1 == "mappolicy") {
                for ( i in auxparam ) if (auxparam[i]) print "iptables -A AuthGP"auxparam[i]" -j AuthGP"$2;
             }
             else if ($1 == "mapuserip") {
                for ( i in auxparam ) if (auxparam[i]) system("echo "$2" "auxparam[i]" >> /usr/share/fwguardian/rtfilters.authmap.ctl");
             }
          }
          else if (authtype == "networks") {
             for ( i in auxparam ) {
                countauth++;
                webtarget="REDIRECT --to-port "webport;
                if ( match ($0, "[ |\t]+bypass($|[ |\t])") ) webtarget="RETURN";

                if ($1 == "from") print "iptables -t nat -I WebAuth "countauth" -i "$2" -s "auxparam[i]" -p tcp --dport 80 -j "webtarget;
                else print "iptables -t nat -I WebAuth "countauth" -o "$2" -d "auxparam[i]" -p tcp --dport 80 -j "webtarget;
             }
          }
       }
    }
    else if ($1 != "gplist") {
      ### GPList was deprecated... use profile.def

      ### Find interfaces
      split($1,ifrt,"->");

      rtint=""; rtback="";
      rtintSt1=""; rtintSt2="";
      rtinback=""; rtoutback="";

      ### Physdev or direct interface (input)
      if (match(ifrt[1], "^phy:")) {
         split(ifrt[1], auxrt, "phy:");
         ifrt[1] = auxrt[2];
         if (match(ifrt[1], "^!")) {
            sub("!","", ifrt[1]);
            rtinaux="-m physdev ! --physdev-in ";
            rtinback="-m physdev ! --physdev-out ";
         }
         else {
            rtinaux="-m physdev --physdev-in ";
            rtinback="-m physdev --physdev-out ";
         }
      }
      else {
         if (match(ifrt[1], "^!")) {
            sub("!","", ifrt[1]);
            rtinaux="! -i ";
            rtinback="! -o ";
         }
         else {
            rtinaux="-i ";
            rtinback="-o ";
         }
      }

      ### Physdev or direct interface (output)
      if (match(ifrt[2], "^phy:")) {
         split(ifrt[2], auxrt, "phy:");
         ifrt[2] = auxrt[2];
         if (match(ifrt[2], "^!")) {
            sub("!","", ifrt[2]);
            rtoutaux="-m physdev ! --physdev-out ";
            rtoutback="-m physdev ! --physdev-in ";
         }
         else {
            rtoutaux="-m physdev --physdev-out ";
            rtoutback="-m physdev --physdev-in ";
         }
      }
      else {
         if (match(ifrt[2], "^!")) {
            sub("!","", ifrt[2]);
            rtoutaux="! -o ";
            rtoutback="! -i ";
         }
         else {
            rtoutaux="-o ";
            rtoutback="-i ";
         }
      }

      if ($1 != "any") {
        if (ifrt[1] && ifrt[1]!="any") {
            rtint=rtint""rtinaux""ifrt[1]" ";
            rtback=rtback""rtinback""ifrt[1]" ";
            rtintSt1=" "rtinaux""ifrt[1];
        }
        if (ifrt[2] && ifrt[2]!="any") {
            rtint=rtint""rtoutaux""ifrt[2]" ";
            rtback=rtback""rtoutback""ifrt[2]" ";
            rtintSt2=" "rtinaux""ifrt[2];
        }
        if (!ifrt[2]) ifrt[2]=ifrt[1];
      }

      OD=""; ROD=""; dorst = 0;
      dproto[1]=sproto[1]=""; dproto[2]=sproto[2]=""; rproto="";

      ### Match with dport and/or sport
      if (match($0, "[ |\t](port|dport|sport)=")) {

        ## Destination ports
        if (match($0,"[ |\t](port|dport)=")) {
           split($0,dproto,"[ |\t]port=|[ |\t]dport=");
           split(dproto[2],dproto," |\t"); split(dproto[1],dproto,"/");

           if (dproto[1] && rproto == "") rproto=dproto[1];
           if (dproto[2] && match(dproto[1], "^(tcp|udp)$")) {
             if (tcprst && dproto[1] == "tcp") dorst = 1;
             if (match(dproto[2], "^!")) {
                sub("!", "", dproto[2]);
                auxport="! --dport "dproto[2];
                auxrport="! --sport "dproto[2];
             }
             else {
                auxport="--dport "dproto[2];
                auxrport="--sport "dproto[2];
             }

             if (match(dproto[2],"([0-9a-zA-Z-])+[:]*([0-9a-zA-Z-])*,")) {
                OD=OD"-m multiport "auxport" ";
                ROD=ROD"-m multiport "auxrport" ";
             }
             else {
                OD=OD"-m "rproto" "auxport" ";
                ROD=ROD"-m "rproto" "auxrport" ";
             }
           }
        }

        ## Source ports
        if (match($0, "[ |\t]sport=")) {
           split($0,sproto,"[ |\t]sport=");
           split(sproto[2],sproto," |\t"); split(sproto[1],sproto,"/");

           if (sproto[1] && rproto == "") rproto=sproto[1];
           if (sproto[2] && match(sproto[1], "^(tcp|udp)$")) {
             if (tcprst && sproto[1] == "tcp") dorst = 1;
             if (match(sproto[2], "^!")) {
                sub("!", "", sproto[2]);
                auxport="! --sport "sproto[2];
                auxrport="! --dport "sproto[2];
             }
             else {
                auxport="--sport "sproto[2];
                auxrport="--dport "sproto[2];
             }

             if (match(sproto[2],"([0-9a-zA-Z-])+[:]*([0-9a-zA-Z-])*,")) {
                OD=OD"-m multiport "auxport" ";
                ROD=ROD"-m multiport "auxrport" ";
             }
             else {
                OD=OD"-m "rproto" "auxport" ";
                ROD=ROD"-m "rproto" "auxrport" ";
             }
           }
        }

        ### Protocol types
        if (rproto != "") {
           if (rproto == "icmp" || rproto == "ipp2p") {
              if (rproto == "icmp") {
                if (dproto[2] == "any" || dproto[2] == "") rproto = "-p icmp";
                else rproto = "-p icmp --icmp-type "dproto[2];
              }
              else {
                if (dproto[2] == "any" || dproto[2] == "") rproto = "-m ipp2p --edk --kazaa --gnu --bit --apple --winmx --soul --ares";
                else {
                  rproto = "-m ipp2p ";
                  auxparam[1]=dproto[2];
                  split(auxparam[1],auxparam,",");
                  for ( i in auxparam ) rproto=rproto" --"auxparam[i];
                }
              }
           }
           else rproto = "-p "rproto;           
           OD=rproto" "OD;
           ROD=rproto" "ROD;
        }
      }

      ### Match with source and/or destination address (Mandatory)
      iprange="";
      if ($3 != "0/0" && $3 != "any") {
         dstnet=$3;
         ip_range=0;
         if (match(dstnet, "^iprange:")) {
            ip_range=1;
            sub("iprange:","", dstnet);
            if (iprange == "") iprange="-m iprange";
         }

         if (match(dstnet, "^!")) {
            sub("!","", dstnet);
            srcnet="! -s "dstnet;
            dstnet="! -d "dstnet;
         }
         else {
            srcnet="-s "dstnet;
            dstnet="-d "dstnet;
         }

         if (ip_range) {
            sub("-s", "--src-range", srcnet);
            sub("-d", "--dst-range", dstnet);
         }
         OD=dstnet" "OD;
         ROD=srcnet" "ROD;
      }
      if ($2 != "0/0" && $2 != "any") {
         srcnet=$2;
         ip_range=0;
         if (match(srcnet, "^iprange:")) {
            ip_range=1;
            sub("iprange:","", srcnet);
            if (iprange == "") iprange="-m iprange";
         }

         if (match(srcnet, "^!")) {
            sub("!","", srcnet);
            dstnet="! -d "srcnet;
            srcnet="! -s "srcnet;
         }
         else {
            dstnet="-d "srcnet;
            srcnet="-s "srcnet;
         }

         if (ip_range) {
            sub("-s", "--src-range", srcnet);
            sub("-d", "--dst-range", dstnet);
         }
         OD=srcnet" "OD;
         ROD=dstnet" "ROD;
      }

      if (iprange == "-m iprange") {
         OD="-m iprange "OD;
         ROD="-m iprange "ROD;
      }

      ### Connection state - match with new packets
      if (match($0,"[ |\t](start|new)($|[ |\t])")) {
         if (dproto[1]=="tcp") OD=OD"--syn ";
         else OD=OD"-m conntrack --ctstate NEW "
      }
      else if (match($0,"[ |\t]nonew($|[ |\t])")) {
         if (dproto[1]=="tcp") OD=OD" ! --syn ";
         else OD=OD"-m conntrack ! --ctstate NEW ";
      }
    
      if ($4 == "SYNPROXY") fwtarget="Do_SYNPROXY";
      else {
        if ($4 == "IPS") fwtarget="fw_intIPS";
        else fwtarget=$4;
      }
      rstopt = "";

      if (rtsec == 1) {
         if ($1 == "any" || $1 == "none") print "iptables -t mangle -A RtSecRules "OD"-j "fwtarget;
         else print "iptables -t mangle -A RtSecRules "rtoutaux,ifrt[2],OD"-j "fwtarget;
      }
      else {

        ### Rule priority: insert(FRtRules) or append(RtRules)
        if (dorst && (fwtarget == "%R" || fwtarget == "REJECT")) rstopt = "--reject-with tcp-reset";
        if (match($0,"[ |\t](insert|urgent|guaranteed)($|[ |\t])")) {
          countfrt++;
          chRule=" FRtRules";
          if (countfrt == 1) {
             if (mkfrt) {
                print "iptables -N FRtRules 2>/dev/null";
                print "iptables -D FORWARD -j FRtRules 2>/dev/null";
                print "iptables -I FORWARD -j FRtRules";
                print "touch /usr/share/fwguardian/rtfilters.frtlock";
             }
             print "echo FRtRules >> /usr/share/fwguardian/rtfilters.chains";
          }
        }
        else chRule=" RtRules";
        auxRule=chRule;

        if (intoch == 1) { 
           if ($4 == "FILTER") fwtarget="filter_"nchain[2];
           else chRule=" filter_"nchain[2];
        }

        ### Making log rules
        if (match($0,"[ |\t](log-desc|log)=")) {
           split($0,logg,"[ |\t]log-desc=|[ |\t]log="); split(logg[2],logg,"\""); gsub("\\s+$", "", logg[2]);
           if ( usegp == 0 ) print "iptables -A"chRule,rtint,OD"-m conntrack --ctstate NEW -j LOG --log-level info --log-prefix \"[ "logg[2]" ]: \"";
           else print "iptables -A AuthGP"gp,rtint,OD"-m conntrack --ctstate NEW -j LOG --log-level info --log-prefix \"[ "logg[2]" ]: \"";
        }

        ### Routing rule (packet filter)
        if (usegp == 0) print "iptables -A"chRule,rtint,OD"-j "fwtarget,rstopt;
        else print "iptables -A AuthGP"gp,rtint,OD"-j "$4,rstopt; 

        if (match($0,"[ |\t]stateless($|[ |\t])")) stless=1;
        else stless=0;
        if ((stless && $4 != "FILTER") || $4 == "SYNPROXY") {
           if (stless) {
              if (usegp == 0) print "iptables -A"chRule,rtback,ROD"-j "$4;
              else print "iptables -A AuthGP"gp,rtback,ROD"-j "$4;
           }

           ### Make NoTrack rules
           if (match($0,"[ |\t]notrack($|[ |\t])") || $4 == "SYNPROXY") {
              ContTr++;
              if (ContTr == 1) {
                print "iptables -t raw -N RtRules 2>/dev/null";
                print "iptables -t raw -D PREROUTING -j RtRules 2>/dev/null"; 
                print "iptables -t raw -A PREROUTING -j RtRules";
              }

              if (stless) {
                 if (rtintSt1 != "") print "iptables -t raw -A RtRules"rtintSt1,OD"-j CT --notrack";
                 if (rtintSt2 != "") print "iptables -t raw -A RtRules"rtintSt2,ROD"-j CT --notrack";
              }
              else print "iptables -t raw -A RtRules"rtint,OD"-j CT --notrack";
           }
        }
      }

      ### NAT rules
      if (match($0,"[ |\t](masq|autosnat)($|[ |\t])") && $1 != "any" && $4 != "FILTER") {
         countnat++; 
         autosnat="";

         if (countnat==1) print "iptables -t nat -N RtRules 2>/dev/null";
         if (match($0, "[ |\t]masq($|[ |\t])")) {
            if (ifrt[2]=="any") onat="";
            else onat=rtoutaux" "ifrt[2];
            print "iptables -t nat -A RtRules "onat,OD"-j MASQUERADE";
         }
         else { 
            if ($3 == "0/0") getsrc=200; 
            else getsrc=$3 ;
            rtcmd="ip route get "getsrc" | sed \"/ src / s/.* src/src/\" | head -1 | cut -d \" \" -f 2";
            rtcmd | getline autosnat; close(rtcmd);
            if (autosnat) print "iptables -t nat -A RtRules "rtoutaux,ifrt[2],OD"-j SNAT --to "autosnat;
         }
      }
    }
  }
}

