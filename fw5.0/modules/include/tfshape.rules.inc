#!/bin/igawk
{
  if (!match($1,"^[ |\t]*set-") && classifier != "" && !disabledpol) {

     ### Check condition by QoS rules
     disabled=0;
     disabled=fwalias("chkperm", "tfshape");

     if (!disabled) {
        ### Apply alias
        if (alcont > 0) fwalias("apply", "tfshape");

        ## Select a default PREROUTING, FORWARD or POSTROUTING chain
        qoschain="FORWARD_QoS";
        if (classifier == "filter") {
           if ($4 == "LB") {
              qoschain="POSTROUTING_QoS";
              if (!bwnf_existflow[bwnf_flow[name_qos]]) print "iptables -t mangle -N "qoschain;
           }
        }
        else if (bwnf_flow[name_qos]) qoschain = bwnf_flow[name_qos]"_QoS";
        auxchain=qoschain;
        qostarget="";
        setclass="";

        ## Identify the rule type (netfilter or tc)
        allownf=1;
        if (classifier == "tc-rule" || (classifier == "filter" && match($4, "^(MIRROR|INGRESS|(TC|IN)-IGNORE)$"))) {
           allownf=0;
           inburst="";
           if (classifier == "filter" && $4 == "INGRESS") {
              qostarget="drop";
              if (match($0,"[ |\t]burst=")) {
                 split($0,auxparam,"[ |\t]burst=");
                 split(auxparam[2],auxparam," |\t");
                 inburst=auxparam[1];
              }
              else inburst="15k";
           }
        }

        ## Target to "bypass" rules
        if (match($4, "^(IGNORE|(TC|IN)-IGNORE)$")) {
           setclass="%ignore";
           if (allownf == 0) qostarget="reclassify";
           else qostarget="-j RETURN";
        }

        if (classifier != "filter") {
           ## Make a new QoS chain (nf chain) 
           if ((classifier == "classify-rule" || classifier == "mark-rule") && ($4 == "FILTER" || nffilter != "")) {
              if ($4 == "FILTER") {
                 qoschain="QoSFilter_"name_qos;
                 if (countchain[qoschain]++ < 1) {
                    print "iptables -t mangle -N "qoschain" 2>/dev/null";
                    print "echo "qoschain" >> /usr/share/fwguardian/tfstart.chains";
                 }

                 nffilter=qoschain;
                 qoschain=auxchain;
                 qostarget="-j "nffilter;
              }
              else qoschain=nffilter;
              if ($4 == "IGNORE") setclass="%filter";
              else if ($4 != "FILTER") qostarget="-j "qoschain;
           }

           ## Select the tc class
           if (classid[name_qos] && $4 != "IGNORE" && $4 != "FILTER") {
              ifout = bwif[name_qos];
              if (setclass != "%ignore") {
                 if (bwmark[name_qos]) shmark = bwmark[name_qos];
                 if (classid[name_qos]) setclass = classid[name_qos];
              }
           }
        }
        else setclass="";

        if (match(classifier, "^((mark|classify)-rule|filter)$") && allownf == 1) {
           rproto="";
           ifin=ifout="";

           OD="";
           dproto[1]=sproto[1]="";
           dproto[2]=sproto[2]="";

           ### Netfilter dport and/or sport match
           if (match($0, "[ |\t](port|dport|sport)=")) {

              ### Destination ports
              if (match($0,"[ |\t](port|dport)=")) {
                 split($0,dproto,"[ |\t]port=|[ |\t]dport=");
                 split(dproto[2],dproto," |\t"); split(dproto[1],dproto,"/");

                 if (dproto[1] && rproto == "") rproto=dproto[1];
                 if (dproto[2] && match(dproto[1], "^(tcp|udp)$")) {
                    if (match(dproto[2], "^!")) { 
                       sub("!", "", dproto[2]);
                       auxport="! --dport "dproto[2];
                    }
                    else auxport="--dport "dproto[2];
                    if (match(dproto[2],"([0-9a-zA-Z-])+[:]*([0-9a-zA-Z-])*,")) OD=OD" -m multiport "auxport;
                    else OD=OD" -m "rproto" "auxport;
                 }
              }

              ### Source ports
              if (match($0, "[ |\t]sport=")) {
                 split($0,sproto,"[ |\t]sport=");
                 split(sproto[2],sproto," |\t"); split(sproto[1],sproto,"/");

                 if (sproto[1] && rproto == "") rproto=sproto[1];
                 if (sproto[2] && match(sproto[1], "^(tcp|udp)$")) {
                    if (match(sproto[2], "^!")) {
                       sub("!", "", sproto[2]);
                       auxport="! --sport "sproto[2];
                    }
                    else auxport="--sport "sproto[2];
                    if (match(sproto[2],"([0-9a-zA-Z-])+[:]*([0-9a-zA-Z-])*,")) OD=OD" -m multiport "auxport;
                    else OD=OD" -m "rproto" "auxport;
                 }
              }

              ### Protocol types
              if (rproto != "") {
                 if (rproto == "icmp" || rproto == "ipp2p") {
                   if (rproto == "icmp") {
                     if (dproto[2] == "any" || dproto[2] == "") rproto = " -p icmp";
                     else rproto = " -p icmp --icmp-type "dproto[2];
                   }
                   else {
                     if (dproto[2] == "any" || dproto[2] == "") rproto = " -m ipp2p --edk --kazaa --gnu --bit --apple --winmx --soul --ares";
                     else {
                       rproto = " -m ipp2p ";
                       auxparam[1]=dproto[2];
                       split(auxparam[1],auxparam,",");
                       for ( i in auxparam ) rproto=rproto" --"auxparam[i];
                     }
                   }
                 }
                 else rproto = " -p "rproto;
                 OD=rproto" "OD;
              }
           }

           iprange="";
           if ($2 != "0/0" && $2 != "any") {
              ip_range=0;
              srcnet=$2;
              if (match(srcnet, "^iprange:")) {
                 ip_range=1;
                 sub("iprange:","", srcnet);
                 if (iprange == "") iprange="-m iprange";
              }
              srcnet="-s "srcnet;
              if (ip_range) sub("-s", "--src-range", srcnet);
              OD=OD" "srcnet;
           }
           if ($3 != "0/0" && $3 != "any") {
              ip_range=0;
              dstnet=$3;
              if (match(dstnet, "^iprange:")) {
                 ip_range=1;
                 sub("iprange:","", dstnet);
                 if (iprange == "") iprange="-m iprange";
              }
              dstnet="-d "dstnet;
              if (ip_range) sub("-d", "--dst-range", dstnet);
              OD=OD" "dstnet;
           }
           if (iprange == "-m iprange") OD="-m iprange "OD;

           ### Netfilter extensions
           # connbytes=dir/bytes_interval
           # connlimit=max/mask
           if (match($0,"[ |\t](connbytes|connpkts|connlimit|length|geoip|ndpi)=")) {
              if (match($0,"[ |\t]connbytes=")) {
                 split($0,auxparam,"[ |\t]connbytes=");
                 split(auxparam[2],auxparam," |\t"); split(auxparam[1],auxparam,"/");
                 if (!auxparam[2]) auxparam[2]="both";
                 if (!match(auxparam[1],"[0-9]+:([0-9]|$)")) auxparam[1]=auxparam[1]":";
                 if (auxparam[1]) OD=OD" -m connbytes --connbytes "auxparam[1]" --connbytes-dir "auxparam[2]" --connbytes-mode bytes ";
              }
              else {
                 if (match($0,"[ |\t]connpkts=")) {
                    split($0,auxparam,"[ |\t]connpkts=");
                    split(auxparam[2],auxparam," |\t"); split(auxparam[1],auxparam,"/");
                    if (!auxparam[2]) auxparam[2]="both";
                    if (!match(auxparam[1],"[0-9]+:([0-9]|$)")) auxparam[1]=auxparam[1]":";
                    if (auxparam[1]) OD=OD" -m connbytes --connbytes "auxparam[1]" --connbytes-dir "auxparam[2]" --connbytes-mode packets ";
                 }
              }
              if (match($0,"[ |\t]connlimit=")) {
                 split($0,auxparam,"[ |\t]connlimit=");
                 split(auxparam[2],auxparam," |\t"); split(auxparam[1],auxparam,"/");
                 if (!auxparam[2]) auxparam[2]=32;
                 if (auxparam[1]) OD=OD" -m connlimit --connlimit-above "auxparam[1]" --connlimit-mask "auxparam[2]" ";
              }
              if (match($0,"[ |\t]geoip=")) {
                 split($0,auxparam,"[ |\t]geoip=");
                 split(auxparam[2],auxparam," |\t");
                 if (auxparam[1]) {
                    if (classifier != "filter") OD=OD" -m geoip --dst-cc "auxparam[1]" ";
                    else OD=OD" -m geoip --src-cc "auxparam[1]" ";
                 }
              }
              if (match($0,"[ |\t]ndpi=")) {
                 split($0,auxparam,"[ |\t]ndpi=");
                 split(auxparam[2],auxparam," |\t");
                 if (match(auxparam[1], "^(tftp|ftp|pptp|sip|h323|irc)$")) OD=OD" -m helper --helper "auxparam[1]" ";
                 else {
                    OD=OD" -m ndpi ";
                    split(auxparam[1],auxparam,",");
                    for ( i in auxparam ) if (auxparam[i]) OD=OD"--"auxparam[i]" ";
                 }
              }
              if (match($0,"[ |\t]length=")) {
                 split($0,auxparam,"[ |\t]length=");
                 split(auxparam[2],auxparam," |\t");
                 if (auxparam[1]) OD=OD" -m length --length "auxparam[1]" ";
              }
           }

           ### Getting rule interfaces
           if (bwnf_flow[name_qos] != "PREROUTING" && classifier != "filter" && !match(bwif[name_qos], "^ifb[0-9]")) ifout=" -o "bwif[name_qos];
           if (bwnf_flow[name_qos] == "POSTROUTING") ifin="";
           else if ($1 != "any") ifin="-i "$1;

           ### Making netfilter rule
           if (classifier == "filter") {
              if ($4 == "LB") {
                 qostarget="-j QoS_LBRules";
                 ifin="";
                 if ($1 != "any") ifout="-o "$1;
                 if (countlbr < 1) print "iptables -t mangle -N QoS_LBRules";
                 countlbr++;
              }
              else if ($4 == "IGNORE") qostarget="-j RETURN";

              if (countchain[qoschain]++ < 1) {
                 print "iptables -t mangle -N "qoschain" 2>/dev/null";
                 print "echo "qoschain" >> /usr/share/fwguardian/tfstart.chains";
              }
           }
           else {
              if (setclass != "%ignore" && setclass == classid[name_qos]) {
                 if (domark==0 && shmark=="0") qostarget="-j CLASSIFY --set-class "setclass;
                 else qostarget="-j MARK --set-mark 0x"shmark;
              }
           }
           if (bwphy[bwif[name_qos]]) ifout=" -m physdev --physdev-out "bwif[name_qos];
           print "iptables -t mangle -A "qoschain,ifin""ifout,OD,qostarget;
        }
        else {
           if (classifier == "tc-rule" || classifier == "filter") {
              OD="";
              tusock=0;
              dproto[1]=sproto[1]="";
              dproto[2]=sproto[2]="";
              if ($2 != "0/0" && $2 != "any") OD=OD"match ip src "$2" ";
              if ($3 != "0/0" && $3 != "any") OD=OD"match ip dst "$3" ";

              ### U32 dport and/or sport match
              if (match($0,"[ |\t](port|dport)=")) {
                 split($0,dproto,"[ |\t]port=|[ |\t]dport=");
                 split(dproto[2],dproto," |\t"); split(dproto[1],dproto,"/");
              }
              if (match($0,"[ |\t]sport=")) {
                 split($0,sproto,"[ |\t]sport=");
                 split(sproto[2],sproto," |\t"); split(sproto[1],sproto,"/");
              }
              if (dproto[1] || sproto[1]) {
                 if (sproto[1] == "tcp" || dproto[1] == "tcp") {
                    tusock=1;
                    OD=OD"match ip protocol 0x06 0xff ";
                 }
                 else if (sproto[1] == "udp" || dproto[1] == "udp") {
                    tusock=1;
                    OD=OD"match ip protocol 0x11 0xff ";
                 }
                 else if (sproto[1] == "icmp" || dproto[1] == "icmp") OD=OD"match ip protocol 0x01 0xff ";
                 else if (sproto[1] == "gre" || dproto[1] == "gre") OD=OD"match ip protocol 0x2f 0xff ";
                 else if (sproto[1] == "esp" || dproto[1] == "esp") OD=OD"match ip protocol 0x32 0xff ";
                 else if (sproto[1] == "ah" || dproto[1] == "ah") OD=OD"match ip protocol 0x33 0xff ";
                 else if (sproto[1] == "ospf" || dproto[1] == "ospf") OD=OD"match ip protocol 0x59 0xff ";
                 else if (sproto[1] == "vrrp" || dproto[1] == "vrrp") OD=OD"match ip protocol 0x70 0xff ";
                 if (tusock == 1) {
                    if (dproto[2]) OD=OD"match ip dport "dproto[2]" 0xffff ";
                    if (sproto[2]) OD=OD"match ip sport "sproto[2]" 0xffff ";
                 }
                 if (match($0,"[ |\t]length=")) {
                    lens=0;
                    lene=65535;
                    split($0,auxparam,"[ |\t]length=");
                    split(auxparam[2],auxparam," |\t"); split(auxparam[1],auxparam,":");
                    if (!auxparam[2]) {
                       lene=lene-auxparam[1];
                    }
                    else {
                       lens=auxparam[1];
                       lene=lene-auxparam[2];
                    }
                    lens=sprintf("%04X", lens);
                    lene=sprintf("%04X", lene);
                    if (auxparam[1]) OD=OD"match u16 0x"lens" 0x"lene" at 2 ";
                 }
              }
              if (OD == "") OD=" match ip src any ";

              if (classifier == "tc-rule" || (classifier == "filter" && $4 == "TC-IGNORE")) {
                 ifout=$1;
                 if (classifier == "tc-rule") ifout=bwif[name_qos];
                 if (name_qos && bwid[ifout]) {
                    if (qostarget == "reclassify") print "tc filter add dev "ifout" parent "bwid[ifout]": protocol ip prio "pcount[bwid[ifout]]" u32 "OD" police reclassify flowid :1";
                    else if (setclass != "") print "tc filter add dev "ifout" parent "bwid[ifout]": protocol ip prio "pcount[bwid[ifout]]" u32 "OD" flowid "setclass;
                 }
              }
              else if (allownf == 0) {
                 ## Add a ingress Qdisc
                 ifin=$1;
                 if (bwingress[ifin] != ifin) {
                    bwingress[ifin]=ifin;
                    print "tc qdisc add dev "ifin" ingress handle ffff:";
                    print "tc filter add dev "ifin" parent ffff: protocol ip prio 1 u32 match ip protocol 6 0xff match u8 0x10 0xff at nexthdr+13 police reclassify flowid :1";
                 }

                 ## Make a ingress or mirror tc rule
                 if ($4 != "MIRROR") {
                    if (qostarget == "drop") qostarget = "rate "$5" burst "inburst" drop";
                    print "tc filter add dev "ifin" parent ffff: protocol ip prio 5 u32 "OD" police "qostarget" flowid :1";
                 }
                 else print "tc filter add dev "ifin" parent ffff: protocol ip prio 5 u32 "OD" flowid :1 action mirred egress redirect dev "bwifb[ifin];
              }
           }
        }
     }
  }
}
