#!/bin/igawk
{
  if (match($1, "^(alias|set-(condition|qos|egress|filter))$")) {
     nffilter="";
     classifier="";
     if ($1 == "alias") fwalias("make", "tfshape");
     else {
        # Script conditions
        disabled=0;
        disabledpol=0;
        disabledpol=fwalias("chkperm", "tfshape");

        # Burst calc
        minburst="";
        if (match($0,"[ |\t]burst=")) {
           split($0,auxparam,"[ |\t]burst=");
           split(auxparam[2],auxparam," |\t");
           if (auxparam[1] == "auto" || auxparam[1] == "minburst") minburst=mburst(maxrate);
           else {
              minburst=auxparam[1];
              minburst = "burst "minburst;
           }
        }

        # Set filter classifier
        if ($1 == "set-filter") {
           classifier="filter";
           if (cont_mirror > 0) {
              print "modprobe ifb numifbs="cont_mirror;
              for (i=0; i<cont_mirror; i++) {
                 print "ip link set dev ifb"i" up";
                 print "echo ifb"i" >> /usr/share/fwguardian/tfstart.ifb";
              }
           }
        }
        else if ($1 == "set-condition") fwalias("mkperm", "tfshape");
     }
  }

  ### Making the root qdisc
  if ($1 == "set-qos" && !disabledpol) {
     ## Check iptables CLASSIFY support
     if (cont_qos == 0) nf_test=0;
     if ((nf_test == 0) && (!match($0, "[ |\t]type=ingress($|[ |\t])"))) {
        qoschain="POSTROUTING";
        rtcmd="iptables -j CLASSIFY --help 2>&1 | tail -1 | grep -v set-class | wc -w";
        rtcmd | getline domark; close(rtcmd);
        countlb = 0;
        nf_test=1;
     }
     name_qos=$2;
     cont_qos++;
 
     ### Apply alias
     if ($1 == "set-qos" && match($3, ":") && alcont > 0) fwalias("apply", "tfshape");

     ## Qdisc rate: prefer full interface bandwidth
     if (match($3, "^phy")) {
        split($3,auxparam,":");
        bwif[name_qos]=auxparam[2]; bwrate=auxparam[3];
        bwphy[bwif[name_qos]]=1;
     }
     else {
        split($3,auxparam,":");
        bwif[name_qos]=auxparam[1]; bwrate=auxparam[2];
        bwphy[bwif[name_qos]]=0;
     }

     ## Qdisc algo: htb, cbq or ingress
     if (match($0,"[ |\t]type=")) {
        split($0,auxparam,"[ |\t]type=");
        split(auxparam[2],auxparam," |\t"); bwtype[name_qos]=auxparam[1];
     }
     if(!bwtype[name_qos]) bwtype[name_qos]="htb";

     ## Mirrored interfaces
     if (match($0, "[ |\t](set-mirror|mirrored)($|[ |\t])")) {
        if (match($0,"[ |\t]set-mirror($|[ |\t])")) {
           if (!bwifb[bwif[name_qos]]) {
              if (!cont_mirror) cont_mirror=0;
              bwifb[bwif[name_qos]]="ifb"cont_mirror;
              cont_mirror++;
           }
        }
        else bwif[name_qos]=bwifb[bwif[name_qos]];
     }

     ## Egress Qdisc
     if (bwtype[name_qos] != "ingress" && bwif[name_qos]!=bwroot[bwif[name_qos]]) {
        bwa_if=bwif[name_qos];
        imleaf[name_qos]="yes";
        bwid[bwa_if]=100+cont_qos;
        classid[name_qos]=bwid[bwa_if]":0";
        bwleaf[name_qos]="sfq";
        
        cont_name++;
        bwname[cont_name]=name_qos;
        bwlimit[name_qos] = "default";
        bwperturb[name_qos] = 15;

        # Init prio counters
        pcount[bwid[bwa_if]]=9;
        maxcount[bwid[bwa_if]]=10;

        # Calc interface MTU and HTB r2q
        r2q[bwif[name_qos]]=0;
        bwmtu[bwif[name_qos]]=1500;
        rtcmd="cat /sys/class/net/"bwif[name_qos]"/mtu 2>/dev/null";
        rtcmd | getline bwmtu[bwif[name_qos]]; close(rtcmd);
        if (!bwmtu[bwif[name_qos]]) bwmtu[bwif[name_qos]]=1500;

        # Set default Qdisc
        setdefault="";
        if (!bwdefault[bwif[name_qos]]) {
           bwdefault[bwif[name_qos]]="2";
           if (match($0, "[ |\t]set-default($|[ |\t])")) {
              setdefault="default ffff";
              bwdefault[bwif[name_qos]]="ffff";
           }
           else {
              if (match($0, "[ |\t]self-default($|[ |\t])") && !match($0, "[ |\t]no-rootclass($|[ |\t])")) {
                 setdefault="default 1";
                 bwdefault[bwif[name_qos]]="1";
              }
           }
        }

        # HTB Qdisc
        if (bwtype[name_qos]=="htb") {
           r2q[bwif[name_qos]]=10;
           if (match(bwrate,"[KMGkmg](bit|b)")) {
              auxrate = bwrate;
              sub("[KMGkmg](bit|b)", "", auxrate);
              if (match(bwrate, "[Kk](bit|b)")) auxrate = ((auxrate * 1000) / 8);
              else if (match(bwrate, "[Mm](bit|b)")) auxrate = ((auxrate * 1000000) / 8);
              else if (match(bwrate, "[Gg](bit|b)")) auxrate = ((auxrate * 1000000000) / 8);
              if (bwmtu[bwif[name_qos]] >= 1500) {
                 r2q[bwif[name_qos]]=(auxrate/(3 * bwmtu[bwif[name_qos]]));
                 r2q[bwif[name_qos]]=sprintf("%d", r2q[bwif[name_qos]]);
              }
           }
           if (r2q[bwif[name_qos]] < 1) r2q[bwif[name_qos]]=10;
           else {
              if (r2q[bwif[name_qos]] > 100) {
                 r2q[bwif[name_qos]]=100;
                 if (r2q[bwif[name_qos]] > 300) r2q[bwif[name_qos]]=300;
              }
           }
           print "tc qdisc add dev "bwif[name_qos]" root handle "classid[name_qos]" htb "setdefault" r2q "r2q[bwif[name_qos]];
           if (!match($0, "[ |\t]no-rootclass($|[ |\t])")) print "tc class add dev "bwif[name_qos]" parent "classid[name_qos]" classid "bwid[bwa_if]":1 htb rate "bwrate" "minburst;
        }
        else {
           # HFSC Qdisc
           if (bwtype[name_qos]=="hfsc") {
              print "tc qdisc add dev "bwif[name_qos]" root handle "classid[name_qos]" hfsc "setdefault;
              if (!match($0, "[ |\t]no-rootclass($|[ |\t])")) print "tc class add dev "bwif[name_qos]" parent "classid[name_qos]" classid "bwid[bwa_if]":1 hfsc sc rate "bwrate" ul rate "bwrate;
           }
           else {
              # CQB Qdisc
              rtcmd="cat /sys/class/net/"bwif[name_qos]"/speed 2>/dev/null";
              rtcmd | getline bwband; close(rtcmd);
              if (!bwband) {
                 bwband="100";
                 if (bwrate=="1000Mbit" || bwrate=="1Gbit") bwband=bwrate;
              }
              else bwband=bwband"Mbit";

              bwallot[bwif[name_qos]]=bwmtu[bwif[name_qos]];
              bwallot[bwif[name_qos]]+=14;
              avpkt=bwallot[bwif[name_qos]];
              avpkt=sprintf("%d", avpkt-(avpkt/3));

              print "tc qdisc add dev "bwif[name_qos]" root handle "classid[name_qos]" cbq bandwidth "bwband" avpkt "avpkt;
              if (!match($0, "[ |\t]no-rootclass($|[ |\t])")) print "tc class add dev "bwif[name_qos]" parent "classid[name_qos]" classid "bwid[bwa_if]":1 cbq bandwidth "bwband" rate "bwrate" allot "bwallot[bwif[name_qos]]" avpkt "avpkt" bounded";
           }
        }

        bwroot[bwif[name_qos]]=bwif[name_qos];
        if (!match($0, "[ |\t]no-rootclass($|[ |\t])")) {
           minorid[bwid[bwa_if]]++;
           classid[name_qos]=bwid[bwa_if]":1";
        }
     }
     else cont_qos--;
  } 

  ## Parent and classid tree
  parent_qos="";
  if ($1=="set-egress" && !disabledpol) {
     split($2, auxparam, "->");
     name_qos=auxparam[2];
     parent_qos=auxparam[1];

     ### Rule type
     if (match(name_qos, "^%") || match(parent_qos, "^(default|realtime)") || bwif[name_qos] || !bwif[parent_qos]) disabledpol=1;
     else {
        bwa_if=bwif[parent_qos];
        if (match($0, "[ |\t]tc-rule($|[ |\t])") || match(bwif[parent_qos], "^ifb[0-9]")) classifier="tc-rule";
        else {
           bwnf_flow[name_qos] = "FORWARD";
           if (match($0, "[ |\t](mark|premark|postmark)-rule($|[ |\t])")) {
              classifier="mark-rule";
              if (match($0,"[ |\t]premark-rule($|[ |\t])")) bwnf_flow[name_qos] = "PREROUTING";
              else if (match($0,"[ |\t]postmark-rule($|[ |\t])")) bwnf_flow[name_qos] = "POSTROUTING";
           }
           else {
              classifier="classify-rule";
              if (match($0,"[ |\t]post-rule($|[ |\t])")) bwnf_flow[name_qos] = "POSTROUTING";
           }

           if (!bwnf_existflow[bwnf_flow[name_qos]]) {
              bwnf_existflow[bwnf_flow[name_qos]] = bwnf_flow[name_qos];
              print "iptables -t mangle -N "bwnf_flow[name_qos]"_QoS";
              print "iptables -t mangle -A "bwnf_flow[name_qos]" -j "bwnf_flow[name_qos]"_QoS";
           }
        }
     }

     ### Class definitions
     if (parent_qos != "" && bwid[bwa_if]) {

        if (!disabledpol) {

           ### Configure default leaf
           if (bwleaf[parent_qos]) bwleaf[name_qos]=bwleaf[parent_qos];
           else bwleaf[name_qos]="sfq";

           ### Class prio (user defined or incremental)
           pcount[bwid[bwa_if]]++;
           if (pcount[bwid[bwa_if]] > maxcount[bwid[bwa_if]]) maxcount[bwid[bwa_if]]=pcount[bwid[bwa_if]];
           split($0,auxparam,"[ |\t]prio="); split(auxparam[2],auxparam," |\t");
           if (!auxparam[1]) {
              contprio++;
              clprio=contprio;
           }
           else clprio=auxparam[1];

           ### Calc Class ID
           if (match(name_qos, "^default") && bwdefault[bwif[parent_qos]] == "ffff") classid[name_qos]=bwid[bwa_if]":ffff";
           else {
              minorid[bwid[bwa_if]]++;
              classid[name_qos]=bwid[bwa_if]":"minorid[bwid[bwa_if]];
           }
           bwif[name_qos]=bwif[parent_qos];
           bwtype[name_qos]=bwtype[parent_qos];

           ### Network rate and max rate
           split($3,auxparam,":");
           nrate=auxparam[1];
           maxrate=auxparam[2];
           if (!maxrate) maxrate=nrate;

           ## SFQ flow and leaf type
           if (match($0,"[ |\t]sfq-flow=")) {
              split($0,auxparam,"[ |\t]sfq-flow=");
              split(auxparam[2],auxparam," |\t");
              if (auxparam[1] == "disabled") bwleaf[name_qos] = "pfifo";
              else {
                 bwleaf[name_qos]="sfq";
                 bwlflow[name_qos]=auxparam[1];
              }
           }

           ## Packet queue length
           bwlimit[name_qos] = "default";
           bwperturb[name_qos] = 15;
           if (match($0, "[ |\t]packets=")) {
              split($0, auxparam, "[ |\t]packets=");
              split(auxparam[2],auxparam," |\t");
              if (auxparam[1] != "default" && auxparam[1] != "none") {
                 split(auxparam[1],auxparam,"/");
                 bwlimit[name_qos]=auxparam[1];
                 if (auxparam[2] != "" && auxparam[2] != "default") bwperturb[name_qos]=auxparam[2];
              }
           }

           ### Making HTB, HFSC or CBQ class 
           cont_name++;
           bwname[cont_name]=name_qos;
           if (bwtype[name_qos] == "htb" && classid[parent_qos]) {
              # Calc quantum
              quantum=0;
              if (match(nrate,"[KMGkmg](bit|b)")) {
                 auxrate = nrate;
                 sub("[KMGkmg](bit|b)", "", auxrate);
                 if (match(nrate, "[Kk](bit|b)")) auxrate = ((auxrate * 1000) / 8);
                 else if (match(nrate, "[Mm](bit|b)")) auxrate = ((auxrate * 1000000) / 8);
                 else if (match(nrate, "[Gg](bit|b)")) auxrate = ((auxrate * 1000000000) / 8);
              }
              quantum=auxrate/r2q[bwif[name_qos]];
              if (quantum < bwmtu[bwif[name_qos]] || quantum > 60000) {
                 quantum=bwmtu[bwif[name_qos]] * 3;
                 quantum="quantum "quantum" ";
              }
              else quantum="";

              if (minburst != "") {
                 auxburst=minburst;
                 sub("burst", "cburst", minburst);
                 minburst=auxburst" "minburst;
              }
              print "tc class add dev "bwif[name_qos]" parent "classid[parent_qos]" classid "classid[name_qos]" htb prio "clprio" rate "nrate" ceil "maxrate,quantum,minburst;
           }
           else {
              if (bwtype[name_qos] == "hfsc" && classid[parent_qos]) {
                  sc="";
                  if (match($0,"[ |\t]latency=")) {
                     split($0,auxparam,"[ |\t]latency=");
                     split(auxparam[2],auxparam," |\t");
                     sc=auxparam[1];
                  }
                  if (match(sc, "^[0-9]+ms$")) sc="umax "bwmtu[bwif[name_qos]]+40" dmax "sc;
                  if (match(name_qos, "^realtime")) sc="rt "sc" rate "nrate;
                  else sc="sc "sc" rate "nrate" ul rate "maxrate;

                  print "tc class add dev "bwif[name_qos]" parent "classid[parent_qos]" classid "classid[name_qos]" hfsc "sc;
              }
              else {
                 if (nrate < maxrate) BOUNDED=""; else BOUNDED="bounded";
                 if (match($0,"[ |\t]isolated($|[ |\t])")) ISOLATED="isolated"; else ISOLATED="";

                 if (classid[parent_qos]) print "tc class add dev "bwif[name_qos]" parent "classid[parent_qos]" classid "classid[name_qos]" cbq prio "clprio" bandwidth "maxrate" rate "nrate" allot "bwallot[bwif[name_qos]]" avpkt "avpkt" "BOUNDED" "ISOLATED;
              }
           }

           ### Indentify SFQ leaf nodes
           imleaf[parent_qos]="no";
           imleaf[name_qos]="yes";

           ### Make mark definitions to use in mark rules
           bwmark[name_qos]="0";
           if (classifier == "mark-rule" && bwid[bwa_if]) {
              # Calc next prio
              pcount[bwid[bwa_if]]++;
              if (pcount[bwid[bwa_if]] > maxcount[bwid[bwa_if]]) maxcount[bwid[bwa_if]]=pcount[bwid[bwa_if]];

              # Make fwmark filter
              shmark=classid[name_qos]; 
              sub(":","",shmark);
              if (match(shmark, "ffff$")) sub("ffff$", "f", shmark);
              bwmark[name_qos]=shmark;
              print "tc filter add dev "bwif[name_qos]" parent "bwid[bwa_if]": protocol ip prio "pcount[bwid[bwa_if]]" handle 0x"shmark" fw flowid "classid[name_qos];
           }

           ### Squid delay_pool like
           if (match($0, "[ |\t]nf-lb($|[ |\t])") && countlbr > 0) {
              countlb++;
              connew[countlb]="";
              if (classifier == "mark-rule") ctlbmark++;
              if (match($0,"[ |\t]track-new($|[ |\t])")) connew[countlb]="-m conntrack --ctstate NEW ";
              if (countlb == 1) {
                 lbtrack="";
                 if (match($0, "[ |\t]track-dst($|[ |\t])")) lbtrack="--rdest";
                 if (ctlbmark > 0) print "iptables -t mangle -A QoS_LBRules -j CONNMARK --restore-mark";
                 system("echo QoS_LBRules >> /usr/share/fwguardian/tfstart.chains");
              }
              print "iptables -t mangle -N LB_QOS"countlb;
              if (ctlbmark < 1) {
                 print "iptables -t mangle -A QoS_LBRules -m recent --update --seconds 3600 --name LBQOS"countlb" "lbtrack" -j LB_QOS"countlb;
                 print "iptables -t mangle -A LB_QOS"countlb" -j CLASSIFY --set-class "classid[name_qos];
                 print "iptables -t mangle -A LB_QOS"countlb" -m recent --name LBQOS0 "lbtrack" --set ";
                 if (!match($0, "[ |\t]fixed($|[ |\t])")) {
                    print "iptables -t mangle -A LB_QOS"countlb" -m recent --name LBQOS"countlb" "lbtrack" --remove -p tcp --tcp-flags ALL RST -j RETURN";
                    print "iptables -t mangle -A LB_QOS"countlb" -m recent --name LBQOS"countlb" "lbtrack" --remove -p tcp --tcp-flags ALL FIN -j RETURN";
                 }
                 print "iptables -t mangle -A LB_QOS"countlb" -m recent --name LBQOS"countlb" "lbtrack" --set -j RETURN ";
              }
              else {
                 print "iptables -t mangle -A QoS_LBRules -m mark --mark 0x"shmark" -j LB_QOS"countlb;
                 print "iptables -t mangle -A LB_QOS"countlb" -m mark --mark 0x0 -j CONNMARK --set-mark 0x"shmark;
              }

              system("echo LB_QOS"countlb" >> /usr/share/fwguardian/tfstart.chains");
           }
        }
     }
  }
}
