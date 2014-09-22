#!/bin/igawk
{
  ### Making rules
  if (!match($1,"^(set-|alias)")) {

     ### Check condition by advrouting rules
     if (!disabledpol) disabled=0;
     disabled=fwalias("chkperm", "rttables");

     if (setrt_links && $4) system("touch /tmp/tb-"$4".warn 2>/dev/null");

     if (!disabledpol && !disabled) {

        ### Apply alias
        if (alcont > 0) fwalias("apply", "rttables");

        split($1,ifrt,"->"); 
        if (!ifrt[2]) ifrt[2]=ifrt[1];
        OD=""; dproto[1]=sproto[1]=""; dproto[2]=sproto[2]="";

        if (match($0,"[ |\t](port|dport)=")) {
           split($0,dproto,"[ |\t]port=|[ |\t]dport=");
           split(dproto[2],dproto," |\t"); split(dproto[1],dproto,"/");
        }
        if (match($0,"[ |\t]sport=")) {
           split($0,sproto,"[ |\t]sport=");
           split(sproto[2],sproto," |\t"); split(sproto[1],sproto,"/");
        }

        if ((dproto[1]) || (sproto[1])) if(dproto[1]) OD=OD"-p "dproto[1]" "; 
        else OD=OD"-p "sproto[1]" ";

        if (dproto[2]) OD=OD"--dport "dproto[2]" ";
        if (sproto[2]) OD=OD"--sport "sproto[2]" ";
        if (match($0,"(tcp|udp)/([0-9a-zA-Z-])+[:]*([0-9a-zA-Z-])*,")) { OD="-m multiport "OD" "; }

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

        if (setpol_nf) {
           if (priopol >= 50) {
              mark = "";
              contpnat++;
              for (i in aptable) if (aptable[i] == $4) { mark=apmark[i]; break; };
              if (contpnat == 1) {
                 if (mkprt) {
                    print "iptables -t mangle -N PrTAB 2>/dev/null";
                    print "iptables -t mangle -D PREROUTING -j PrTAB 2>/dev/null";
                    print "iptables -t mangle -A PREROUTING -j PrTAB 2>/dev/null";
                    print "touch /usr/share/fwguardian/rttables.prlock";
                 }
                 for (i in ipmark) {
                    priopol++;
                    print "ip rule add prio "priopol" "ipmark[i];
                 }
              }
              if (mark) {
                 if (match(ifrt[1], "^(none|any)$")) print "iptables -t mangle -A PrTAB "OD" -j CONNMARK --set-mark 0x"mark;
                 else print "iptables -t mangle -A PrTAB -i "ifrt[1],OD" -j CONNMARK --set-mark 0x"mark;
              }
           }
        }
        else {
           ### Making iproute2 rules
           if (setpol_rpdb) {
              if (priopol >= 50) {
                 ipparam="";

                 priopol++;
                 if (!match(ifrt[1], "^(any|none)")) ipparam=ipparam" iif "ifrt[1];
                 if (($2) && ($2)!="0/0") ipparam=ipparam" from "$2;
                 if (($3) && ($3)!="0/0") ipparam=ipparam" to "$3;
                 print "ip rule add prio "priopol" "ipparam" table "$4" 2>/dev/null";
              }
           }
           else if (setrt_links) {
              ptable=$4;
              itgw=$1; netgw=$2; defgw=$3;

              ## Initial counters
              contval++;
              afrom="from";
              if (contval == 1) {
                 priopol=50;
                 blprio=1000;
                 if (!gctime) gctime=300;
                 system("echo "gctime" > /proc/sys/net/ipv4/route/gc_timeout");
              }

              ## Calc ID tables (update rt_tables iproute2 file)
              tbids(ptable);

              ## Flush current routing table and looking for table in rt_tables
              print "ip route flush table "ptable" 2>/dev/null";

              ## Making the routing table
              if ($2 == "auto" && $3 == "auto") {
                 dyngw=1;
                 defgw=itgw;
              }
              else dyngw=0;
              print "echo -e \"\t    Making/Loading routing table...\" "ptable;
              if (defgw) {
                 ipsrc="";
                 if (!dyngw) {
                    rtcmd="ip route get "defgw" | sed \"/ src / s/.* src/src/\" | head -1 | cut -d \" \" -f 2";
                    rtcmd | getline ipsrc;
                    close(rtcmd);
                    if (ipsrc) {
                       print "ip route add "netgw" dev "itgw" table "ptable" src "ipsrc" proto static metric 10";
                       print "ip route add default via "defgw" dev "itgw" table "ptable" src "ipsrc" proto static metric 10";
                    }
                 }
                 else print "ip route add default dev "itgw" table "ptable" proto static metric 10";

                 if (match($0, "[ |\t]onfail-(prohibit|blackhole|throw)($|[ |\t])")) {
                    if (match($0, "[ |\t]onfail-prohibit")) auxpar="prohibit";
                    else if (match($0, "[ |\t]onfail-blackhole")) auxpar="blackhole";
                    else auxpar="throw";
                    print "ip route append "auxpar" default table "ptable" metric 15 proto static";
                 }
              }

              lb=0;
              onlytable=0;
              setlb=0; setfo=0;
              if (match($0, "[ |\t]lbgroup=")) {
                 setlb=1;
                 fwr=1;
                 lb=1;
              }
              if (match($0, "[ |\t]fogroup=")) {
                 setfo=1;
                 fwr=1;
                 lb=1;
              }
              if (match($0,"[ |\t](onlytb|only-table)($|[ |\t])")) onlytable=1;
              if (!onlytable || lb) {
                 if (!rtfoff || lb) {
                    if (rtsrc == "1") auxgw=ipsrc;
                    else auxgw=netgw;
                    if (dyngw) {
                       afrom="";
                       auxgw=" dev "itgw;
                       lbgw=auxgw;
                    }
                    else lbgw=" via "defgw;

                    # Make load balance rules 
                    if (lb && defgw) {
                       if (setlb) {
                          auxpar=0;
                          auxtype="lb";
                          split($0,auxparam,"[ |\t]lbgroup=");
                          split(auxparam[2],auxparam," |\t"); split(auxparam[1],auxparam,":");
                          if (!auxparam[2]) auxparam[2]=1;
                          for (i in lbtable) if (lbtable[i] == auxparam[1]) {
                                 auxtype=lbtype[i];
                                 auxpar=1; break;
                              };

                          if (auxtype == "lb") {
                             if (!auxpar && auxparam[1]) {
                                tbids(auxparam[1]);
                                auxprio=blprio+4000;
                                if (!onlytable) print "ip rule add prio "auxprio" table "auxparam[1];
                                print "ip route flush table "auxparam[1]" 2>/dev/null";
                                rtcmd="hostname -i";
                                rtcmd | getline ipfw;
                                close(rtcmd);
                                print "echo \"ip route add default proto static src "ipfw" scope global table "auxparam[1]"\" > /usr/share/fwguardian/"auxparam[1]".lbtable";
                                lbtable[blprio]=auxparam[1]; lbtype[blprio]="lb";
                                if (auxprio == 5000) lb=2;
                                blprio++;
                                system("touch /usr/share/fwguardian/keepalive.ctl");
                             }
                             print "echo \" nexthop "lbgw" weight "auxparam[2]"\" >> /usr/share/fwguardian/"auxparam[1]".lbtable";
                          }
                       }
                       if (setfo) {
                          auxpar=0;
                          auxtype="fo";
                          split($0,auxparam,"[ |\t]fogroup=");
                          split(auxparam[2],auxparam," |\t"); split(auxparam[1],auxparam,":");
                          for (i in lbtable) if (lbtable[i] == auxparam[1]) {
                                 auxtype=lbtype[i];
                                 auxpar=1; break;
                              };

                          if (auxtype == "fo") {
                             if (!auxpar && auxparam[1]) {
                                tbids(auxparam[1]);
                                auxprio=blprio+4000;
                                if (!onlytable) print "ip rule add prio "auxprio" table "auxparam[1];
                                print "ip route flush table "auxparam[1]" 2>/dev/null";

                                lbtable[blprio]=auxparam[1]; lbtype[blprio]="fo";
                                if (auxprio == 5000) lb=2;
                                blprio++;
                             }
                             print "ip route append default "lbgw " table "auxparam[1];
                          }
                       }
                       if (lb == 2) {
                          lb=1;
                          print "ip route del default 2>/dev/null";
                          print "echo 1 > /proc/sys/net/ipv4/route/gc_interval";
                       }
                    }

                    # Make link rules
                    if (!(rtfoff && onlytable)) {
                       if (match($0, "[ |\t]prio=")) {
                          split($0,auxparam,"[ |\t]prio="); split(auxparam[2],auxparam," |\t");
                          auxprio=auxparam[1];
                       }
                       else {
                          auxprio=blprio++;
                          auxprio=auxprio+30;
                       }
                       ruleprio=auxprio;
                       print "ip rule del prio "ruleprio,afrom,auxgw" table "ptable" 2>/dev/null";
                       print "ip rule add prio "ruleprio,afrom,auxgw" table "ptable;
                    }
                 }

                 ## Add iproute fwmark criteria - force for keep-alive sessions (fwr = 1)
                 if (!match($0,"[ |\t]only-iproute($|[ |\t])") || fwr) {
                    pmark=300; rtmark++; pmark+=rtmark;
                    auxmark="fwmark 0x"pmark" table "ptable;

                    if (lb) {
                       priopol++;
                       print "ip rule add prio "priopol" "auxmark;
                    }
                    else ipmark[rtmark-1]=auxmark;

                    rtcmd="echo "ptable" "itgw" "defgw"  ip:"ipsrc" 0x"pmark" >> /usr/share/fwguardian/modules/rttables.ctl";
                    system(rtcmd);
                 }
              }

              aptable[contval-1]=ptable; apmark[contval-1]=pmark; aipsrc[contval-1]=ipsrc;
              if (match($0,"[ |\t](onlytb|only-table|only-iproute)($|[ |\t])")) apmark[contval-1]=0;

              ### Changing routing table to test-dgd checks
              if ($5 != "none") {
                 split($5,auxparam,",");
                 for ( i in auxparam ) {
                    if (auxparam[i]) {
                       print "ip route del "auxparam[i]" 2>/dev/null";
                       print "ip route add "auxparam[i]" via "defgw" proto static metric 10";

                       if (dyngw) auxdefgw="auto";
                       else auxdefgw=defgw;
                       print "echo \""ptable" "auxparam[i]" "auxdefgw"\" >> /usr/share/fwguardian/rtdgd.ctl";
                    }
                 }
              }
           }
        }
     
        ### Making source nat
        if (match($0,"[ |\t](masq|autosnat)($|[ |\t])")) {
           contnat++;
           autosnat="";
           natTarget="";

           if (contnat==1) print "iptables -t nat -N PoTAB 2>/dev/null";
           if (match($0, "[ |\t]masq($|[ |\t])")) natTarget="-j MASQUERADE";
           else {
              for (i in aptable) if (aptable[i] == $4) { 
                 if (aipsrc[i]) natTarget="-j SNAT --to "aipsrc[i];
                 break;
              }
           }
           if (natTarget) print "iptables -t nat -A PoTAB -o "ifrt[2],OD,natTarget;
        }
     }
  }
}

