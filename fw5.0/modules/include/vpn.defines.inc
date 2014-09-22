#!/bin/igawk
{
   if (match($1,"^((set-(policy|condition)|alias)$)")) {
      if ($1 == "alias") fwalias("make", "fgvpn");
      else {
        if ($1 == "set-policy") {
           vpnpol="";
           disabled=0;
           disabledpol=0;
           disabledpol=fwalias("chkperm", "fgvpn");
           if (!disabledpol) {
              if (!cbipsec && !csetkey) {
                 print "setkey -F";
                 print "setkey -FP";
                 csetkey++;
              }
              if ($2 == "DIRECT") vpnpol="DIRECT";
              else if ($2 == "PPTP-SERVER") vpnpol="PPTP";
              else if ($2 == "IPSEC-SERVER") vpnpol="IPSEC";
              else if ($2 == "IP-USERMAPS") vpnpol="IP-USERMAPS";
              else disabledpol=1;
           }
        }
        else if ($1 == "set-condition") fwalias("mkperm", "fgvpn");
     }
   }
   else {
     if (!disabledpol) disabled=0;
     disabled=fwalias("chkperm", "fgvpn");

     if (!disabledpol && !disabled) {
        if ((vpnpol == "PPTP" || vpnpol == "IPSEC") && $2 != "none") {
           cb[vpnpol]++;
           if (cb[vpnpol] == 1) {
              cfg[vpnpol]=0;
              mppe[vpnpol]=1;
              winbind[vpnpol]=0;
              winbindgrp[vpnpol]="none";
              defaultgw[vpnpol]=0;
           }
           if ($1=="bind") {
              bind[vpnpol]=$2;
              if (vpnpol == "PPTP") {
                 if ($3) bport=$3; else bport="1723";
                 if (bind[vpnpol] != "any" && bind[vpnpol] != "0.0.0.0") baddr=bind[vpnpol];
                 else baddr="0.0.0.0/0";
                 print "iptables -A FwVpn -d "baddr" -p tcp --dport "bport" -j ACCEPT";
                 print "iptables -A FwVpn -d "baddr" -p gre -j ACCEPT";
                 countgre++;
                 if (countgre==1) print "modprobe ip_gre" ;
                 print "modprobe ppp_mppe";

                 if (vserver) cfg[vpnpol]=1;
              }
              else if (vpnpol == "IPSEC") {
                 l2tpena=0;
                 if ($3) bport=$3; else bport="500,4500";
                 if (bind[vpnpol] != "any" && bind[vpnpol] != "0.0.0.0") baddr=bind[vpnpol];
                 else baddr="0.0.0.0/0";
                 print "iptables -A FwVpn -d "baddr" -m multiport -p udp --dport "bport" -j ACCEPT 2>/dev/null";
                 print "iptables -A FwVpn -d "baddr" -p 50 -j ACCEPT 2>/dev/null";
                 print "iptables -A FwVpn -d "baddr" -p 51 -j ACCEPT 2>/dev/null";

                 if (vserver) cfg[vpnpol]=1;
              }
           }
           else if ($1=="ppp-pool") {
              if (vpnpol == "PPTP") pool[vpnpol]=$2;
              else if (vpnpol == "IPSEC") {
                 if ($2 ~ /([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}-([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}/) pool[vpnpol]=$2;
                 else {
                    match($2, /[0-9]+\.[0-9]+\.[0-9]+\./);
                    netipsec=substr($2, RSTART, RLENGTH);

                    match($2, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\-/);
                    netipsec1=substr($2, RSTART, RLENGTH-1);
                    match($2, "-[0-9]+");
                    netipsec2=substr($2, RSTART+1, RLENGTH);
                    pool[vpnpol]=netipsec1"-"netipsec""netipsec2;
                 }
              }
           }
           else if ($1=="ppp-local") local[vpnpol]=$2;
           else if ($1=="ms-dns") {
              split($0, auxvpn,"ms-dns[ |\t]+");
              split(auxvpn[2],auxvpn,"[ |\t|,]");
              for (i in auxvpn) {
                  if (vpnpol == "IPSEC" && auxvpn[i]) ipsecdns[++countdns[vpnpol]]=auxvpn[i];
                  if (vpnpol == "PPTP" && auxvpn[i]) pptpdns[++countdns[vpnpol]]=auxvpn[i];
              }
           }
           else if ($1=="ms-wins") {
              split($0, auxvpn,"ms-wins[ |\t]+");
              split(auxvpn[2],auxvpn,"[ |\t|,]");
              for (i in auxvpn) {
                  if (vpnpol == "IPSEC" && auxvpn[i]) ipsecwins[++countwins[vpnpol]]=auxvpn[i];
                  if (vpnpol == "PPTP" && auxvpn[i]) pptpwins[++countwins[vpnpol]]=auxvpn[i];
              }
           }
           else if ($2=="on" || $2=="yes") {
              if ($1=="proxy-arp") proxyarp[vpnpol]="proxyarp";
              else if ($1=="optional-mppe") mppe[vpnpol]=0;
              else if ($1=="default") defaultgw[vpnpol]=1;
              else if ($1=="l2tp" && vpnpol == "IPSEC") {
                 l2tpena=1;
                 print "iptables -A FwVpn -m policy --dir in --pol ipsec -d "bind[vpnpol]" -p udp --dport 1701 -j ACCEPT";
              }
           }
           else if ($1=="winbind-authgroup") {
              winbind[vpnpol]=1;
              winbindgrp[vpnpol]=$2;
           }
           else if ($1=="peerkey" && vpnpol == "IPSEC") {
              if ($2=="psk") ipseckey="psk";
              else ipseckey="cert";
           }
           else if ($1=="default-psk" && vpnpol == "IPSEC") {
              //# ipsecpsk[++countipsk]=$2;
              print "sed -i '/\\*\\t/ d' /usr/share/fwguardian/vpn/ipsec/psk.txt";
              if ($2 != "none" && $2 != "auto") print "echo \"*\t"$2"\" >> /usr/share/fwguardian/vpn/ipsec/psk.txt";
           }
        }
        else if (vpnpol == "DIRECT") {
           ### Apply alias
           if (alcont > 0) fwalias("apply", "fgvpn");

           vpndev=$1;
           vpnnet=$5;
           vpnaddr=$2;
           vpntype=$4;
           if (vpntype == "ROUTE") {
              ### Routing rules (RPDB)
              if (countdir && vpnnet != "any") {
                 if (igre[vpndev]) {
                    if ($2 != "any" && $2 != "0/0") {
                       print "ip route add "vpnnet" dev "vpndev" table tbvpn_"vpndev;
                       print "ip rule add prio 30 from "$2"  to "vpnnet" table tbvpn_"vpndev;
                    }
                    else {
                       srcaddr="";
                       if ($3 != "any" && $3 != "0/0") srcaddr="src "$3;
                       print "ip route del "vpnnet" dev "vpndev" 2>/dev/null";
                       print "ip route add "vpnnet" dev "vpndev" "srcaddr;
                    }
                 }
              }
           }
           else {
              ### Direct tunnel (gre/ipsec)
              ipip=0;
              countdir++;
              if (countdir==1) print "rm -f /usr/share/fwguardian/vpn/vpndgd.ctl";
              if (match($0, "[ |\t]with-ipip([ |\t]|$)")) {
                 ipip=1;
                 countipip++;
                 if (countipip==1) {
                    print "modprobe tunnel4";
                    print "modprobe ipip";
                 }
              }
              else {
                 countgre++;
                 if (countgre==1) print "modprobe ip_gre";
              }
              tbids("tbvpn_"vpndev);

              if (match($3, "[a-zA-Z]+")) {
                 vpcmd="dig "$3" +nocomments +short +time=1 +tries=2";
                 vpcmd | getline remoteaddr; close(vpcmd);
              }
              else remoteaddr=$3;

              if (remoteaddr != "") {
                 if (match($0,"[ |\t]local=")) {
                    split($0,vloc,"[ |\t]local="); split(vloc[2],vloc," |\t");
                    iploc=vloc[1];
                 }
                 else {
                    vpcmd="ip route get "remoteaddr" | sed \"/ src / s/.* src/src/\" | head -1 | cut -d \" \" -f 2";
                    vpcmd | getline iploc; close(vpcmd);
                 }

                 ### Configure a manual IPSec Key and GRE tunnel
                 if (match($0,"[ |\t]ipsec-psk=")) {
                    split($0,psk,"[ |\t]ipsec-psk="); split(psk[2],psk,"\"");
                    if (length(psk[2]) < 24) psk[2] = sprintf("%s%0"24-length(psk[2])"d", psk[2], 0);

                    split($0,spi,"[ |\t]spi="); split(spi[2], spi, " |\t");
                    split(spi[1], spi, "/");

                    countipsec++;
                    print "iptables -A FwVpn -p 50 -s "remoteaddr" -d "iploc" -j ACCEPT";
                    print "iptables -A FwVpn -p 51 -s "remoteaddr" -d "iploc" -j ACCEPT";

                    print " echo \"add "iploc" "remoteaddr" esp "spi[2]" -E 3des-cbc \\\""psk[2]"\\\" ; \" | setkey -c";
                    print " echo \"spdadd "iploc" "remoteaddr" any -P out ipsec esp/transport//require; \" | setkey -c";

                    print " echo \"add "remoteaddr" "iploc" esp "spi[1]" -E 3des-cbc \\\""psk[2]"\\\" ; \" | setkey -c";
                    print " echo \"spdadd "remoteaddr" "iploc" any -P in ipsec esp/transport//require; \" | setkey -c";
                 }
                 else {
                    if (ipip==1) print "iptables -A FwVpn -p 4 -s "remoteaddr" -d "iploc" -j ACCEPT";
                    else print "iptables -A FwVpn -p gre -s "remoteaddr" -d "iploc" -j ACCEPT";
                 }

                 # Making the GRE tunnel
                 if (ipip==1) print "ip tunnel add "vpndev" mode ipip remote "remoteaddr" local "iploc;
                 else print "ip tunnel add "vpndev" mode gre remote "remoteaddr" local "iploc;
                 print "ip link set dev "vpndev" mtu 1400 up";
                 print "ip addr add "vpnaddr" dev "vpndev;

                 # Adding the route path
                 if (vpnnet != "any" && vpnnet != "0/0") {
                    print "ip route flush table tbvpn_"vpndev;
                    print "ip route del "vpnnet" dev "vpndev;
                    print "ip route add "vpnnet" dev "vpndev;
                    print "iptables -t mangle -I RtSec -s "vpnnet" -j RETURN 2>/dev/null";
                 }
                 else print "iptables -t mangle -I RtSec -i "vpndev" -j RETURN 2>/dev/null";

                 # Update firewall addr
                 fwaddr = vpnaddr;
                 sub("/.*", "", fwaddr);
                 print "iptables -t mangle -D RtSec -s "vpnaddr" -j RETURN 2>/dev/null";
                 print "iptables -t mangle -I RtSec -s "vpnaddr" -j RETURN";
                 print "grep -q \"\\b"fwaddr"\\b\" /usr/share/fwguardian/fw.ipaddr || echo "fwaddr" >> /usr/share/fwguardian/fw.ipaddr";

                 # Configure a DGD VPN peers
                 if ($6 != "none" && $6 != "any") {
                    dgdrl=0;
                    if (match($0, "[ |\t]dgd-reload($|[ |\t])")) dgdrl=1;
                    if ($6 != "") {
                       print "echo \""dgdrl" "$6"\" >> /usr/share/fwguardian/vpn/vpndgd.ctl";
                       print "iptables -A FwVpn -p icmp --icmp-type echo-request -s "$6" -j ACCEPT";
                    }
                 }
           
                 igre[vpndev]=countdir;
              }
           }
        }
        else if (vpnpol == "IP-USERMAPS") {
           ### Apply alias
           if (alcont > 0) fwalias("apply", "fgvpn");

           vpnuser=$1;
           vpnaddr=$2;
           if ($3 == "ppp") {
              ### Reset and configure PAP and CHAP secrets
              if ($4 == "SET" && match($5, "^passwd=")) {
                 cvpn++;
                 if (cvpn==1) {
                    print "echo -e \"\\t    Flush PAP and CHAP secrets!\"";
                    print "echo \"# Secrets for authentication using PAP\" > /etc/ppp/pap-secrets";
                    print "echo \"# Secrets for authentication using CHAP\" > /etc/ppp/chap-secrets";
                    print "echo \"# client        server  secret                  IP addresses\" >> /etc/ppp/pap-secrets ";
                    print "echo \"# client        server  secret                  IP addresses\" >> /etc/ppp/chap-secrets ";
                 }

                 ppass[1]="";
                 auxpass[1]="*";
                 split($5,ppass,"passwd="); 
                 split(ppass[2],ppass,"\"");

                 ppass[1]="chap";
                 if (match($0, "[ |\t]with-pap($|[ |\t])")) ppass[1]="pap";
                 else if (match($0, "[ |\t]with-chpap($|[ |\t])")) ppass[1]="chpap";

                 if (match(ppass[2], "^$")) auxpass[2]="";
                 else {
                    if (match(ppass[2], ":")) split(ppass[2],auxpass,":");
                    else {
                       auxpass[1] = "*";
                       auxpass[2] = ppass[2];
                    }
                 }
                 if (match(ppass[1],"^(pap|chpap)$"))  print "echo \""vpnuser"          "auxpass[1]"       \""auxpass[2]"\"          "vpnaddr" \" >> /etc/ppp/pap-secrets ";
                 if (match(ppass[1],"^(chap|chpap)$")) print "echo \""vpnuser"          "auxpass[1]"       \""auxpass[2]"\"          "vpnaddr" \" >> /etc/ppp/chap-secrets ";

                 if (vpnaddr != "*") {
                    print "iptables -t mangle -D RtSec -s "vpnaddr" -j RETURN";
                    print "iptables -t mangle -I RtSec -s "vpnaddr" -j RETURN";
                 }
              }
           }
           else if (match($3,"ssh") && $4 != "none") {
              ### Set the SSH user permissions
              finduser=0;
              vpcmd="id "vpnuser" 2>/dev/null | wc -l";
              vpcmd | getline finduser; close(vpcmd);

              if (finduser==1) {
                 finduser=0;
                 for (i in sshuser) {
                    if (sshuser[i]==vpnuser) {
                       finduser=1;
                       break;
                 } }
                 if (finduser==0) {
                    sshuser[++countu]=vpnuser;
                    print "echo -e \"\\t Making SSH VPN (forward) rules for user (owner): "vpnuser" \" ";
                    print "iptables -t mangle -N ssh_"vpnuser" 2>/dev/null";
                    print "iptables -t mangle -F ssh_"vpnuser" 2>/dev/null";
                    print "iptables -t mangle -A ssh_"vpnuser" -m conntrack --ctstate NEW,INVALID -j DROP";
                    print "iptables -t mangle -I RtSec "countu" -m owner --uid-owner "vpnuser" -j ssh_"vpnuser" 2>/dev/null";
                 }
                 print "iptables -t mangle -I ssh_"vpnuser" -d "vpnaddr" -j "$4;
              }
           }
        }
     }
   }
}

