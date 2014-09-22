#!/bin/igawk
{
   if (match($1,"^(set-(condition|policy)|alias)$")) {
       if ($1 == "alias") fwalias("make", "fwinput");
       else if ($1 == "set-policy") {
         disabled=0; disabledpol=0;
         disabledpol=fwalias("chkperm", "fwinput");
       }
       else fwalias("mkperm", "fwinput");
   }
   else {
      if (!disabledpol) disabled=0;
      disabled=fwalias("chkperm", "fwinput");

      if (!disabledpol && !disabled) {
         fwalias("apply", "fwinput");
         OD=""; dorst = 0;
         dproto[1]=""; dproto[2]="";

         ### Match with dport and/or sport and new packets
         if (match($0,"[ |\t](port|dport)=")) {
            split($0,dproto,"[ |\t]dport=|port=");
            split(dproto[2],dproto," |\t"); split(dproto[1],dproto,"/");
         }

         ### Protocol types
         if (dproto[1] == "icmp" || dproto[1] == "ipp2p") {
            if (dproto[1] == "icmp") {
              if (dproto[2] == "any" || dproto[2] == "") OD = OD"-p icmp ";
              else OD = OD"-p icmp --icmp-type "dproto[2]" ";
            }
            else {
              if (dproto[2] == "any" || dproto[2] == "") OD = OD"-m ipp2p --edk --kazaa --gnu --bit --apple --winmx --soul --ares ";
              else {
                OD = OD"-m ipp2p ";
                auxparam[1]=dproto[2];
                split(auxparam[1],auxparam,",");
                for ( i in auxparam ) OD=OD" --"auxparam[i];
                OD=OD" ";
              }
            }
         }
         else {
           if (tcprst && dproto[1] == "tcp") dorst = 1;
           if(dproto[1]) OD=OD"-p "dproto[1]" ";
           if(dproto[2]) OD=OD"--dport "dproto[2]" ";
           if (match($0,"(tcp|udp)/([0-9a-zA-Z-])+[:]*([0-9a-zA-Z-])*,")) OD="-m multiport "OD;
         }

         ### Connection state
         if (match($0,"[ |\t](start|new)($|[ |\t])")) {
            if (dproto[1]=="tcp") OD=OD"--syn ";
            else OD=OD"-m conntrack --ctstate NEW ";
         }
         else if (match($0,"[ |\t]nonew($|[ |\t])")) {
            if (dproto[1]=="tcp") OD=OD" ! --syn ";
            else OD=OD"-m conntrack ! --ctstate NEW ";
         }

         ### Physdev or direct interface (input)
         srcif=$1;
         if (srcif != "any") {
            if (match(srcif, "^phy:")) {
               split(srcif, auxrt, "phy:");
               srcif = auxrt[2];
               if (match(srcif, "^!")) {
                  sub("!","", srcif);
                  OD="-m physdev ! --physdev-in "srcif" "OD;
               }
               else OD="-m physdev --physdev-in "srcif" "OD;
            }
            else {
               if (match(srcif, "^!")) {
                  sub("!","", srcif);
                  OD="! -i "srcif" "OD;
               }
               else OD="-i "srcif" "OD;
            }
         }

         ### Match with source and/or destination address
         srcnet="";
         dstnet="";
         iprange="";
         if (match($3, "([0-9]+.){3}[0-9]+") || $3 == "any") {
            if ($2 != "0/0" && $2 != "any") srcnet=$2;
            if ($3 != "0/0" && $3 != "any") dstnet=$3;
            fwtarget=$4;
         }
         else {
            if ($2 != "0/0" && $3 != "any") srcnet=$2;
            fwtarget=$3;
         }

         rstopt = "";
         if (fwtarget == "SYNPROXY") fwtarget="Do_SYNPROXY";
         else {
           if (fwtarget == "IPS") fwtarget="fw_intIPS";
           else {
              if (dorst && (fwtarget == "%R" || fwtarget == "REJECT")) rstopt = "--reject-with tcp-reset";
           }
         }

         # Make the INPUT rule
         if (srcnet != "") {
            ip_range=0;
            if (match(srcnet, "^iprange:")) {
               ip_range=1;
               sub("iprange:","", srcnet);
               if (iprange == "") iprange="-m iprange";
            }
            if (match(srcnet, "^!")) {
               sub("!","", srcnet);
               srcnet="! -s "srcnet;
            }
            else srcnet="-s "srcnet;
            if (ip_range) sub("-s", "--src-range", srcnet);
            OD=OD" "srcnet;
         }
         if (dstnet != "") {
            ip_range=0;
            if (match(dstnet, "^iprange:")) {
               ip_range=1;
               sub("iprange:","", dstnet);
               if (iprange == "") iprange="-m iprange";
            }
            if (match(dstnet, "^!")) {
               sub("!","", dstnet);
               dstnet="! -d "dstnet;
            }
            else dstnet="-d "dstnet;
            if (ip_range) sub("-d", "--dst-range", dstnet);
            OD=OD" "dstnet;
         }
         if (iprange == "-m iprange") OD="-m iprange "OD;

         print "iptables -A FwIn "OD" -j "fwtarget,rstopt;
      }
   }
}

