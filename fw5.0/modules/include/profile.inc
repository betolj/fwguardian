#!/bin/igawk
{
   if (match($1,"^set-(policy|condition)$")) {
      if ($1 == "set-policy") {
         countp=0;
         profpol="";
         proflim=0;
         disabled=0;
         disabledpol=0;
         disabledpol=fwalias("chkperm", "profile");
         if (rload != $2 && rload != ".*") disabledpol=1;
         if (!disabledpol) {
            profpol = $2;
            table="filter";
            if (match(profpol, "^(limit|vpn|mangle):")) {
               if (match(profpol,"^limit:")) {
                  proflim = 1;
                  split(profpol,chain,"limit:"); 
                  profpol=chain[2];
               }
               else {
                  split(profpol,chain,"vpn:|mangle:"); 
                  profpol=chain[2];
                  table="mangle";
               }
            }
            if (match(profpol,"^(rsquid|vpop3)")) {
               if (table == "mangle" || proflim == 1) disabled=1;
               else table="nat";
            }

            if (!disabled) {
               print "iptables -t "table" -F "profpol" 2>/dev/null";
               print "iptables -t "table" -N "profpol" 2>/dev/null";
               if (proflim && !match(profpol, "^my_")) {
                  print "iptables -t "table" -A "profpol" -m limit --limit 3/s --limit-burst 3 -j LOG --log-level info --log-prefix \"DROP profile "profpol" \" ";
                  print "iptables -t "table" -A "profpol" -j DROP ";
               }
            }
         }
      }
      else fwalias("mkperm", "profile");
   }
   else {
      if (!disabledpol) disabled=0;
      disabled=fwalias("chkperm", "profile");

      isgeoip=0;
      isgplist=0;
      if (match($3, "^(src|dst)_(addr|gplist)$")) isgplist=1;
      else if (match($3, "(src|dst)_geoip")) isgeoip=1; 

      if (!disabledpol && !disabled) {
         OD="";

         ### Interface
         if ($1 == "from" && $2 != "any" ) OD=" -i "$2;
         else {
            if ($2 != "any") OD=" -o "$2;
         }

         ### IP Address
         if ($6 == "from" && $7 != "any" && !match($3, "^src_(gplist|addr)$")) OD=OD" -s "$7;
         else {
            if ($7 != "any" && !match($3, "^dst_(gplist|addr)$")) OD=OD" -d "$7;
         }

         ### Protocol adjustments
         pproto="";
         if (!isgplist && $3 != "any") {
            if (isgeoip) {
               # Nice lookup - http://www.infosniper.net/index.php
               if ($3 == "src_geoip") pproto=pproto" -m geoip --src-cc "$4;
               else pproto=pproto" -m geoip --dst-cc "$4;
            }
            else {
               if (match($3, "^(tcp|udp)") && match($4,"^([0-9a-zA-Z-])+[:]*([0-9a-zA-Z-])*,")) pproto=" -m multiport";
               pproto=pproto" -p "$3;
               if ($4 != "any") pproto=pproto" --dport "$4;
            }
            if (match($0,"[ |\t](start|new)($|[ |\t])")) {
               if ($3 == "tcp") pproto=pproto" --syn";
               pproto=pproto" -m conntrack --ctstate NEW";
            }
         }
         if (match($0,"[ |\t]string=")) {
            split($0, string, "[ |\t]string=");
            split(string[2], string, "\t");
            pproto=pproto" -m string --string "string[1]" --algo bm";
         }

         ### Target
         if ($5 == "IGNORE" || profpol == "rsquid" || profpol == "vpop3") ptarget="RETURN";
         else ptarget=$5;
         if (ptarget == "REJECT" && $3 == "tcp") ptarget="REJECT --reject-with tcp-reset";

         ## Enable log profile
         if (match($0,"[ |\t]log($|[ |\t])")) {
            auxplog="log_"profpol"_"ptarget;
            if (!plog[auxplog]) {
               plog[auxplog] = 1;
               print "iptables -t "table" -N "auxplog" 2>/dev/null";
               print "iptables -t "table" -F "auxplog;

               print "iptables -t "table" -A "auxplog" -m limit --limit 3/s -m conntrack --ctstate NEW -j LOG --log-level info --log-prefix \"FW profile "profpol" \" ";
               print "iptables -t "table" -A "auxplog" -j "ptarget;
            }
            ptarget=auxplog;
         }

         if (proflim) {
            if ($5=="PKTLIMIT") {
              ### Hashlimit control
              if (match($8, "^[0-9]+/[smh],[0-9]+$")) {
                 split($8, hlimit, ",");
                 if (match($9,"^flow=") && hlimit[2]) {
                    countp++;
                    split($9, hash, "=");
                    split(hash[2], flow, "/");

                    if (!flow[2]) {
                       flow[2]=flow[1];
                       hashname=profpol""countp;
                    }
                    else hashname=flow[1];
                    if (hashname == "synlimit") hashdef="--hashlimit-htable-expire 60000 --hashlimit-htable-max "maxsyn;
                    else hashdef="--hashlimit-htable-max 30000";
                    print "iptables -t "table" -I "profpol,countp,OD,pproto" -m hashlimit "hashdef" --hashlimit-mode "flow[2]" --hashlimit "hlimit[1]" --hashlimit-burst "hlimit[2]" --hashlimit-name "hashname" -j RETURN";
                 }
              }
            }
            else {
               if ($5=="CONNLIMIT") {
                  ### Connlimit control
                  if (match($8, "^[0-9]+/[0-9]+($|,(upto|above)$)")) {
                     split($8, climit, ",");
                     limit="above";
                     ptarget="DROP";
                     if (climit[2] && climit[2] == "upto" || !climit[2]) {
                        limit="upto";
                        ptarget="RETURN";
                     }
                     if (match(climit[1],"^[0-9]+/[0-9]+$")) {
                        countp++;
                        split(climit[1], climit, "/");
                        if (!climit[2]) cmask="32";
                        else cmask=climit[2];
                        print "iptables -t "table" -I "profpol,countp,OD,pproto" -m connlimit --connlimit-"limit" "climit[1]" --connlimit-mask "cmask" -j "ptarget;
                     }
                  }
               }
               else {
                  ## Configure a default or gplist profile
                  if (!isgplist) {
                     countp++;
                     print "iptables -t "table" -I "profpol,countp,OD,pproto" -j "ptarget;
                  }
                  else {
                     split($4, ipgplist,",");
                     if (match($3, "^src_(gplist|addr)$")) pproto="-s";
                     else pproto=" -d ";
                     for (i in ipgplist) {
                        countp++;
                        print "iptables -t "table" -I "profpol,countp,OD,pproto,ipgplist[i]" -j "ptarget;
                     }
                  }
               }
            }
         }
         else {
            ## Configure a default or gplist profile
            if (!isgplist) print "iptables -t "table" -A "profpol,OD,pproto" -j "ptarget;
            else {
               split($4, ipgplist,",");
               if (match($3, "^src_(gplist|addr)$")) pproto="-s";
               else pproto=" -d ";
               for (i in ipgplist) print "iptables -t "table" -A "profpol,OD,pproto,ipgplist[i]" -j "ptarget;
            }
         }
      }
   }
}
