#!/bin/igawk
{
   if (match($1, "^(alias|set-condition)$")) {
      if ($1 == "alias") fwalias("make", "fwhosts");
      else fwalias("mkperm", "fwhosts");
   }
   else {
     ### Check conditions for fwhosts rules
     disabled = 0;
     invert = 0;
     fwalias("chkperm", "fwhosts");

     if (!disabled) {
       ### Apply alias
       if (alcont > 0) fwalias("apply", "fwhosts");

       if ($1=="set") {
          if ($2=="log") {
             if (cont == 0) {
                cont++;
                split($0,logd,"[ |\t]log[ |\t]"); split(logd[2],logd,"\"");
                defLog=logd[2];
             }
          }
          else {
             if ($2 == "protect") {
                if ($3=="on") {
                   fwprotect=1;
                   ctnobanned=0;
                   pcount++;
                   print "iptables -t mangle -N Protect";
                   if ($4 && $4!="any") {
                      split($0,pif,"\""); split(pif[2],pif," |,");
                      if (!pif[1]) pif[1]=$4;
                      for (i in pif) {
                         pifaux = "";
                         if (match(pif[i], "^!")) {
                            sub("!","", pif[i]);
                            pifaux="! -i "pif[i];
                         }
                         else pifaux="-i "pif[i];
                         print "iptables -t mangle -I PREROUTING "pcount,pifaux" -p tcp --syn -j Protect";
                      }
                   }
                   else print "iptables -t mangle -I PREROUTING "pcount" -p tcp --syn -j Protect";
                }
                else fwprotect=0;
             }
          }
       }
       else {
         if ($2!="0.0.0.0" && $2!="0/0") {
            srcnet=$2;
            if (match(srcnet, "^!")) {
               invert = 1;
               sub("!","", srcnet);
               srcnet="! -s "srcnet;
            }
            else srcnet="-s "srcnet;
         }
         else srcnet="";

         srcmac=$3;
         if (match(srcmac, "^!")) {
            invert = 1;
            sub("!","", srcmac);
            srcmac="! --mac-source "srcmac;
         }
         else srcmac="--mac-source "srcmac;

         if (fwprotect==1) {
            if ($4 == "LOG" || match($0,"[ |\t](log|protect)($|[ |\t])")) {
               protected = 0;
               if (cont == 0) {
                  defLog = "[ IP Spoof ]:";
                  cont++;
               }
               if (match($0,"[ |\t]log-desc=")) {
                  split($0,logd,"[ |\t]log-desc="); split(logd[2],logd,"\"");
                  logdesc=logd[2];
               }
               else logdesc = defLog;
               if (match($0,"[ |\t]protect($|[ |\t])") && invert == 0) protected = 1;
               if (logdesc != defLog) {
                  nchain = "Protect_"$1;
                  print "iptables -t mangle -N "nchain" 2>/dev/null";
               }
               else {
                  if (protected == 1) {
                     nchain = "Protect_dropdefault";
                     if (dropdef < 2) {
                        dropdef++;
                        if (dropdef == 1) print "iptables -t mangle -N "nchain;
                     }
                  }
                  else {
                     nchain = "Protect_logdefault";
                     if (logdef < 2) {
                        logdef++;
                        if (logdef == 1) print "iptables -t mangle -N "nchain;
                     }
                  }
               }
               if ((dropdef < 2 && nchain == "Protect_dropdefault") || (logdef < 2 && nchain == "Protect_logdefault") || logdesc != defLog) {
                  print "iptables -t mangle -A "nchain" -m limit --limit 1/s --limit-burst 1 -j LOG --log-level info --log-prefix \" "logdesc" (fwhosts): \"";
                  system("echo "nchain" >> /usr/share/fwguardian/protect.chains");
               }

               if (protected == 1) {
                  if (logdesc != defLog || (logdesc == defLog && dropdef < 2)) print "iptables -t mangle -A "nchain" -j DROP";
                  print "iptables -t mangle -A Protect "srcnet" -m mac ! --mac-source "$3" -j "nchain;
               }
               else print "iptables -t mangle -A Protect "srcnet" -m mac "srcmac" -j "nchain;
            }

            if (match ($0,"[ |\t]nobanned($|[ |\t])") && invert == 0) {
               ctnobanned++;
               print "iptables -t mangle -I AcBanned "ctnobanned" -s "$2" -j RETURN";
            }
         }

         if ($4!="LOG") print "iptables -A FwHosts "srcnet" -m mac "srcmac" -j "$4;
       }
     }
   }
}
