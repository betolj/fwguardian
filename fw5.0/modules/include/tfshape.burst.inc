### Try to calc the minburst (in kbytes)
function mburst(rate) {
   auxburst = 1.5;

   if (match(rate,"[KMGkmg](bit|b)")) {
      auxthz = rate;
      sub("[KMGkmg](bit|b)", "", auxthz);
      if (match(rate, "[Mm](bit|b)")) auxthz = auxthz * 1000;
      if (match(rate, "[Gg](bit|b)")) auxthz = auxthz * 1000000;
      auxburst = (auxthz) / (THZ * 8);
   }
   if (auxburst < 1) auxburst = 1.5;
   auxburst = "burst "auxburst"k";

   return auxburst;
}

function lastqos() {
   setdefault=1;
   for (i in bwname) if (imleaf[bwname[i]]=="yes") {
      bwa_if=bwif[bwname[i]];

      ## Setting default CBQ
      if (bwtype[bwname[i]]=="cbq" && setdefault == 1) {
         if (match(bwname[i], "^default") && bwdefault[bwa_if] == "ffff") {
            setdefault=0;
            print "tc filter add dev "bwa_if" protocol ip parent "bwid[bwa_if]": prio "maxcount[bwid[bwa_if]]+1000" u32 match ip src 0/0 flowid "bwid[bwa_if]":ffff";
         }
         else {
            if (bwdefault[bwa_if] == "1") {
               setdefault=0;
               print "tc filter add dev "bwa_if" protocol ip parent "bwid[bwa_if]": prio "maxcount[bwid[bwa_if]]+1000" u32 match ip src 0/0 flowid "bwid[bwa_if]":1";
            }
         }
      }

      ## Configuring SFQ and hash keys flow
      leafhandle=bwid[bwa_if]+i+700;
      if (bwlimit[bwname[i]] == "default" || bwlimit[bwname[i]] == "none") limit="";
      else limit="limit "bwlimit[bwname[i]];
      if (bwleaf[bwname[i]] == "sfq") {
         perturb="";
         if (bwperturb[bwname[i]] > 0) perturb="perturb "bwperturb[bwname[i]];

         if (bwlflow[bwname[i]]) {
            split(bwlflow[bwname[i]],auxparam,"/");
            print "tc qdisc add dev "bwa_if" parent "classid[bwname[i]]" handle "leafhandle" sfq divisor "auxparam[2],perturb,limit;
            if (auxparam[1] && auxparam[2]) print "tc filter add dev "bwa_if" protocol ip pref 1 parent "leafhandle": handle "leafhandle" flow hash keys "auxparam[1]" divisor "auxparam[2],perturb;
         }
         else print "tc qdisc add dev "bwa_if" parent "classid[bwname[i]]" handle "leafhandle" sfq "perturb,limit;
      }
      else print "tc qdisc add dev "bwa_if" parent "classid[bwname[i]]" handle "leafhandle" pfifo "limit;
   }

   ## LB rules
   if (countlb > 0) {
      if (ctlbmark < 1) print "iptables -t mangle -A QoS_LBRules -m recent --rcheck --name LBQOS0 "lbtrack" -j RETURN";
      else {
         print "iptables -t mangle -A QoS_LBRules -m connmark ! --mark 0x0 -j CONNMARK --save";
         print "iptables -t mangle -A QoS_LBRules -m connmark ! --mark 0x0 -j RETURN";
      }
      for (i=1; i<=countlb; i++) print "iptables -t mangle -A QoS_LBRules "connew[i]"-m statistic --mode nth --every "countlb" --packet "i-1" -j LB_QOS"i;
      if (ctlbmark < 1) print "iptables -t mangle -A QoS_LBRules -m recent --name LBQOS0 "lbtrack" --remove -j RETURN";
   }
}
