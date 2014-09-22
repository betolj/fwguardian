#!/bin/igawk
{
   # cluster_id <router_id> <node_id>
   # - Set <router_id> to configure the keepalived router_id
   # - Set <node_id> 1 to identify the manager node (define node id in active-active mode too)
   if ($1 == "cluster_id" || $1 == "router_id") {
       syncst=0;
       prback=0;
       activeactive=0;
       print "global_defs {";
       print "     router_id "$2;
       print "}";

       locnode=$3;
   }
   else if ($1 == "mac_type") {
       if ($2 == "vmac" && !activeactive) {
          usevmac=1;
          vmacdif=0;
       }
       else vmacdif=2;
   }
   else if ($1 == "preempt") {
       if (match($2, "^[yY](es|ES)$")) nopreempt=0;
       else nopreempt=1;
   }
   else if ($1 == "sync_state" || $1 == "active_active") {
       if (match($2, "^[yY](es|ES)$") && ctsup) {
          syncst=1;
          if (!activeactive) prback=1;
          system("touch /usr/share/fwguardian/cluster.sync_state");
          if ($1 == "active_active") {
             prback=0;
             usevmac=0;
             vmacdif=2;
             activeactive=1;
          }
       }
       else syncst=0;
   }
   else if (match($1,"^set-(interface|vipconf|vipaddr|condition)$")) {
      if (match($1, "^set-(interface$|vip)")) {
         clpol="";
         disabled=0;
         disabledpol=0;
         disabledpol=fwalias("chkperm", "cluster");
         if (!disabledpol) {
            if ($1 == "set-interface") {
               master=0;
               backup=0;
               ifcount=0;
               vipcount=0;
               clpol="ifcfg";
            }
            else {
               if ($1 == "set-vipconf") clpol="vipconf";
               else if ($1 == "set-vipaddr") clpol="vipaddr";
               else disabledpol=1;
            }
         }
      }
      else if ($1 == "set-condition") fwalias("mkperm", "cluster");
   } 
   else {
     if (!disabledpol) disabled=0;
     disabled=fwalias("chkperm", "cluster");

     if (!disabledpol && !disabled) {

        if (clpol == "vipconf") {
           vipprio=50;
           vipmaster=0;
           vipconfcount=0;
           vipinop[vipcount]=0;
           vipi[vipcount,vipconfcount++]="vrrp_instance VIP_"$2" {";
           vipi[vipcount,vipconfcount++]="   interface "$3;
           vipdev=$3;
           if ($1 == "master" || $1 == "MASTER") {
              master=1;
              vipmaster=1;
              vipi[vipcount,vipconfcount++]="   state MASTER";
              vipname[0, masterct++]=$2;
              oristate="MASTER";
              bckstate="BACKUP";
              if ($5 == "auto") vipprio="100";
              else vipprio=$5;
           }
           else {
              backup=1;
              vipi[vipcount,vipconfcount++]="   state BACKUP";
              vipname[1, backupct++]=$2;
              oristate="MASTERFO";
              bckstate="BACKUP";
              #bckstate="VFAULT";
              if ($5 == "auto") vipprio="50";
              else vipprio=$5;
           }
           vipi[vipcount,vipconfcount++]="   virtual_router_id "$2;
           if (usevmac) {
              vipdev="vrrp."$2;
              vipinop[vipcount]+=2;
              vipi[vipcount,vipconfcount++]="   use_vmac vrrp."$2;
              vipi[vipcount,vipconfcount++]="";
              #vipi[vipcount,vipconfcount++]="   vmac_xmit_base";
           }
           vipi[vipcount,vipconfcount++]="   priority "vipprio;
           vipi[vipcount,vipconfcount++]="   advert_int "$4;
           if (activeactive || !vipmaster) garpd=1;
           else garpd=2;
           vipi[vipcount,vipconfcount++]="   garp_master_delay "garpd;
           vipi[vipcount,vipconfcount++]="   authentication {";
           vipi[vipcount,vipconfcount++]="       auth_type PASS";
           vipi[vipcount,vipconfcount++]="       auth_pass "$6;
           vipi[vipcount,vipconfcount++]="   }";
           if (ifcount > 0) {
              vipi[vipcount,vipconfcount++]="   track_interface {";
              vipi[vipcount,vipconfcount++]="   }";
           }
           else {
              vipi[vipcount,vipconfcount++]="";
              vipi[vipcount,vipconfcount++]="";
           }
           vipi[vipcount,vipconfcount++]="   virtual_ipaddress {";
           vipi[vipcount,vipconfcount++]="   }";
           if (nopreempt || !vipmaster) vipi[vipcount,vipconfcount++]="   nopreempt";
           else vipi[vipcount,vipconfcount++]="   preempt_delay 1";
           if ((vipdefgw[$3] || vipdefgw["lo"]) && !vipgw) {
              vipgw++;
              vipinop[vipcount]+=3;
              if (vipdefgw["lo"]) setvipdef=vipdefgw["lo"]" src "vipdefsrc["lo"];
              else setvipdef=vipdefgw[$3]" src "vipdefsrc[$3]" dev "vipdev;

              vipi[vipcount,vipconfcount++]="   virtual_routes {";
              vipi[vipcount,vipconfcount++]="       default via "setvipdef;
              vipi[vipcount,vipconfcount++]="   }";
           }
           vipi[vipcount,vipconfcount++]="   notify_master \"/usr/local/bin/vmac_tweak.sh "$2" "$3" "oristate"\"";
           vipi[vipcount,vipconfcount++]="   notify_backup \"/usr/local/bin/vmac_tweak.sh "$2" "$3" "bckstate"\"";
           vipi[vipcount,vipconfcount++]="   notify_fault  \"/usr/local/bin/vmac_tweak.sh "$2" "$3" VFAULT\"";
           vipi[vipcount,vipconfcount++]="}";
           if (force_vipbase[$3]) vipbase[$3] = force_vipbase[$3];
           else if ($2 < vipbase[$3] || !vipbase[$3]) vipbase[$3]=$2;
           vipiid[$2]=vipcount;
           vipif[vipcount]=$3;
           vipcount++;
        }
        else if (clpol == "vipaddr") {
           split($3, auxparam, ",");
           if ($1 == vipif[vipiid[$2]] && !activeactive) {
              if (usevmac) auxeth="dev vrrp."$2;
              else auxeth="";
           }
           else auxeth="dev "$1;
           if (!vipifsync[$1]) {
              vipifsync[$1]=1;
              if (activeactive) {
                 system("echo \'"$1" "locnode"\' >> /usr/share/fwguardian/cluster.prerules");
                 if (vipbase[$1]) system("echo \'"$1" "vipbase[$1]"\' >> /usr/share/fwguardian/cluster.multicastmac");
              }
              system("echo "$1" "$3" >> /usr/share/fwguardian/cluster.vrrp");
              if (usevmac && !ifvmac) {
                 ifvmac = 1;
                 system("echo vrrp+ "$3" >> /usr/share/fwguardian/cluster.vrrp");
              }
           }
           for (i in auxparam) vipaddr[vipiid[$2], vipaddrcount[vipiid[$2]]++]=auxparam[i]" "auxeth;
        }
        else if (clpol == "ifcfg") {
           if (match($2, ":")) sub(":.*","", $2);
           if ($1 == "monitor") trackif[ifcount++]=$2;
           else if ($1 == "heartbeat") system("echo \'"$2" "$3" "$4"\' >> /usr/share/fwguardian/cluster.heartbeat");
           else if ($1 == "set_maddr") force_vipbase[$2]=$3;
           else if ($1 == "defaultgw") {
              vipdefgw[$2]=$4;
              vipdefsrc[$2]=$3;
              system("touch /usr/share/fwguardian/cluster.defaultgw");
           }
        }
     }
   }
}
