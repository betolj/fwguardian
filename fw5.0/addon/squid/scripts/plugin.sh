#!/bin/bash
#
# - Use this script for plugin manager
# - Disabled plugins will result in denied access
# 
# Author: Humberto L Jucá -  betolj@gmail.com

cmd=$1
plugin=$2
squid=$(which squid)
DIR="/etc/squid/acl/plugin"
#DIR="$(readlink -f "$(dirname $0)"/)/plugin"

# Editor select (for editclient or editdomain options)
[ "$EDITOR" == "" ] || [ "$EDITOR" == "vim" ]  && EDITOR=$(which vim) || EDITOR=$(which $EDITOR)

cladmin() {
   cmd=$1
   case "$cmd" in
      add) [ "$2" == "noreload" ] || [ "$2" == "nosync" ] || [ "$2" == "noauto" ] && touch /tmp/$2 || echo -e "\nERROR: Invalid option!"
      ;;
      del) 
           if [ "$2" == "noreload" ] || [ "$2" == "nosync" ] || [ "$2" == "noauto" ]; then
              [ -f /tmp/nosync ] && [ "$2" == "nosync"] && touch /tmp/plugin.sync
              [ -f /tmp/noauto ] && [ "$2" == "noauto"] && touch /tmp/plugin.sync
              rm -f /tmp/$2 2>/dev/null
           else
              echo -e "ERROR: Invalid option!"
           fi
      ;;
      *)
         echo -e "\nCluster help:"
         echo -e "\n\t./plugin.sh cluster <add|del> noreload            - Add or delete noreload cluster control file"
         echo -e "\t./plugin.sh cluster <add|del> nosync              - Add or delete nosync cluster control file"
         echo -e "\n\t./plugin.sh cluster <add|del> noauto              - Add or delete noauto cluster control file - after delete script will try a new replication\n"
      ;;
   esac
}

authadmin() {
   cmd=$1
   case "$cmd" in
      enable)
         if [ -f "$DIR/../../auth/authmodule" ]; then
            cp -f $DIR/../../auth/options $DIR/../buildauth/ 2>&1 >/dev/null
            cp -f $DIR/../../auth/authpolicy $DIR/../buildauth/ 2>&1 >/dev/null
            cp -f $DIR/../../auth/authmodule $DIR/../buildauth/ 2>&1 >/dev/null
            touch $DIR/../buildauth/enabled
            echo -e "\nINFO: Your rules was applied and enabled!"
         else
            echo -e "\nERROR: Add a auth module first!"
         fi
      ;;
      disable)
         candel=1
	 for line in $(ls $DIR/); 
	 do
	    if [ -d "/etc/squid/acl/plugin/$line" ] && [ "$line" != "available_plugins" ] && [ "$line" != "disable_plugins" ]; then
               if [ "$(readlink -f /etc/squid/acl/plugin/clientaddr_$line)" == "/etc/squid/acl/plugin/available_plugins/user_$line" ]; then
                  candel=0
                  pstats='\E[48;31m'"\033[1m$line\033[0m"
                  printf "Plugin: $pstats\n" ""
               fi
            fi
         done
         if [ "$candel" == "1" ]; then
            echo "# Disabled auth" > $DIR/../buildauth/options
            echo "# Disabled auth" > $DIR/../buildauth/authpolicy
            echo "# Disabled auth" > $DIR/../buildauth/authmodule
            rm -f $DIR/../buildauth/enabled 2>/dev/null
         else
            echo -e "\nERROR: There are plugins working in user mode!"
         fi
         echo -e "INFO: Resetting *authmodule*"
         ls $DIR/../../auth/*.active 2>/dev/null | while read line; do mv $line $(echo $line | sed 's/\.active$//'); done
         rm -f $DIR/../../auth/authmodule 2>/dev/null
      ;;
      add)
         authmod=$2
         if [ -f "$DIR/../../auth/$authmod" ]; then
            if [ "$authmod" == "ntlm" ] || [ "$authmod" == "negotiate" ]; then
               [ "$authmod" == "ntlm" ] && cat $DIR/../../auth/ntlm >> $DIR/../../auth/authmodule || \
                                           cat $DIR/../../auth/negotiate >> $DIR/../../auth/authmodule
            else
               cat $DIR/../../auth/$authmod >> $DIR/../../auth/authmodule
               [ "$authmod" == "basic_ncsa" ] && touch /etc/squid/acl/auth/.ncsa_passwd

               shift 2
               echo "auth_param basic realm $@" >> $DIR/../../auth/authmodule
            fi
            cat $DIR/../../auth/authmodule
            mv $DIR/../../auth/$authmod $DIR/../../auth/$authmod.active 2>/dev/null
         fi
      ;;
      *)
         echo -e "\nAuth help:"
         echo -e "\n\t./plugin.sh auth add <basic_ncsa|basic_ntlm|basic_pam|negotiate|ntlm> [basic realm]    - Add a new authentication support\n"
         echo -e "\t./plugin.sh auth enable                                                                - Enable squid authentication"
         echo -e "\t./plugin.sh auth disable                                                               - Disable and reset squid authentication"
      ;;
   esac
}

pmanager=0
umanager=0
[ "$cmd" == "manage" ] || [ "$cmd" == "permissive-manage" ] && pmanager=1
if [ "$cmd" == "usermanage" ] || [ "$cmd" == "permissive-usermanage" ]; then
   if [ -f "$DIR/../buildauth/enabled" ]; then
      pmanager=1
      umanager=1
   else
      echo -e "\nERROR: Enable auth first!"
      exit
   fi
fi

if [ "$pmanager" == "1" ] || [ "$cmd" == "allow" ]; then
   touch /tmp/plugin.sync
   rm -f $DIR/clientaddr_$plugin 2>/dev/null
   [ -f "$DIR/$plugin/deny" ] && rm -f $DIR/$plugin/deny
   [ -f "$DIR/$plugin/permissive" ] && rm -f $DIR/$plugin/permissive

   # Clientaddr link
   if [ "$pmanager" == "1" ]; then

      [ "$plugin" == "multimedia" ] || [ "$plugin" == "mime_videoaudio" ] && echo -e "\nWARN: Set the same plugin type for multimedia and mime_videoaudio!"
      [ -f $DIR/$plugin/allow ] && rm -f $DIR/$plugin/allow
      if [ "$umanager" == "1" ]; then
         [ -f $DIR/available_plugins/user_$plugin ] && ln -sf $DIR/available_plugins/user_$plugin $DIR/clientaddr_$plugin
      else
         [ -f $DIR/available_plugins/clientaddr_$plugin ] && ln -sf $DIR/available_plugins/clientaddr_$plugin $DIR/clientaddr_$plugin
      fi
      if [ "$cmd" == "permissive-manage" ] || [ "$cmd" == "permissive-usermanage" ]; then
         if [ -f "$DIR/$plugin/pmacl" -a "$umanager" == "0"  ] || [ -f "$DIR/$plugin/upmacl" -a "$umanager" == "1" ]; then
            touch $DIR/$plugin/permissive
            if [ "$umanager" == "1" ]; then
               grep -Fxvf $DIR/$plugin/acl $DIR/$plugin/upmacl >/dev/null 2>/dev/null && cp -f $DIR/$plugin/upmacl $DIR/$plugin/acl
            else
               grep -Fxvf $DIR/$plugin/acl $DIR/$plugin/pmacl >/dev/null 2>/dev/null && cp -f $DIR/$plugin/pmacl $DIR/$plugin/acl
            fi
         else
            echo -e "\nINFO: Unsupported action for plugin $plugin... using 'manage' action!"
         fi
      else
         if [ "$umanager" == "1" ]; then
            grep -Fxvf $DIR/$plugin/acl $DIR/$plugin/ucmacl >/dev/null 2>/dev/null && cp -f $DIR/$plugin/ucmacl $DIR/$plugin/acl
         else
            grep -Fxvf $DIR/$plugin/acl $DIR/$plugin/cmacl >/dev/null 2>/dev/null && cp -f $DIR/$plugin/cmacl $DIR/$plugin/acl
         fi
      fi
   else
      touch $DIR/$plugin/allow
      grep -Fxvf $DIR/$plugin/acl $DIR/$plugin/cmacl >/dev/null 2>/dev/null && cp -f $DIR/$plugin/cmacl $DIR/$plugin/acl
      [ -f $DIR/../networks_allowed ] && ln -sf $DIR/../networks_allowed $DIR/clientaddr_$plugin
   fi

   # Domain link
   rm -f $DIR/domain_$plugin 2>/dev/null
   [ -f $DIR/available_plugins/domain_$plugin ] && ln -sf $DIR/available_plugins/domain_$plugin $DIR/domain_$plugin
else
   [ -f $DIR/$plugin/allow ] && [ "$cmd" != "deny" ] && exit
   data=$(echo $3 | sed 's/\//\\\//g');
   case "$cmd" in
      deny)
         touch /tmp/plugin.sync
	 touch $DIR/$plugin/deny
	 rm -f $DIR/clientaddr_$plugin 2>/dev/null
	 rm -f $DIR/domain_$plugin 2>/dev/null
	 [ -f $DIR/$plugin/allow ] && rm -f $DIR/$plugin/allow
         if [ -f "$DIR/$plugin/permissive" ]; then
            rm -f $DIR/$plugin/permissive
            grep -Fxvf $DIR/$plugin/acl $DIR/$plugin/cmacl >/dev/null 2>/dev/null || cp -f $DIR/$plugin/cmacl $DIR/$plugin/acl
         fi
	 [ -f $DIR/disable_plugins/domain_$plugin ] && ln -sf $DIR/disable_plugins/domain_$plugin $DIR/domain_$plugin
	 [ -f $DIR/disable_plugins/clientaddr_$plugin ] && ln -sf $DIR/disable_plugins/clientaddr_$plugin $DIR/clientaddr_$plugin
      ;;
      addclient)
	 if [ -f $DIR/clientaddr_$plugin ] && [ "$3" != "" ]; then
	    grep -q "^$3\$" "$DIR/clientaddr_$plugin" || echo "$3" >> $DIR/clientaddr_$plugin
	 fi
      ;;
      adddomain)
	 if [ -f $DIR/domain_$plugin ] && [ "$3" != "" ]; then
	    grep -q "^$3\$" "$DIR/domain_$plugin" $DIR/domain_$plugin || echo "$3" >> $DIR/domain_$plugin
	 fi
      ;;
      editclient)
         rlfile=$(readlink -f $DIR/clientaddr_$plugin)
         [ "$3" == "ip" ] && rlfile=$DIR/available_plugins/clientaddr_$plugin
         [ "$3" == "user" ] && rlfile=$DIR/available_plugins/user_$plugin
         if [ -f $rlfile ] && [ ! -f $DIR/$plugin/deny ]; then
            $EDITOR $rlfile
         fi
      ;;
      editdomain)
         if [ -f $DIR/available_plugins/domain_$plugin ] && [ ! -f $DIR/$plugin/deny ]; then
            $EDITOR $DIR/available_plugins/domain_$plugin
         fi
      ;;
      delclient)
	 [ -f $DIR/clientaddr_$plugin ] && echo -e ",g/^$data\$/d\nw\nq" | ed $DIR/clientaddr_$plugin >/dev/null 2>&1
      ;;
      deldomain)
	 [ -f $DIR/domain_$plugin ] && echo -e ",g/^$data\$/d\nw\nq" | ed $DIR/domain_$plugin >/dev/null 2>&1
      ;;
      cluster)
         cladmin $2 $3
      ;;
      auth)
         cmdaux=$2
         shift 2
         authadmin $cmdaux $@
      ;;
      show)
	 [ ! "$2" ] && echo -e "\nPlugin action:" || echo -e "\nFinding plugins for $2:"
	 for line in $(ls $DIR/); 
	 do
	    if [ -d "/etc/squid/acl/plugin/$line" ] && [ "$line" != "available_plugins" ] && [ "$line" != "disable_plugins" ]; then
               if [ ! "$2" ]; then
                  psize=$(echo $line | wc -m)
                  psize="$( expr 40 - $psize )s"
                  if [ -f /etc/squid/acl/plugin/$line/allow ]; then
                     pstats='\E[48;32m'"\033[1mAllow\033[0m"
                     printf "\tPlugin: $line %-$psize \t$pstats\n" ""
                  else
                     if [ -f /etc/squid/acl/plugin/$line/deny ]; then
                        pstats='\E[48;31m'"\033[1mDeny\033[0m"
                        printf "\tPlugin: $line %-$psize \t$pstats\n" ""
                     else
                        [ -f /etc/squid/acl/plugin/$line/permissive ] && \
                            pstats='\E[48;32m'"\033[1mPERMISSIVE-Manage\033[0m" || \
                            pstats='\E[48;30m'"\033[1mManage\033[0m"

                        [ "$(readlink -f /etc/squid/acl/plugin/clientaddr_$line)" == "/etc/squid/acl/plugin/available_plugins/user_$line" ] && pstats="Manage (user)"
                        printf "\tPlugin: $line %-$psize \t$pstats\n" ""
                     fi
                  fi
               else
                  grep -i "^[ |\s]*$2[ |\s]*$" /etc/squid/acl/plugin/clientaddr_$line >/dev/null && echo -e "\tDefined in \E[48;30m\033[1m $line \033[0m" || \
                       if [ -f /etc/squid/acl/plugin/$line/allow ]; then
                           echo -e "\tDefined in \E[48;30m\033[1m $line \033[0m (allowed plugin)"
                       fi
               fi
            fi
         done
      ;;
      reconfigure)
         $squid -k reconfigure 2>/dev/null >/dev/null
      ;;
      *)
         echo -e "\nHelp:"
         echo -e "\n\t./plugin.sh allow <plugin_name>                  - Allow access (made by *networks_allowed ACL*)"
         echo -e "\t./plugin.sh manage <plugin_name>                 - Personalized access to all networks_allowed"
         echo -e "\t./plugin.sh usermanage <plugin_name>             - Personalized access to users in all networks"
         echo -e "\t./plugin.sh permissive-manage <plugin_name>      - Personalized access to blacklist networks (allowed for others)"
         echo -e "\t./plugin.sh permissive-usermanage <plugin_name>  - Personalized access to users in blacklist networks (allowed for others)"
         echo -e "\t./plugin.sh deny <plugin_name>                   - Deny access"
         echo -e "\n\t./plugin.sh reconfigure                          - Squid reconfigure"
         echo -e "\t./plugin.sh show                                 - Show plugin action (allow, deny or manage)"
         echo -e "\n\t./plugin.sh editclient <plugin_name>             - Edit the IP plugin file"
         echo -e "\t./plugin.sh editdomain <plugin_name>             - Edit the domain plugin file"
         echo -e "\n\t./plugin.sh addclient <plugin_name> <ip>         - Add IP address"
         echo -e "\t./plugin.sh adddomain <plugin_name> <domain>     - Add domain"
         echo -e "\t./plugin.sh delclient <plugin_name> <ip>         - Delete IP address"
         echo -e "\t./plugin.sh deldomain <plugin_name> <domain>     - Delete domain"
         echo -e "\n\t./plugin.sh cluster <options>                    - Cluster options. Use [cluster help] for more options."
         echo -e "\t./plugin.sh auth <options>                       - Auth options. Use [auth help] for more options.\n"
         exit
      ;;
   esac
fi

if [ -f /tmp/plugin.sync ]; then
   touch /tmp/fullsync
   echo 0 > $DIR/../cache/syncreload
   rm -f /tmp/plugin.sync 2>/dev/null
fi
