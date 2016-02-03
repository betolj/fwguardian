#!/usr/bin/perl

#Rev.2 - Version 5.0

# Make a HTML interface or network SELECT
sub selifnet {
   my $tsel = shift;
   my @auxif = sort @fwifs;
   if ($tsel eq "if") {
     foreach (@auxif) {
        $_ =~ s/\n//;
        print FILE "<OPTION value=\"$_\">$_</OPTION>";
        print FILE "<OPTION value=\"$_+\">$_+</OPTION>" if ($_ !~ /\+/);
        print FILE "<OPTION value=\"\!$_\">\!$_</OPTION>" if ($_ !~ /^\!/);
     }
     print FILE "<OPTION value=\"tun+\">tun+</OPTION>" if ($_ !~ /^tun\+/);
     print FILE "<OPTION value=\"ppp+\">ppp+</OPTION>" if ($_ !~ /^ppp\+/);
   }
   else {
     foreach (@netalias) {
        $_ =~ s/\n//;
        print FILE "<OPTION value=\"$_\">$_</OPTION>";
     }
   }
}

# Make a jqGrid interface or network SELECT
sub selGridifnet {
   my $value;
   my $tsel = shift;
   my @auxif = sort @fwifs;
   $value = "any:any";
   if ($tsel eq "if") {
      $value = "any:any";
      foreach (@auxif) {
         $_ =~ s/\n//;
         if ($_ !~ /^ifb/) {
            my $line = "$_:$_";

            $line = "$line;$_+:$_+" if ($_ !~ /\+/);
            $line = "$line;\!$_:\!$_" if ($_ !~ /^\!/);
            $value = "$value;$line";
         }
      }
      $value = "$value;tun+:tun+";
      $value = "$value;ppp+:ppp+";
   }
   else {
     foreach (@netalias) {
        if ($tsel eq "net" || ($tsel eq "ipnet" && $_ !~ /^iprange/)) {
           $_ =~ s/\n//;
           $_ =~ s/^iprange:// if ($tsel eq "net" && $_ =~ /^iprange/);
           my $line = "$_:$_";
           $value = "$value;$line";
        }
     }
   }
   return $value;
}

# "Calc white spaces for text fields"
sub calc_bl {
   my $field = shift;
   my $len = shift;
   my $blank = "";
   for (my $i=length($field); $i<=$len; $i++) {
      $blank="$blank ";
   }
   return $blank
}

# "String convert"
sub str_conv {
   my $line = shift;
   $line =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg  if ($line);
   return $line;
}

# "Try to find dhcpd.lease file"
sub dhcpConf {
  my @server = ();
  my $dhcp_server = "";
  $server[0]="dhcpd";
  $server[1]="dhcpd3";
  for (my $i=0; $i<2; $i++) {
     $dhcp_server = "";
     $dhcp_server = `which $server[$i] | tr -d '\\n'`;
     $i = 2 if (-e "$dhcp_server" && $dhcp_server =~ /\/[s]*((bin|sbin)|(\/usr\/(bin|sbin)))\//);
  }

  my $lease = `strings $dhcp_server | grep -v dhcpd6 | grep "^/var/.*/dhcpd[0-9]*.leases" | tr -d '\\n'`;
  $lease = "/var/lib/dhcp3/dhcpd.leases" if (not -e "$lease");
  return $lease;
}


# Write a shadow title
sub menustyle {

  my $menutitle = shift;
  
my $mstyle = << "FontSw";
<style type="text/css">
<!--
#text{
        font-size: 25px;
        color: #800000;
        content: "$menutitle";
        display: block;
        line-height: 1em;
        height: 1.5em;
        padding-top:0.4cm;
/*
        filter: Shadow(Color=#1C4059, Direction=135, OffX=1, OffY=1, Positive=1, Strength=4);
        text-shadow: #1C4059 0.1em 0.1em 0.2em;
*/
        background-color: transparent;
        white-space: nowrap;
}
div.chsform,
#chcondition {
    position: absolute;
    width: 400px;
    height: 80px;
    left: 50%;
    top:50%;
    margin-left: -200px;
    margin-top: -125px;
    border: 1px solid;
    padding:5px;
    background-color: #eee;
	padding: 20px;
	margin-top: 10px;
	margin-right: 20px;
    text-align: center;
    box-shadow: 10px 10px 5px black;
    -moz-box-shadow: 10px 10px 5px black;
    -webkit-box-shadow: 10px 10px 5px black;
    filter: progid:DXImageTransform.Microsoft.dropShadow(color=black, offX=5, offY=5, positive=true);
    z-index:2;
    display:none;
}
#chwait {
    position: absolute;
    width: 340px;
    height: 65px;
    left: 50%;
    top:50%;
    margin-left: -200px;
    margin-top: -125px;
    border: 1px solid;
    padding:5px;
    background-color: #eee;
	padding: 20px;
	margin-top: 10px;
	margin-right: 20px;
    text-align: center;
    box-shadow: 10px 10px 5px black;
    -moz-box-shadow: 10px 10px 5px black;
    -webkit-box-shadow: 10px 10px 5px black;
    filter: progid:DXImageTransform.Microsoft.dropShadow(color=black, offX=5, offY=5, positive=true);
    z-index:3;
    display:none;
}
-->
</style>
FontSw

  return $mstyle;
}

# Write check conditions
sub ckcond {
    my $ckname = shift;
    my @msg = ("", "");
    print FILE "<SELECT name=\"$ckname\" style=\"width:120; Font-Family: Arial, Helvetica;\">";
    $msg[0] = "Checar";
    $msg[1] = "Check";
    print FILE "<OPTION value=\"\">--- $msg[$FW_LANG] ---</OPTION>";
    $msg[0] = "desabilitado";
    $msg[1] = "disabled";
    print FILE "<OPTION value=\"disabled\">$msg[$FW_LANG]</OPTION>";
    foreach my $lschk (@fwchk) {
       $lschk =~ s/\n//;
       print FILE "<OPTION value=\"$lschk\">$lschk</OPTION>";
    }
    print FILE "</SELECT>";
}

# "POST /admin/chinfra.cgi"
sub chinfra {
    my $s = shift;
    my $infratype = shift;

    my $rlfw = 0;
    my $canSync = 0;
    my $txtvalue = "";
    my $allow = 0;
    my @msg = ("", ""), @msg2 = ("", "");
    my @auxopt = ("IFWAN", "IFLAN", "local_ports", "profile", "default_profile", "TRUST", "DNS", "conntrack");
    read_fwcfg;

    my $res = HTTP::Response->new();

    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && ($canch == 1 || $infratype eq "local")) {
       # Parsing json response (sorting by ID)
       my %json = ();
       my %groupData = ();
       my $group = "";
       $txtvalue = "NO";
       
       foreach my $auxjson (split /"[0-9]+":/, $s) {
          $auxjson =~ s/\[//g;
          $auxjson =~ s/\]//g;
          $auxjson =~ s/{//g;
          $auxjson =~ s/}//g;
          $auxjson =~ s/,$//;

          if ($auxjson && $auxjson ne "") {
             %json = ();
             foreach my $auxjson2 (split/,/, $auxjson) {
                $auxjson2 =~ s/\"//g;
                $auxjson2 =~ s/\'//g;
                my @dvalue = ();
                @dvalue = split /:/, $auxjson2;
                if ($dvalue[1] && $dvalue[0] && $dvalue[1] !~ / & | && |;|\|/) {
                   if ($infratype eq "local") {
                      $allow = 0;
                      if ($dvalue[1] && ($dvalue[0] =~ /^(host(Name|Ip)|chk(Ipv6|PrefIpv4|DomCache)|domain(Resolv|Server|Search|Name)|realmName|dc(Login|Passwd|Type|Address)|res(Attempts|Timeout))$/)) {
                          if ($dvalue[0] =~ /^(domain(Resolv|Server|Search))$/) {
                             if ($json{$dvalue[0]}) {
                                $json{$dvalue[0]} = "$json{$dvalue[0]} $dvalue[1]";
                             }
                             else {
                                $json{$dvalue[0]} = "$dvalue[1]";
                             }
                          }
                          else {
                             $json{$dvalue[0]} = str_conv($dvalue[1]);
                          }
                          $json{$dvalue[0]} = "no" if ($dvalue[1] =~ /^((n|N)o|false)$/);
                          $json{$dvalue[0]} = "yes" if ($dvalue[1] =~ /^((y|Y)es|true)$/);
                      }
                   }
                   elsif ($infratype eq "support") {
                      $allow = 1;
                      if ($dvalue[0] =~ /^(Group|gOption|Control|id)$/) {
                         $json{$dvalue[0]} = $dvalue[1];
                      }
                      elsif ($dvalue[0] eq "ckValue") {
                         $json{$dvalue[0]} = "no";
                         $json{$dvalue[0]} = "yes" if ($dvalue[1] =~ /^(y|Y)es$/);
                      }
                   }
                   elsif ($infratype eq "options") {
                      $allow = 1;
                      if ($dvalue[1] && ($dvalue[0] =~ /^(IFLAN|IFWAN|local_ports|profile|default_profile|TRUST|DNS|conntrack)$/)) {
                         if ($json{$dvalue[0]}) {
                            my $tmpaux = str_conv($dvalue[1]);
                            $json{$dvalue[0]} = "$json{$dvalue[0]} $tmpaux";
                         }
                         else {
                            $json{$dvalue[0]} = str_conv($dvalue[1]);
                         }
                         $json{$dvalue[0]} = "no" if ($dvalue[1] =~ /^((n|N)o|false)$/);
                         $json{$dvalue[0]} = "yes" if ($dvalue[1] =~ /^((y|Y)es|true)$/);
                      }
                   }
                }
             }

             if ($allow == 1) {
                # fwguardian.conf rules
                if ($infratype eq "options") {
                   foreach my $fRules (@auxopt) {
                      if ($json{$fRules}) {
                         $canSync = 1 if ($canSync == 0);
                         $auxentry = "$fRules $json{$fRules}";

                         # network options
                         push(@{$groupData{'opt'}}, $auxentry);
                      }
                   }
                }
                else {
                   if ($json{'Group'} =~ /^(web|network|security|kill|log)$/) {
                      $canSync = 1;
                      $auxentry = "$json{'gOption'} $json{'ckValue'}";

                      # support rules
                      $group = $json{'Group'};
                      push(@{$groupData{$group}}, $auxentry);
                   }
                }
             }
          }
       }

       if ($canSync == 1) {
          open FILE, ">$FW_DIR/fwguardian.conf";

          # Writing support options
          my @fwgroup = ("web", "network", "security", "kill", "log");
          print FILE "\n### General options (Web, Network, security and log)\n";
          foreach my $fRules (@fwgroup) {
             print FILE "\n# $fRules";
             if ($infratype eq "options") {
                foreach my $aRules (@{$infrarules{"$fRules"}}) {
                   $aRules =~ s/\n//;
                   $aRules =~ s/\\"/\"/g;
                   $aRules =~ s/\\'/\'/g;
                   print FILE "\n$aRules";
                }
             }
             else {
                foreach my $aRules (@{$groupData{"$fRules"}}) {
                   $aRules =~ s/\n//;
                   $aRules =~ s/\\"/\"/g;
                   $aRules =~ s/\\'/\'/g;
                   print FILE "\n$aRules";
                }
             }
             print FILE "\n";
          }

          # Writing main editable settings
          print FILE "\n\n### Main editable settings\n";
          if ($infratype eq "options") {
             open TFILE, ">$FW_DIR/accesslist/trust";
             foreach my $fRules (@{$groupData{'opt'}}) {
                $fRules =~ s/\n//;
                $fRules =~ s/\\"/\"/g;
                $fRules =~ s/\\'/\'/g;
                if ($fRules =~ /^TRUST /) {
                   $fRules =~ s/TRUST\s+//;
                   $fRules =~ s/\s/\n/g;
                   print TFILE "$fRules\n";
                }
                else {
                   print FILE "\n$fRules\n";
                }
             }
             print FILE "\n";
             close(TFILE);
          }
          else {
             foreach my $fRules (@fwcfgopt) {
                $fRules =~ s/\n//;
                $fRules =~ s/\\"/\"/g;
                $fRules =~ s/\\'/\'/g;
                print FILE "\n$fRules";
                foreach my $aRules (@{$fwcfg{$fRules}}) {
                   print FILE " $aRules";
                }
                print FILE "\n";
             }
          }

          close(FILE);
          $txtvalue="OK";

          rsyncupdate("$FW_DIR/fwguardian.conf", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }

       if ($infratype eq "local") {
          # Change firewall hostname and pref address
          system("echo $json{'domainName'} > /etc/bind/localdomains");
          $json{'domainName'} =~ s/\s+.*//g;

          my $fqdnhost = $json{'hostName'};
          $fqdnhost = "$fqdnhost\.$json{'domainName'}" if ($json{'domainName'} && $json{'domainName'} ne "");
          system("$FW_DIR/webauth/chsystem", "/etc/hosts", "update-host", "$fqdnhost $json{'hostIp'}") if ($json{'hostName'} && $json{'hostName'} =~ /[a-zA-Z0-9]+/ && $json{'hostIp'} ne "");

          #IPv6 support
          if ($json{'chkIpv6'} && $json{'chkIpv6'} eq "yes") {
             system("$FW_DIR/webauth/chsystem", "/etc/hosts", "disable-ipv6", "yes");
          }
          else {
             system("$FW_DIR/webauth/chsystem", "/etc/hosts", "enable-ipv6", "$json{'chkPrefIpv4'}");
          }

          # DNS (resolver and server)
          $json{'domainName'} =~ s/\s//g;
          $json{'domainName'} = "none" if ($json{'domainName'} eq "");
          $json{'domainSearch'} = "none" if ($json{'domainSearch'} eq "");
          system("$FW_DIR/webauth/chsystem", "/etc/resolv.conf", "update-resolv", "$json{'domainName'}", "$json{'resTimeout'}", "$json{'resAttempts'}", "$json{domainSearch}");
          $json{'chkDomCache'} = "yes" if ($json{'domainResolv'} =~ /[\s]*127\.0\.0\./);
          if ($json{'chkDomCache'} eq "no") {
             $json{'domainResolv'} = "8.8.8.8 8.8.4.4" if ($json{'domainResolv'} eq "");
             foreach (split /\s+/, $json{'domainResolv'}) {
                system("$FW_DIR/webauth/chsystem", "/etc/resolv.conf", "add-nameserver", "$_") if ($_ ne "");
             }
          }
          else {
             $json{'chkIpv6'} = "no" if (!$json{'chkIpv6'});
             system("$FW_DIR/webauth/chsystem", "/etc/resolv.conf", "add-nameserver", "127.0.0.1");
             system("$FW_DIR/webauth/chsystem", "/etc/resolv.conf", "add-tmpnserver", "$json{'domainResolv'}");
             system("$FW_DIR/webauth/chsystem", "/etc/resolv.conf", "add-tmpdserver", "$json{'domainServer'}") if ($json{'domainServer'} ne "" && $json{'domainName'} ne "none");
             system("$FW_DIR/webauth/chsystem", "/etc/bind/named.conf.options", "update-nameoptions", "$FW_DIR/addon/named.conf", "$json{'chkIpv6'}", "$json{'domainName'}", "$json{'resTimeout'}");
          }

          # Windows auth
          my $auxdtype = "none";
          ($auxdtype, undef) = split /\s/, `cat $FW_DIR/addon/dctype | tr -d '\\n'` if (-e "$FW_DIR/addon/dctype");
          if ($json{'dcType'} ne "none") {
             system("kdestroy 2>/dev/null");

             if ($json{'domainName'} && $json{'domainName'} ne "none" && $auxdtype ne $json{'dcType'}) {
                my $dcserver = "";
                $dcserver = $json{'dcAddress'} if ($json{'dcAddress'});
                ($dcserver, undef) = split /\s+/, $dcserver, 2;
                $dcserver = "all" if ($dcserver eq "" || $dcserver eq "*" || $dcserver eq "0.0.0.0");

                $json{'realmName'} =~ s/\s//g;
                $json{'realmName'} = $json{'domainName'} if ($json{'realmName'} eq "");
                system("$FW_DIR/webauth/chsystem", "/etc/samba/smb.conf", "dc-join", "$FW_DIR", "$json{'dcType'}", "$json{'domainName'}", "$json{'realmName'}", "$json{'dcLogin'}", "$json{'dcPasswd'}", "$dcserver", "$json{'dcAddress'}") if ($json{'dcLogin'} ne "" && $json{'dcPasswd'} ne "");
             }
          }
          else {
             system("echo 'none' > $FW_DIR/addon/dctype");
          }

          $txtvalue="OK";
       }
    }
    else {
       my $rtime = 2;
       if ($canch == 1) {
          $msg[0] = "Recarregando as regras de firewall!";
          $msg[1] = "Reloading firewall rules!";
          $msg2[0] = "<font size=\'2\'>Recarregando todas as regras...</font>";
          $msg2[1] = "<font size=\'2\'>Full reloading...</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "<font size=\'2\'>$msg2[$FW_LANG]</font>");

          system("$FW_DIR/fwguardian --ignore-cluster 1>&2 2>/dev/null &") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
          system("$FW_DIR/fwguardian --ignore-webserver 1>&2 2>/dev/null &");
          system("$FW_DIR/fwguardian 1>&2 2>/dev/null &");

          rsyncupdate("$file_cfg{'fwguardian.conf'}", "all", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
       else {
          $rtime = 0;
       }
       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/infra.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page infra.html"
sub get_global {
    my $htmlfile="$HTMLDIR/admin/dynhttp/infra.html";
    read_fwcfg;
    read_profiles;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making infra.html
    open FILE, ">$htmlfile";

print FILE << "javascript";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />

  <link href="/css/csstab.css" type="text/css" rel="stylesheet" />
  <link href="/css/ui.jqgrid.css" type="text/css" rel="stylesheet" />
  <link href="/css/jquery-ui.css" type="text/css" rel="stylesheet" />
  <link href="/css/multi-select.css" type="text/css" media="screen" rel="stylesheet" />
  <link href="/css/select2.css" type="text/css" media="screen" rel="stylesheet" />

  <style type="text/css">
    html, body {
       margin: 0;
       padding: 0;
    }
    .ui-jqgrid .ui-jqgrid-htable th div 
    { 
       height: auto; 
       padding: 5px 0px;
       font-size: 12px;
    }
    .ui-jqgrid .ui-pg-table 
    { 
       font-size: 12px;
       color: #2e6e9e;
    }
    .ui-jqgrid .ui-state-highlight td {
       font-size: 13px;
       color: Black;
       background-color: #A4A4A4;
    }
    .ui-jqgrid
    { 
       font-size: 12px;
       color: #2e6e9e;
    }
    .uibt
    {
       font-size: 12px;
       padding: 1px;
    }
    .uibt:hover
    {
       font-size: 12px;
       color: green;
       padding: 0;
    }
    .uibt_em
    {
       font-size: 12px;
       padding: 1px;
    }
    .uibt_em:hover
    {
       font-size: 12px;
       color: red;
       padding: 0;
    }
    .select2-search { font-size:small; }
    .select2-search input { background-color: #A4A4A4; font-size:small; }
    .select2-results { font-size:small; }

  </style>

  <script type="text/javascript" src="/js/jquery-1.7.2.min.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.core.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.widget.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.button.js"></script>
  <script type="text/javascript" src="/js/jquery.multi-select.js"></script>
  <script type="text/javascript" src="/js/select2.min.js"></script>
  <script type="text/javascript" src="/js/i18n/grid.locale-en.js"></script>
  <script type="text/javascript" src="/js/i18n/grid.locale-pt-br.js"></script>
  <script type="text/javascript" src="/js/i18n/select2_locale_en.js.template"></script>
  <script type="text/javascript" src="/js/i18n/select2_locale_pt-BR.js"></script>
  <script type="text/javascript" src="/js/jquery.jqGrid.min.js"></script>
  <script type="text/javascript" src="/admin/js/gridctl.js"></script>
  <script type="text/javascript">
        jQuery.jgrid.no_legacy_api = true;
        jQuery.jgrid.useJSON = true;

        \$(function() {
           \$(".uibt" ).button();
           \$(".uibt_em" ).button();
           \$("#btsav1").click(function() {
                 document.fInfra.savegd1.click();
                 return false;
           });
           \$("#btsav2").click(function() {
                 document.fInfra.savegd2.click();
                 return false;
           });
           \$("#btsav3").click(function() {
                 document.fInfra.savegd3.click();
                 return false;
           });
           \$("#btcan1").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btcan2").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btcan3").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btrel1").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.fiInfra1.ReloadFw.click();
                 return false;
           });
           \$("#btrel2").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.fiInfra2.ReloadFw.click();
                 return false;
           });
           \$("#btrel3").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.fiInfra3.ReloadFw.click();
                 return false;
           });

           \$("#iflan").select2();
           \$("#ifwan").select2();
           \$("#lport").select2();
           \$("#dprof").select2();
           \$("#hIp").select2();
           \$("#dType").select2();

           \$( "input[type=button]" ).button().css('font-size', '12px');
        });

  </script>

  <script type="text/javascript">
     jQuery(document).ready(function(){

        // Multi-select jquery
        \$('#conn-select').multiSelect({
javascript
$msg[0]="Modulos suportados";
$msg[1]="Supported modules";
print FILE << "javascript";
           selectableHeader: "<div class='custom-header' style='background-color:#A4A4A4; color:white; text-align:center; font-size:13px'>$msg[$FW_LANG]</div>",
javascript
$msg[0]="Habilitados";
$msg[1]="Enabled";
print FILE << "javascript";
           selectionHeader: "<div class='custom-header' style='background-color:#A4A4A4; color:white; text-align:center; font-size:13px'>$msg[$FW_LANG]</div>"
        });
        \$('#conn-select').multiSelect({ keepOrder: true });

        // Rules array
        var saveall = 0;
        var rulesCt = 0;
        var rulesGrid = new Array();         // Main data
        var newRow = new Array();

        // Make jqgrid
        var scrollPosition = 0;
        jQuery("#fwInfraGrid").jqGrid({
           url:'/admin/getinfra.json',
           datatype: "json",
           height: \$(window).height() - 310,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
    print FILE "           colNames:['ID', 'Politica', 'Opção', 'Valor', 'Descrição', 'Control' ],\n";
}
else {
    print FILE "           colNames:['ID', 'Policy', 'Option', 'Value', 'Description', 'Control' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id', sortable:false, width: 30, sorttype: "int", key: true },
              { name:"Group",   index:'Group', hidden:true,  width:30 },
              { name:"gOption", index:'gOption', sortable:false, editable:false, width:280 },
              { name:"ckValue", index:'ckValue',  sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"yes:no"}, width:80 },
              { name:"Desc",    index:'Desc',  sortable:false, editable:false, dataType:'string', width:540 },
              { name:"Control", index:'Control', sortable:false,  editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 }
           ],
           pager: '#pfwInfraGrid',
           editurl: 'clientArray',
           rowNum: '',
           rowList: [],
           sortname: 'id',
           pgbuttons: false,
           pgtext: null,
           gridview: true,
           viewrecords: false,
           sortable: true,
           loadonce: true,
           shrinkToFit: false,
           grouping:true,
           ondblClickRow: function (selid, iRow,iCol) {
              editRow(jQuery("#fwInfraGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "infra");
              newRow = updnewRow();
           },
           groupingView : {
              groupField : ['Group'],
              groupColumnShow : [false],
              groupCollapse : true,
              groupDataSorted : false,
              groupSorted : false,
              groupText : ['<b><FONT color="Black">{0}</b>  {1}</FONT>']
           },
           gridComplete: function(data, response) {
              rulesGrid=GridComplete(jQuery("#fwInfraGrid"), rulesGrid, rulesCt, saveall, "infra");

              rulesCt++;
              jQuery("#fwInfraGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Opções de rede, segurança e logs";
$msg[1] = "Network, Security and log options";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#fwInfraGrid").css('font-size', '13px');
        jQuery("#fwInfraGrid").jqGrid('navGrid',"#pfwInfraGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Edit button
        \$("#fwInfraGrid").jqGrid('navButtonAdd','#pfwInfraGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#fwInfraGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "infra");
              newRow = updnewRow();
           }
        });

        // Saving all rows in click event
        jQuery("#savegd3").click( function() {
javascript
$msg[0] = "INFO: Definições atualizadas com sucesso!";
$msg[1] = "INFO: Settings updated successfully!";
print FILE << "javascript";
           saveall = 1;
           saveAll(jQuery("#fwInfraGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "infra", "/admin/getinfra.json", "/admin/chinfrasup.cgi");
           newRow = updnewRow();
           if (newRow.length < 1) rulesCt = 0;
        });

        // Grid resize
        \$(window).bind('resize', function() {
            \$("#jqgrid").setGridWidth(\$(window).width() - 120);
        }).trigger('resize');

    });

  </script>

<script type="text/javascript">
<!--
  function newinfra(itype) {
    var ninput="";
    var seldoc = document.fiInfra2.DnsLs;
    if (itype == "trust") {
      seldoc = document.fiInfra2.TrustLs;
javascript
$msg[0] = "Por favor entre com o endereço IP administrativo!";
$msg[1] = "Please enter the admin IP address.!";
  print FILE << "javascript";
      ninput=prompt("$msg[$FW_LANG]","127.0.0.1");
    }
    else {
javascript
$msg[0] = "Por favor entre com o servidor DNS!";
$msg[1] = "Please enter with DNS server!";
  print FILE << "javascript";
      ninput=prompt("$msg[$FW_LANG]","127.0.0.1");
    }

    if (ninput.length > 6 || (ninput === "0/0" && itype === "dns")) {
       var rules = seldoc.length;

       var canadd = 1;
       for (var i = 0; i < seldoc.length ; i++) if (seldoc[i].value == ninput) {
          canadd = 0;
          i = seldoc.length;
       }

       if (ninput !== null) {
          if (canadd) seldoc.options[rules] = new Option(ninput, ninput, true, true);
javascript
$msg[0] = "Este registro já existe!";
$msg[1] = "This record exist!";
print FILE << "javascript";
          else alert("$msg[$FW_LANG]");
       }
    }
  }

  function delinfra(itype) {
    var seldoc = document.fiInfra2.DnsLs;
    if (itype == "trust") seldoc = document.fiInfra2.TrustLs;

    var rules = seldoc.length;
    var ruleid = seldoc.selectedIndex;
    if (ruleid > -1) {
      var selval = seldoc[ruleid].value;
      if (selval) {
         seldoc[ruleid] = null;
         if (ruleid < rules - 1) {
           if (seldoc[ruleid].value) seldoc[ruleid].selected = true;
           else seldoc[ruleid-1].selected = true;
         }      
         else seldoc[ruleid-1].selected = true;
      }
javascript
$msg[0] = "ALERTA... \\nRemoção inválida!";
$msg[1] = "WARNING...\\nInvalid delete!";
print FILE "    else alert(\"$msg[$FW_LANG]\");\n";
print FILE "  }\n";
$msg[0] = "ALERTA... \\nNada para remover!";
$msg[1] = "WARNING...\\nNothing to delete!";
  print FILE "  else alert(\"$msg[$FW_LANG]\");\n";
  print FILE << "javascript";
  }

  function jstype1(cktype, value) {
    if (cktype == "hname") this.hostName = value;
    else if (cktype == "hip") this.hostIp = value;
    else if (cktype == "ckipv6") this.chkIpv6 = value;
    else if (cktype == "dmresolv") this.domainResolv = value;
    else if (cktype == "dmserver") this.domainServer = value;
    else if (cktype == "dmsearch") this.domainSearch = value;
    else if (cktype == "dmname") this.domainName = value;
    else if (cktype == "dmrealm") this.realmName = value;
    else if (cktype == "ckpref4") this.chkPrefIpv4 = value;
    else if (cktype == "dtype") this.dcType = value;
    else if (cktype == "daddress") this.dcAddress = value;
    else if (cktype == "rattempts") this.resAttempts = value;
    else if (cktype == "dlogin") this.dcLogin = value;
    else if (cktype == "dpasswd") this.dcPasswd = value;
    else if (cktype == "rtimeout") this.resTimeout = value;
    else if (cktype == "ckdmcache") this.chkDomCache = value;
  }

  function saveInfra1() {
    var seldoc="";
    var docData = new Array();

    docData.push(new jstype1('hname', encodeHtml(document.getElementById('hName').value)));
    seldoc = document.getElementById('hIp');
    for ( var i=0; i<seldoc.length; i++ ) if (seldoc[i].selected) docData.push(new jstype1('hip', encodeHtml(seldoc[i].value)));
    docData.push(new jstype1('ckipv6', document.getElementById('ckIpv6').checked));
    docData.push(new jstype1('dmresolv', document.getElementById('dmResolv').value));
    docData.push(new jstype1('dmserver', document.getElementById('dmServer').value));
    docData.push(new jstype1('dmsearch', document.getElementById('dmSearch').value));
    docData.push(new jstype1('dmname', document.getElementById('dmName').value));
    docData.push(new jstype1('dmrealm', document.getElementById('dmRealm').value));
    docData.push(new jstype1('ckpref4', document.getElementById('ckPref4').checked));
    seldoc = document.getElementById('dType');
    for ( var i=0; i<seldoc.length; i++ ) if (seldoc[i].selected) docData.push(new jstype1('dtype', encodeHtml(seldoc[i].value)));
    docData.push(new jstype1('daddress', document.getElementById('dAddress').value));
    docData.push(new jstype1('rattempts', document.getElementById('rAttempts').value));
    docData.push(new jstype1('dlogin', document.getElementById('dLogin').value));
    docData.push(new jstype1('dpasswd', document.getElementById('dPasswd').value));
    docData.push(new jstype1('rtimeout', document.getElementById('rTimeout').value));
    docData.push(new jstype1('ckdmcache', document.getElementById('ckDomCache').checked));

    // POST ajax
    document.getElementById('chwait').style.display = 'block';
    jQuery.ajax({
        url         : '/admin/chinfraloc.cgi'
        ,type        : 'POST'
        ,cache       : false
        ,data        : JSON.stringify(docData)
        ,contentType : 'application/json; charset=utf-8'
        ,async: false
        ,success: function(data) {
              document.getElementById('chwait').style.display = 'none';
javascript
$msg[0] = "INFO: Definições atualizadas com sucesso!";
$msg[1] = "INFO: Settings updated successfully!";
print FILE "                 alert(\"$msg[$FW_LANG]\");\n";
print FILE << "javascript";
        }
    });
  }

  function jstype2(cktype, value) {
    if (cktype == "lan") this.IFLAN = value;
    else if (cktype == "wan") this.IFWAN = value;
    else if (cktype == "lport") this.local_ports = value;
    else if (cktype == "eprof") this.profile = value;
    else if (cktype == "dprof") this.default_profile = value;
    else if (cktype == "trustls") this.TRUST = value;
    else if (cktype == "dnsls") this.DNS = value;
    else if (cktype == "connselect") this.conntrack = value;
  }

  function saveInfra2() {
    var seldoc="";
    var docData = new Array();

    seldoc = document.getElementById('ifwan');
    for ( var i=0; i<seldoc.length; i++ ) if (seldoc[i].selected) docData.push(new jstype2('wan', encodeHtml(seldoc[i].value)));
    seldoc = document.getElementById('iflan');
    for ( var i=0; i<seldoc.length; i++ ) if (seldoc[i].selected) docData.push(new jstype2('lan', encodeHtml(seldoc[i].value)));
    docData.push(new jstype2('lport', encodeHtml(document.getElementById('lport').value)));
    docData.push(new jstype2('eprof', document.getElementById('eprof').checked));
    docData.push(new jstype2('dprof', encodeHtml(document.getElementById('dprof').value)));

    seldoc = document.fiInfra2.TrustLs;
    for ( var i=0; i<seldoc.length; i++ ) docData.push(new jstype2('trustls', encodeHtml(seldoc[i].value)));
    seldoc = document.fiInfra2.DnsLs;
    for ( var i=0; i<seldoc.length; i++ ) docData.push(new jstype2('dnsls', encodeHtml(seldoc[i].value)));
    seldoc = document.getElementById('conn-select');
    for ( var i=0; i<seldoc.length; i++ ) if (seldoc[i].selected) docData.push(new jstype2('connselect', encodeHtml(seldoc[i].value)));

    // POST ajax
    document.getElementById('chwait').style.display = 'block';
    jQuery.ajax({
        url         : '/admin/chinfraopc.cgi'
        ,type        : 'POST'
        ,cache       : false
        ,data        : JSON.stringify(docData)
        ,contentType : 'application/json; charset=utf-8'
        ,async: false
        ,success: function(data) {
              document.getElementById('chwait').style.display = 'none';
javascript
$msg[0] = "INFO: Definições atualizadas com sucesso!";
$msg[1] = "INFO: Settings updated successfully!";
print FILE "                 alert(\"$msg[$FW_LANG]\");\n";
print FILE << "javascript";
        }
    });
  }

//-->
</script>\n\n
javascript

    my $srcfs = "";
    if ($canch == 0) {
       $msg[0] = "Somente leitura (nó escravo)!";
       $msg[1] = "Read-only (slave node)!";
       $srcfs = "<h5><FONT color=\"Red\"><strong>$msg[$FW_LANG]</strong></FONT></h5>";
    }

    $msg[0] = "Infraestrutura";
    $msg[1] = "Infrastructure";
    my $mstyle = menustyle("$msg[$FW_LANG]");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' onload="document.getElementById('tab_stats').style.display='block';" $STYLE>
  <span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG] ($srcfile)</span>

  <DIV align="center">
HTMLCODE

   ## Waiting form
   print FILE "<DIV align=\"center\" valign=\"center\" id=\"chwait\">";
   $msg[0] = "Aguarde... isto pode demorar um pouco!";
   $msg[1] = "Wait... this may take a little time!";
   print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
   print FILE "</DIV>";

   print FILE << "HTMLCODE";
    <span id="tab_stats" style="display: none;">
      <ul id="tabs">
HTMLCODE
   $msg[0] = "Definições locais e essenciais";
   $msg[1] = "Local and essential definitions";
   print FILE << "HTMLCODE";
        <li><a href="#" name="#tab1">$msg[$FW_LANG]</a></li>
HTMLCODE
   $msg[0] = "Oções de rede";
   $msg[1] = "Network settings";
   print FILE << "HTMLCODE";
        <li><a href="#" name="#tab2">$msg[$FW_LANG]</a></li>
HTMLCODE
   $msg[0] = "Suporte";
   $msg[1] = "Support";
   print FILE << "HTMLCODE";
        <li><a href="#" name="#tab3">$msg[$FW_LANG]</a></li>
      </ul>
HTMLCODE

    ## Grid rules
    my @ctlist = ();
    print FILE "<div id='content'>";

    print FILE "<div id='tab1'>";
    print FILE "<FORM name='fiInfra1' action='/admin/chinfraloc.cgi' method='POST'>";
    print FILE "<div align='left'>";
    $msg[0] = "Nome do firewall";
    $msg[1] = "Firewall name";
    print FILE "<BR /><p valign='center'><span style='Font-Family: Arial, Helvetica;'>$msg[$FW_LANG]</span>";
    $msg[0] = `hostname -s`;
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 218px;'>";
    print FILE "<INPUT type='text' id='hName' name='hostName' size='15' value=\"$msg[0]\" style='Font-Family: Arial, Helvetica; height:24px; width:160px;'>";
    print FILE "</span></p>";
    $msg[0] = "IP preferêncial (LAN)";
    $msg[1] = "Preferential IP (LAN)";
    print FILE "<span style='Font-Family: Arial, Helvetica;'>$msg[$FW_LANG]</span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 220px;'>";
    print FILE "<SELECT id='hIp' name='hostIp' style='width:160px; font-size:small;'>";
    $msg[0] = `hostname -i | cut -d ' ' -f1 | tr -d '\\n'`;
    $msg[1] = $msg[0];
    foreach ($msg[0], @fwip) {
       my $selip = "";
       if ($msg[0] eq $msg[1] || $_ ne $msg[0]) {
          $selip = "selected" if ($_ eq $msg[0]);
          print FILE "<OPTION value=\"$_\" $selip>$_</OPTION>";
       }
       $msg[1] = "";
    }
    print FILE "</SELECT></span>";
    $msg[0] = "Desabilita IPv6";
    $msg[1] = "Disable IPv6";
    print FILE "<BR /><BR /><span style='Font-Family: Arial, Helvetica;'>$msg[$FW_LANG]</span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 218px;'>";
    $msg[0] = `grep 'blacklist ipv6' /etc/modprobe.d/blacklist-ipv6.conf 2>\&1 >/dev/null && echo \"checked\" | tr -d '\\n'`;
    print FILE "<INPUT type='checkbox' id='ckIpv6' name='chkIpv6' size='25' style='Font-Family: Arial, Helvetica;' $msg[0]></span>";
    print FILE "<BR /><BR /><hr noshade='true' size='1'><BR />";
    $msg[0] = "DNS externo (internet)";
    $msg[1] = "External DNS (internet)";
    print FILE "<p valign='center'><span style='Font-Family: Arial, Helvetica;'>$msg[$FW_LANG]</span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 218px;'>";
    $msg[0] = `grep '^[\\s]*nameserver' /etc/resolv.conf | awk '{ print \$2; }' | tr '\\n' ' '`;
    my $nameserver = $msg[0];
    if ($nameserver =~ /[\s]*127\.0\.0\.1[\s]*/ && -e "/etc/bind/named.conf.options") {
       $msg[0] = `cat /etc/bind/named.conf.options | awk '{ if (\$1 == \"zone\") ct++; if (\$1 == \"forwarders\" && ct < 1) readl=1; if (readl == 1) ct++; if (\$1 == \"};\") readl=0; if (readl == 1 && \$1 != \"forwarders\") print \$1; }' | tr '\\n' ' ' | sed 's/;//g'`;
       $msg[0] = "127.0.0.1" if ($msg[0] eq "");
    }
    print FILE "<INPUT type='text' id='dmResolv' name='domainResolv' size='18' value='$msg[0]' style='Font-Family: Arial, Helvetica; height:24px;'></span>";
    $msg[0] = "DNS interno (lan)";
    $msg[1] = "Internal DNS (lan)";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 488px;'>$msg[$FW_LANG]</span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 620px;'>";
    $msg[0] = `cat /etc/bind/localresolvers | tr -d '\n'`;
    print FILE "<INPUT type='text' id='dmServer' name='domainServer' size='18' value='$msg[0]' style='Font-Family: Arial, Helvetica; height:24px; width:145px;'></span></p>";
    $msg[0] = "Domínios de pesquisa";
    $msg[1] = "Domain search";
    print FILE "<p valign='center'><span style='Font-Family: Arial, Helvetica;'>$msg[$FW_LANG]</span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 218px;'>";
    $msg[0] = `grep '^[\\s]*search' /etc/resolv.conf | cut -d \' \' -f2-`;
    print FILE "<INPUT type='text' id='dmSearch' name='domainSearch' size='50' value=\"$msg[0]\" style='Font-Family: Arial, Helvetica; height:24px; width:200px;'></span>";
    $msg[0] = "Domínio e realm";
    $msg[1] = "Domain and realm";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 488px;'>$msg[$FW_LANG]</span>";
    $msg[0] = `hostname -d | tr -d '\n'`;
    if (-e "/etc/bind/localdomains") {
       $msg[1] = `cat /etc/bind/localdomains | grep -v \"\\b$msg[0]\\(\$\\|\\s+\\)\" | sed \"s/\\b$msg[0]\\s\\+//\"`;
       $msg[0] = "$msg[0] $msg[1]";
       $msg[0] =~ s/\n//g;
    }
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 620px;'>";
    print FILE "<INPUT type='text' id='dmName' name='domainName' size='18' value=\"$msg[0]\" style='Font-Family: Arial, Helvetica; height:25px; width:145px;'></span> ";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 768px;'>";
    $msg[0] = `grep realm /etc/samba/smb.conf | sed 's/.*=\\(\\s\\)*//'`;
    print FILE "<INPUT type='text' id='dmRealm' name='realmName' size='18' value=\"$msg[0]\" style='Font-Family: Arial, Helvetica; height:25px; width:145px;'></span></p>";
    $msg[0] = "Prioriza respostas IPv4";
    $msg[1] = "Prefer IPv4 responses";
    print FILE "<p><span style='Font-Family: Arial, Helvetica;'>$msg[$FW_LANG]</span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 218px;'>";
    $msg[0] = `grep \"^[\\s]*precedence[ |\\t]\\\+::ffff:0:0/96[ |\\t]\\\+100\" /etc/gai.conf 2>\&1 >/dev/null && echo \"checked\"`;
    print FILE "<INPUT type='checkbox' id='ckPref4' name='chkPrefIpv4' style='Font-Family: Arial, Helvetica;' $msg[0]></span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 488px; color: #800000;'>DC/PDC</span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 624px;'>";
    print FILE "<SELECT id='dType' name='dcType' style='width:136px; font-size:small;'>";
    $msg[0] = "";
    $msg[1] = "";
    ($msg[0], $msg[1]) = split /\s/, `cat $FW_DIR/addon/dctype | tr -d '\\n'`, 2 if (-e "$FW_DIR/addon/dctype");
    $msg[0] = "none" if ($msg[0] eq "");
    $msg[1] = "0.0.0.0" if ($msg[1] eq "");
    my @dcType = ("none", "ad", "rpc", "rpc/krb");
    my $seldc = $msg[0];
    foreach (@dcType) {
       my $auxseldc = "";
       $auxseldc = "selected" if ($_ eq $seldc);
       print FILE "<OPTION value=\"$_\" $auxseldc>$_</OPTION>";
    }
    print FILE "</SELECT></span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 768px;'>";
    print FILE "<INPUT type='text' id='dAddress' name='dcAddress' size='13' value=\"$msg[1]\" style='Font-Family: Arial, Helvetica; height:24px; width:145px;'></span></p>";

    $msg[0] = "Tentativas";
    $msg[1] = "Attempts";
    print FILE "<p><span style=\"Font-Family: Arial, Helvetica;\">$msg[$FW_LANG]</span>";
    $msg[0] = `grep \"^[\\s]*options[ |\\t]\\\+attempts\" /etc/resolv.conf | cut -d':' -f2`;
    $msg[0] = "2" if ($msg[0] < 1 or $msg[0] eq "");
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 218px;'>";
    print FILE "<INPUT type='text' id='rAttempts' name='resAttempts' size='2' style='Font-Family: Arial, Helvetica;' value=\"$msg[0]\"></span>";
    $msg[0] = "Conta DC/PDC";
    $msg[1] = "DC/PDC account";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 488px; color: #800000;'>$msg[$FW_LANG]</span>";
    $msg[0] = "";
    $msg[1] = "";
    ($msg[0], $msg[1]) = split /\s/, `cat $FW_DIR/addon/dcaccount | tr -d '\\n'` if (-e "$FW_DIR/addon/dcaccount");
    $msg[0] = "administrator" if ($msg[0] eq "");
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 620px;'>";
    print FILE "<INPUT type='text' id='dLogin' name='dcLogin' size='15' value=\"$msg[0]\" style='Font-Family: Arial, Helvetica; height:24px;'> ";
    print FILE "<INPUT type='password' id='dPasswd' name='dcPasswd' size='15' value=\"$msg[1]\" style='Font-Family: Arial, Helvetica; height:24px;'></span></p>";
    print FILE "<p><span style='Font-Family: Arial, Helvetica;'>Timeout</span>";
    $msg[0] = `grep \"^[\\s]*options[ |\\t]\\\+timeout\" /etc/resolv.conf | cut -d':' -f2`;
    $msg[0] = "5" if ($msg[0] < 1 or $msg[0] eq "");
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 218px;'>";
    print FILE "<INPUT type='text' id='rTimeout' name='resTimeout' size='2' style='Font-Family: Arial, Helvetica;' value=\"$msg[0]\">s</span>";
    $msg[0] = "Integrado (DC)";
    $msg[1] = "Join (DC)";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 488px; color: #800000;'>$msg[$FW_LANG]</span> ";
    $msg[0] = 0;
    if ($seldc ne "none") {
       $seldc = "rpc";
       $seldc = "ads" if ($seldc eq "ad");
       $msg[0] = `LANG='C' net $seldc testjoin 2>/dev/null | grep ' OK\$' >/dev/null && echo '1'`;
    }
    if ($msg[0] == 1) {
      $msg[0] = "<FONT color='green'>Sim</FONT>";
      $msg[1] = "<FONT color='green'>Yes</FONT>";
    }
    else {
      $msg[0] = "<FONT color='red'>Não</FONT>";
      $msg[1] = "<FONT color='red'>No</FONT>";
    }
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 626px;\'><i><strong>$msg[$FW_LANG]</strong></i></span></p>";
    $msg[0] = "Servidor";
    $msg[1] = "Server";
    print FILE "<span style='Font-Family: Arial, Helvetica;'>$msg[$FW_LANG]/Cache</span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 218px;'>";
    $msg[0] = "";
    $msg[0] = "checked" if ($nameserver =~ /[ |\t]*127\.0\.0\.1[ |\t]*$/);
    print FILE "<INPUT type='checkbox' id='ckDomCache' name='chkDomCache' style='Font-Family: Arial, Helvetica;' $msg[0]></span>";
    print FILE "<INPUT type='submit' name='ReloadFw' value='Reload firewall rules' style='visibility:hidden; position:absolute;'>";
    print FILE "</div></FORM>";
    print FILE "<BR />$srcfs";
    print FILE "<BR />" if ($srcfs ne "");
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE "<a href='#' id='btsav1' class='uibt'>$msg[$FW_LANG]</a>";
    $msg[0] = "Cancelar";
    $msg[1] = "Cancel";
    print FILE " <a href='#' id='btcan1' class='uibt_em'>$msg[$FW_LANG]</a>";
    $msg[0] = "Recarregar";
    $msg[1] = "Reload";
    print FILE " &nbsp; <a href='#' id='btrel1' class='uibt'>$msg[$FW_LANG]</a>";
    print FILE "</div>";


    print FILE "<div id='tab2'>";
    print FILE "<FORM name='fiInfra2' action='/admin/chinfraopc.cgi' method='POST'>";
    print FILE "<table width='92%' height='10%' border='0' cellspacing='0' cellpadding='0'>";
    print FILE "<tbody><TR valign='center'><TD align='left' width='50%'>";
    print FILE " &nbsp;<span style='position: relative; width: 44; display:inline-block;'> LAN: </span> ";
    print FILE "<SELECT id='iflan' multiple style='width:250px; font-size:small;'>";
    foreach my $auxsel1 (@fwifs) {
      if ($auxsel1 !~ /^((tun|ppp|ifb|gre|ipip)[0-9])/) {
         $auxsel1 =~ s/\n//;
         my $selif = "";
         foreach my $auxsel2 (@{$fwcfg{"IFLAN"}}) {
            $auxsel2 =~ s/\n//;
            $selif = "selected" if ($auxsel1 && ($auxsel1 eq $auxsel2));
         }
         print FILE "<OPTION value=\"$auxsel1\" $selif>$auxsel1</OPTION>" if ($auxsel1);
      }
    }
    print FILE "</SELECT><BR />";
    print FILE " &nbsp;<span style='position: relative; width: 44; display:inline-block;'> WAN: </span>";
    print FILE " <SELECT id='ifwan' multiple style='width:250px; font-size:small;'>";
    foreach my $auxsel1 (@fwifs) {
      if ($auxsel1 !~ /^(tun|ppp|(gre|ipip)[0-9])/) {
         $auxsel1 =~ s/\n//;
         my $selif = "";
         foreach my $auxsel2 (@{$fwcfg{"IFWAN"}},@{$fwcfg{"IFPUB"}},@{$fwcfg{"IFNET"}}) {
            $auxsel2 =~ s/\n//;
            $selif = "selected" if ($auxsel1 && ($auxsel1 eq $auxsel2));
         }
         print FILE "<OPTION value=\"$auxsel1\" $selif>$auxsel1</OPTION>" if ($auxsel1);
      }
    }
    print FILE "</SELECT><BR />";

    $msg[0] = "Portas locais (intervalo)";
    $msg[1] = "Local port (range)";
    print FILE "<DIV valign='center' align='left' style='border:2px'>";
    print FILE " &nbsp;<span style='position: relative; display:inline-block;'> $msg[$FW_LANG]: </span> ";
    print FILE "<SELECT id='lport' name='local_ports' style='width:90px; font-size:small;'>";
    my @auxsel = ("firewall", "fullnat", "server");
    foreach my $auxsel1 (@auxsel) {
       $auxsel1 =~ s/\n//;
       my $selpt = "";
       $selpt = "selected" if ($fwcfg{"local_ports"}[0] && $fwcfg{"local_ports"}[0] eq $auxsel1);
       print FILE "<OPTION value=\"$auxsel1\" $selpt>$auxsel1</OPTION>" if ($auxsel1);
    }
    print FILE "</select></DIV>";

    print FILE "</TD><TD align='left' width='50%'>";
    my $ckprof = "";
    $ckprof = "checked" if ($fwcfg{"profile"}[0] eq "yes");
    $msg[0] = "Habilita perfis";
    $msg[1] = "Enable profiles";
    print FILE "<DIV valign='center' align='left' style='border:2px'>";
    print FILE "<span style='position: relative; display:inline-block;'>$msg[$FW_LANG] </span>";
    print FILE "<INPUT type='checkbox' id='eprof' name='profile' style='position: relative; display:inline-block;' $ckprof></DIV>";

    $msg[0] = "Perfil padr&atilde;o";
    $msg[1] = "Default profile";
    print FILE "<BR /><span style='position: relative; display:inline-block;'>$msg[$FW_LANG]: </span>";
    print FILE " <SELECT id='dprof' name='default_profile' style='width:180px; font-size:small;'>";
    @auxsel = ("ACCEPT", "DROP");
    push(@auxsel, @fwprof);
    foreach my $auxsel1 (@auxsel) {
       $auxsel1 =~ s/\n//;
       my $seldf = "";
       if ($auxsel1 !~ /^[\s]*((mangle|vpn):|rsquid|vpop3)|\?chk=/) {
          $seldf = "selected" if ($fwcfg{"default_profile"}[0] eq $auxsel1);
          print FILE "<OPTION value=\"$auxsel1\" $seldf>$auxsel1</OPTION>" if ($auxsel1);
       }
    }
    print FILE "</SELECT>";

    print FILE "</TD></TR></tbody></table>";
    print FILE "<hr noshade='true' size='1'>";

    print FILE "<table width='92%' height='44%' border='0' cellspacing='0' cellpadding='0'>";
    print FILE "<tbody><TR valign='center'><TD align='left' valign='center'>";
    print FILE "<FONT style='font-size:small; Font-Family: Arial, Helvetica;'>";
    $msg[0] = "Confi&aacute;veis";
    $msg[1] = "Trusted";
    print FILE "<i>$msg[$FW_LANG]</i></FONT><BR />";
    $msg[0] = "Acesso administrativo";
    $msg[1] = "Admin access";
    print FILE "<DIV class='custom-header' style='background-color:#A4A4A4; border:0px; color:white; text-align:center; font-size:13px; width:180px'>$msg[$FW_LANG]</DIV>";
    print FILE "<SELECT name='TrustLs' size='10' style='width: 180px; height: 200px; border:1px solid #A4A4A4; color: #555; font-size: 14px;'>";
    foreach (@{$fwcfg{"TRUST"}}) {
      $_ =~ s/\n//;
      print FILE "<OPTION value=\"$_\">$_</OPTION>";
    }
    print FILE "</SELECT><BR />";
    print FILE "<INPUT type='button' value='+' onclick=\"return newinfra(\'trust\');\" style='Font-Family: Arial, Helvetica;'>";
    print FILE "<INPUT type='button' value='-' onclick=\"return delinfra(\'trust\');\" style='Font-Family: Arial, Helvetica;'>";

    print FILE "</TD><TD align='left' valign='center'>";
    print FILE "<FONT style='font-size:small; Font-Family: Arial, Helvetica;'>";
    $msg[0] = "Servidores de DNS";
    $msg[1] = "DNS servers";
    print FILE "<i>$msg[$FW_LANG]</i></FONT><BR />";
    $msg[0] = "Servidores externos";
    $msg[1] = "External servers";
    print FILE "<DIV class='custom-header' style='background-color:#A4A4A4; border:0px; color:white; text-align:center; font-size:13px; width:180px'>$msg[$FW_LANG]</DIV>";
    print FILE "<SELECT name='DnsLs' size='10' style='width: 180px; height: 200px; border:1px solid #A4A4A4; color: #555; font-size: 14px;'>";
    foreach (@{$fwcfg{"DNS"}}) {
      $_ =~ s/\n//;
      print FILE "<OPTION value=\"$_\">$_</OPTION>";
    }
    print FILE "</SELECT><BR />";
    print FILE "<INPUT type='button' value='+' onclick=\"return newinfra(\'dns\');\" style='Font-Family: Arial, Helvetica;'>";
    print FILE "<INPUT type='button' value='-' onclick=\"return delinfra(\'dns\');\" style='Font-Family: Arial, Helvetica;'>";

    print FILE "</TD><TD align='center' valign='center'>";
    print FILE "<FONT style='font-size:small; Font-Family: Arial, Helvetica;'>";
    $msg[0] = "Modulos Conntrack";
    $msg[1] = "Conntrack modules";
    print FILE "<i>$msg[$FW_LANG]</i></FONT><BR />";
    print FILE "<SELECT id='conn-select' name='conn-select[]' multiple size='10' multiple='multiple' >";
    @ctlist = `$FW_DIR/fwguardian --list-nat-conntrack | grep \"^\\\(nf\\\|ip\\\)_\" | sed \'s/\\\(nf\\\|ip\\\)_nat_//g\'`;
    push(@ctlist, "ALL");
    foreach my $auxsel1 (@ctlist) {
      $auxsel1 =~ s/\n//;
      my $selct = "";
      foreach my $auxsel2 (@{$fwcfg{"conntrack"}}) {
         $auxsel2 =~ s/\n//;
         $selct = "selected" if ($auxsel1 && ($auxsel1 eq $auxsel2));
      }
      print FILE "<OPTION value=\"$auxsel1\" $selct>$auxsel1</OPTION>" if ($auxsel1);
    }

    print FILE "</TD></TR></tbody></table>";
    print FILE "<INPUT type='submit' name='ReloadFw' value='Reload firewall rules' style='visibility:hidden; position:absolute;'>";
    print FILE "</FORM>";
    print FILE "$srcfs<BR />";
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE "<a href='#' id='btsav2' class='uibt'>$msg[$FW_LANG]</a>";
    $msg[0] = "Cancelar";
    $msg[1] = "Cancel";
    print FILE " <a href='#' id='btcan2' class='uibt_em'>$msg[$FW_LANG]</a>";
    $msg[0] = "Recarregar";
    $msg[1] = "Reload";
    print FILE " &nbsp; <a href='#' id='btrel2' class='uibt'>$msg[$FW_LANG]</a>";
    print FILE "</div>";


    print FILE "<div id='tab3'>";
    print FILE "<FORM name='fiInfra3' action='/admin/chinfrasup.cgi' method='POST'>";
    print FILE << "HTMLCODE";
    <table id="fwInfraGrid" width="100%" style="font-size:12px;"></table>
    <div id="pfwInfraGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
    print FILE "<INPUT type='submit' name='ReloadFw' value='Reload firewall rules' style='visibility:hidden; position:absolute;'>";
    print FILE "</FORM>";
    print FILE "$srcfs<BR />";
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE "<a href=\"#\" id=\"btsav3\" class=\"uibt\">$msg[$FW_LANG]</a>";
    $msg[0] = "Cancelar";
    $msg[1] = "Cancel";
    print FILE " <a href=\"#\" id=\"btcan3\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
    $msg[0] = "Recarregar";
    $msg[1] = "Reload";
    print FILE " &nbsp; <a href=\"#\" id=\"btrel3\" class=\"uibt\">$msg[$FW_LANG]</a>";
    print FILE "</div>";

    print FILE "</div>";

print FILE << "HTML";
    <FORM name="fInfra">
    <input type="BUTTON" id="savegd1" name="savegd1" value="Save" onclick="return saveInfra1();" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="savegd2" name="savegd2" value="Save" onclick="return saveInfra2();" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="savegd3" name="savegd3" value="Save" style="visibility:hidden; position:absolute;" />
    </FORM></span></DIV>

    <script type="text/javascript" src="/js/csstab.js"></script>
    </body></html>
HTML
   close(FILE);

   return get_file("text/html", $htmlfile);
}

return 1;
