#!/usr/bin/perl

#Rev.0 - Version 5.0

# "Reset stats variables"
sub st_var {
  @st_rt = ();
  @st_rtdb = ();
  @st_host = ();
  @st_link = ();
  @st_nettun = ();

  @st_tg_dns = ();
  @st_tg_icmp = ();
  @st_tg_host = ();
  @st_tg_route = ();
}


# "Getting firewall stats"
sub mk_fwstats {
  my @msg = ("", "");

  ### Main firewall info
  st_var;
  push(@st_host, "- Hostname: ",`hostname`);
  foreach (`echo "- Resolv.conf" && cat /etc/resolv.conf | grep nameserver`) {
     $_ =~ s/\n//;
     push(@st_host, $_);
  }
  foreach (`ifconfig -a`) {
     $_ =~ s/\n//;
     push(@st_ifs, $_);
  }
  foreach(`for i in \$(ifconfig | grep -i "link encap" | cut -d" " -f1)\; do ethtool \$i && echo && echo \;done`) {
     $_ =~ s/\n//;
     push(@st_link, $_);
  }
  foreach (`sysctl -a 2>/dev/null | grep "rp_filter\\\|proxy_arp\\\|arp_filter"`) {
     $_ =~ s/\n//;
     push(@st_nettun, $_);
  }

  my $isrt = `sysctl -a 2>/dev/null | grep ip_forward`;
  push(@st_rt, $isrt);
  $msg[0] = "ERRO: roteamento desabilitado...";
  $msg[1] = "ERROR: disabled routing...";
  push(@st_rt, "$msg[$FW_LANG]") if ( $isrt eq 0 );
  foreach(`route -n`) {
     $_ =~ s/\n//;
     push(@st_rt, $_);
  }

  foreach(`ip rule ls`) {
     $_ =~ s/\n//;
     push(@st_rtdb, $_);
  }
}


# "Make web page fwstats.html"
sub get_fwstats {

    my $htmlfile="$HTMLDIR/admin/dynhttp/fwstats.html";

    my @msg = ("", "");

    ### Making fwstats.html
    open FILE, ">$htmlfile";

print FILE << "javascript";
<html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  <link href="/css/csstab.css" type="text/css" rel="stylesheet" />

  <script type="text/javascript" src="/js/jquery-1.7.2.min.js"></script>

javascript

   mk_fwstats;
   $msg[0] = "Informa&ccedil;&otilde;es de rede!";
   $msg[1] = "Networking information!";
   my $mstyle = menustyle("$msg[$FW_LANG]");
   print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor="#F2F2F2" $STYLE onload="document.getElementById('tab_stats').style.display='block';">
  <p><span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG]</span></p>

  <DIV align="center">
HTMLCODE

   ### DIV of Firewall stats
   print FILE << "HTMLCODE";
    <span id="tab_stats" style="display: none;">
      <ul id="tabs">
HTMLCODE
$msg[0] = "Rotas";
$msg[1] = "Routes";
print FILE "          <li><a href=\"#\" name=\"#tab1\">$msg[$FW_LANG]</a></li>\n";
$msg[0] = "Politica de roteamento";
$msg[1] = "Routing Policy";
print FILE "          <li><a href=\"#\" name=\"#tab2\">$msg[$FW_LANG]</a></li>\n";
$msg[0] = "Informa&ccedil;&otilde;es locais";
$msg[1] = "Local information";
print FILE "          <li><a href=\"#\" name=\"#tab3\">$msg[$FW_LAN]</a></li>\n";
print FILE "          <li><a href=\"#\" name=\"#tab4\">Interfaces</a></li>\n";
$msg[0] = "Negocia&ccedil;&atilde;o de rede";
$msg[1] = "Inteface negotiation";
print FILE "          <li><a href=\"#\" name=\"#tab5\">$msg[$FW_LAN]</a></li>\n";
print FILE "          <li><a href=\"#\" name=\"#tab6\">Tunning</a></li>\n";
print FILE << "HTMLCODE";
      </ul>

  <div id="content">
      <div id="tab1">
HTMLCODE
$msg[0] = "Tabela de roteamento principal";
$msg[1] = "Main routing table";
print FILE "      <strong><i>$msg[$FW_LANG]</i></strong>\n";

   print FILE "  <textarea style=\"height: 68%; width: 100%;\" readonly>";
   foreach(@st_rt) {
     print FILE "$_\n";
   }
   print FILE "  </textarea>\n";

   print FILE << "HTMLCODE";
      </div>

      <div id="tab2">
HTMLCODE
$msg[0] = "Politica de Roteamento (RPDB)";
$msg[1] = "Routing Policy Database (RPDB)";
print FILE "      <strong><i>$msg[$FW_LANG]</i></strong>\n";

   print FILE "  <textarea style=\"height: 68%; width: 100%;\" readonly>";
   foreach(@st_rtdb) {
     print FILE "$_\n";
   }
   print FILE "  </textarea>\n";

   print FILE << "HTMLCODE";
      </div>
 
      <div id="tab3">
HTMLCODE
$msg[0] = "Informa&ccedil;&otilde;es locais";
$msg[1] = "Local info";
print FILE "      <strong><i>$msg[$FW_LANG]</i></strong>";
   print FILE "  <textarea style=\"height: 68%; width: 100%;\" readonly>";
   foreach(@st_host) {
     print FILE "$_\n";
   }
   print FILE "  </textarea>\n";
   print FILE << "HTMLCODE";
      </div>

      <div id="tab4">
HTMLCODE
$msg[0] = "Interfaces de rede";
$msg[1] = "Network interfaces";
print FILE "      <strong><i>$msg[$FW_LANG]</i></strong>\n";
   print FILE "  <textarea style=\"height: 68%; width: 100%;\" readonly>";
   foreach(@st_ifs) {
     print FILE "$_\n";
   }
   print FILE "  </textarea>\n";
   print FILE << "HTMLCODE";
      </div>

      <div id="tab5">
HTMLCODE
$msg[0] = "Negocia&ccedil;&atilde;o de rede";
$msg[1] = "Inteface negotiation";
print FILE "      <strong><i>$msg[$FW_LANG]</i></strong>\n";
   print FILE "  <textarea style=\"height: 68%; width: 100%;\" readonly>";
   foreach(@st_link) {
     print FILE "$_\n";
   }
   print FILE "  </textarea>\n";
   print FILE << "HTMLCODE";
      </div>

      <div id="tab6">
      <strong><i>Network tunning</i></strong>
HTMLCODE
   print FILE "  <textarea style=\"height: 68%; width: 100%;\" readonly>";
   foreach(@st_nettun) {
     print FILE "$_\n";
   }
   print FILE "  </textarea>\n";
   print FILE << "HTMLCODE";
      </div>
  </div>
  </span></DIV>

  <script type="text/javascript" src="/js/csstab.js"></script>
  </body></HTML>
HTMLCODE
   close(FILE);

   st_var;
   return get_file("text/html", $htmlfile);
}

return 1

