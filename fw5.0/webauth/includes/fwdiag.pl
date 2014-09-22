#!/usr/bin/perl

#Rev.0 - Version 5.0

# "Define a TARGET address or FDQN"
sub chtarget {
  my $s = shift;
  my $txtvalue = "";
  my $dvalue = $s;
  my @msg = ("", ""), @msg2 = ("", "");

  my $res = HTTP::Response->new();

  if ($s =~ /^ChkAddr=[0-9a-zA-Z\.\/]+\&/) {
     $dvalue =~ s/^ChkAddr=([0-9a-zA-Z\.\/]+)\&.*/$1/;
     $dvalue = str_conv($dvalue);

    ### Set target to the user session
    system("echo \"$dvalue\" > /tmp/sessions/cgisess_$read_cookie.app.tgdiag");
    $msg[0] = "Alvo avaliado: <font color=\'Navy\'>$dvalue</font><BR /><BR />Por favor, aguarde um momento...";
    $msg[1] = "Target check: <font color=\'Navy\'>$dvalue</font><BR /><BR />Wait a moment please...";
    $txtvalue = msgbox("info", "$msg[$FW_LANG]", "");
  }
  else {
    $msg[0] = "Nada a ser feito!";
    $msg[1] = "Nothing to do!";
    $msg2[0] = "<FONT color=\"Red\">Selecione um endere&ccedil;o ALVO v&aacute;lido ou FQDN</FONT>";
    $msg2[1] = "<FONT color=\"Red\">Select a valid TARGET address or FQDN</FONT>";
    $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]", "");
  }

  my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"2;URL=/admin/fwdiags.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
  $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";

  $res->content_type("text/html");
  $res->content($txtvalue);
  return $res;
}


# "Reset diag variables"
sub diag_var {
  @tg_dns = ();
  @tg_icmp = ();
  @tg_host = ();
  @tg_route = ();
}


# "Making target diagnostics"
sub mk_diags {
  my $target = "";
  my $tg_ip = "";
  my @msg = ("", "");

  ### Do target tests
  $target = "www.google.com" if ($target eq "auto");
  $target = `cat /tmp/sessions/cgisess_$read_cookie.app.tgdiag | tr -d '\\n'`;
  diag_var;

  ### DNS tests
  push(@tg_dns, "");
  $msg[0] = "--- Relat&oacute;rio: dig ";
  $msg[1] = "--- Report: dig ";
  push(@tg_dns, "$msg[$FW_LANG]");
  foreach(`dig $target +nocomments +short +time=1 +tries=2`) {
     $_ =~ s/\n//;
     push(@tg_dns, $_);
  }
  push(@tg_dns, "");
  $msg[0] = "--- Relat&oacute;rio: nslookup ";
  $msg[1] = "--- Report: nslookup ";
  push(@tg_dns, "$msg[$FW_LANG]");
  foreach(`nslookup -timeout=1 -retry=2 $target | tail -3 | head -2`) {
     $_ =~ s/\n//;
     push(@tg_dns, $_);
  }

  ### Select the TARGET IP Address
  $tg_ip = $target;
  $tg_ip = `dig $target +nocomments +short +time=1 +tries=2 | tail -1 | tr -d '\\n'` if ($target =~ /^[a-zA-Z_]+/);
  my $tg_dev = `ip route get $tg_ip | head -1 | sed 's/.* dev \\([a-zA-Z0-9\\.@]\\+\\) .*/\\1/' | tr -d '\\n'`;
  my $defgw = `ip route get $tg_ip | grep 'via' | head -1 | sed 's/.* via \\([0-9]\\+\\.[0-9]\\+\\.[0-9]\\+\\.[0-9]\\+\\) .*/\\1/' | tr -d '\\n'`;

  ### ICMP tests
  push(@tg_icmp, "");
  push(@tg_icmp, "--- Ping: gateway $defgw ");
  foreach(`ping -c 3 -w 3 $defgw 2>/dev/null` ) {
    $_ =~ s/\n//;
    push(@tg_icmp, $_) if ($_ =~ /packets transmitted|bytes from/);
  }
  push(@tg_icmp, "");
  push(@tg_icmp, "");
  $msg[0] = "--- Ping: $target (padr&atilde;o) ";
  $msg[1] = "--- Ping: $target (default) ";
  push(@tg_icmp, "$msg[$FW_LANG]");
  foreach(`LANG=en ping -c 5 -w 5 $target 2>/dev/null` ) {
    $_ =~ s/\n//;
    push(@tg_icmp, $_) if ($_ =~ /packets transmitted|bytes from/);
  }
  push(@tg_icmp, "");
  push(@tg_icmp, "");
  $msg[0] = "--- Ping: $target (com 1400 bytes) ";
  $msg[1] = "--- Ping: $target (with 1400 bytes) ";
  push(@tg_icmp, "$msg[$FW_LANG]");
  foreach(`LANG=en ping -c 3 -w 3 -s 1400 $target 2>/dev/null` ) {
    $_ =~ s/\n//;
    push(@tg_icmp, $_) if ($_ =~ /packets transmitted|bytes from/);
  }
  push(@tg_icmp, "");
  push(@tg_icmp, "");
  $msg[0] = "--- Ping: $target (com 2500 bytes) ";
  $msg[1] = "--- Ping: $target (with 2500 bytes) ";
  push(@tg_icmp, "$msg[$FW_LANG]");
  foreach(`LANG=en ping -c 3 -w 3 -s 2500 $target 2>/dev/null` ) {
    $_ =~ s/\n//;
    push(@tg_icmp, $_) if ($_ =~ /packets transmitted|bytes from/);
  }

  ### Routing tests
  push(@tg_route, "");
  $msg[0] = "--- Roteador selecionado ";
  $msg[1] = "--- Selected router ";
  push(@tg_route, "$msg[$FW_LANG]", $defgw);
  push(@tg_route, "");
  push(@tg_route, "--- Traceroute ");
  foreach(`traceroute $target -m 8 -w 2 -n`) {
     $_ =~ s/\n//;
     push(@tg_route, $_);
  }

  ### Host info
  push(@tg_host, "");
  $msg[0] = "--- Consulta NBT (nbtscan) ";
  $msg[1] = "--- NBT search (nbtscan) ";
  push(@tg_host, "$msg[$FW_LANG]", `nbtscan -t 1 -q $tg_ip`);
  push(@tg_host, "", "");
  $msg[0] = "--- Consulta arp (arping) ";
  $msg[1] = "--- Arp search (arping) ";
  push(@tg_host, "$msg[$FW_LANG]");
  foreach(`arping $tg_ip -I $tg_dev -w1 -c 2`) {
     $_ =~ s/\n//;
     push(@tg_host, $_);
  }
  push(@tg_host, "", "");
  push(@tg_host, "--- Portscan (nmap) ");
  foreach(`nmap -sS $tg_ip -T5 -n --host_timeout 15s --max_rtt_timeout 100ms -P0`) {
     $_ =~ s/\n//;
     push(@tg_host, $_);
  }
}

# "Make web page fwdiags.html"
sub get_fwdiags {

    my $htmlfile="$HTMLDIR/admin/dynhttp/fwdiags.html";
    my $sttype = shift;

    my @msg = ("", "");

    ### Making fwdiags.html
    open FILE, ">$htmlfile";

print FILE << "javascript";
<html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  <link href="/css/csstab.css" type="text/css" rel="stylesheet" />
  <link href="/css/jquery-ui.css" type="text/css" rel="stylesheet" />

  <script type="text/javascript" src="/js/jquery-1.7.2.min.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.core.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.widget.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.button.js"></script>
  <script type="text/javascript">
       \$(function() {
          \$( "input[type=submit]" ).button().css('font-size', '12px');
       });
  </script>
\n\n
javascript

   diag_var;
   mk_diags if (-e "/tmp/sessions/cgisess_$read_cookie.app.tgdiag");

   $msg[0] = "Diagn&oacute;stico de rede!";
   $msg[1] = "Network diagnostics!";
   my $mstyle = menustyle("$msg[$FW_LANG]");
   print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE onload="document.getElementById('tab_stats').style.display='block';">
  <p><span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG]</span></p>

  <DIV align="center">
  <form name="fitarget" method="post" action="/admin/chtarget.cgi">
HTMLCODE
$msg[0] = "Verifica IP ";
$msg[1] = "Check IP ";
print FILE "  $msg[$FW_LANG] <input name=\"ChkAddr\" style=\"background-color: #bec2c8;\"> \n";
$msg[0] = "Verificar";
$msg[1] = "Check";
print FILE "  <input name=\"BtChkAddr\" value=\"$msg[$FW_LANG]\" type=\"submit\"><BR /> ";

   ### DIV of Target tests
   print FILE << "HTMLCODE";
    <span id="tab_stats" style="display: none;">
       <ul id="tabs">
HTMLCODE
$msg[0] = "Roteamento";
$msg[1] = "Routing";
print FILE "          <li><a href=\"#\" name=\"#tab1\">$msg[$FW_LANG]</a></li>\n";
print FILE << "HTMLCODE";
          <li><a href=\"#\" name="#tab2">DNS</a></li>
          <li><a href=\"#\" name="#tab3">ICMP</a></li>
          <li><a href=\"#\" name="#tab4">Host</a></li>
       </ul>

    <div id="content">
      <div id="tab1">
HTMLCODE
   $msg[0] = "Testes de roteamento";
   $msg[1] = "Routing testes";
   print FILE "      <strong><i>$msg[$FW_LANG]</i></strong>\n";

   print FILE "  <textarea style=\"height: 62%; width: 100%;\" readonly>";
   foreach(@tg_route) {
     print FILE "$_\n\n";
   }
   print FILE "  </textarea>";
   print FILE << "HTMLCODE";
      </div>

      <div id="tab2">
HTMLCODE
   $msg[0] = "Testes de DNS";
   $msg[1] = "DNS tests";
   print FILE "      <strong><i>$msg[$FW_LANG]</i></strong>";

   print FILE "  <textarea style=\"height: 62%; width: 100%;\" readonly>";
   foreach(@tg_dns) {
     print FILE "$_\n\n";
   }
   print FILE "  </textarea>";
   print FILE << "HTMLCODE";
      </div>

      <div id="tab3">
HTMLCODE
   $msg[0] = "Testes ICMP";
   $msg[1] = "ICMP testes";
print FILE "      <strong><i>$msg[$FW_LANG]</i></strong>\n";
   print FILE "  <textarea style=\"height: 62%; width: 100%;\" readonly>";
   foreach(@tg_icmp) {
     print FILE "$_\n\n";
   }
   print FILE "  </textarea>";
   print FILE << "HTMLCODE";
      </div>

      <div id="tab4">
HTMLCODE
   $msg[0] = "Informa&ccedil;&otilde;es do Host";
   $msg[1] = "Host info";
print FILE "      <strong><i>$msg[$FW_LANG]</i></strong>\n";
   print FILE "  <textarea style=\"height: 62%; width: 100%;\" readonly>";
   foreach(@tg_host) {
     print FILE "$_\n\n";
   }
   print FILE "  </textarea>";
   print FILE << "HTMLCODE";
     </div>
   </div>
   </span></form></DIV>

   <script type="text/javascript" src="/js/csstab.js"></script>
   </body></HTML>
HTMLCODE
   close(FILE);

   diag_var;
   system("rm -f /tmp/sessions/cgisess_$read_cookie.app.tgdiag 2>/dev/null");
   return get_file("text/html", $htmlfile);
}

return 1

