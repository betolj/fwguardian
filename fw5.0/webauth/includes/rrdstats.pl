
# "Make web page rrdstats.html"
sub get_rrdstats {
    my $htmlfile="$HTMLDIR/admin/dynhttp/rrdstats.html";

    my $url = shift;
    my $stype = shift;
 
    my @msg = ("", "");

    ### Making fwstats.html
    open FILE, ">$htmlfile";

print FILE << "javascript";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  <meta CACHE-CONTROL="no-cache, no-store, must-revalidate" HTTP-EQUIV="Refresh" CONTENT="300">
  <link href="/css/csstab.css" type="text/css" rel="stylesheet" />

  <script type="text/javascript" src="/js/jquery-1.7.2.min.js"></script>

javascript


   #$msg[0] = "Tráfego de rede!";
   #$msg[1] = "Networking traffic!";
   #my $mstyle = menustyle("$msg[$FW_LANG]");
   #print FILE "$mstyle";
   
   my %stabs = ();
   $stabs{"day"} = "dia";
   $stabs{"week"} = "semana";
   $stabs{"month"} = "mês";
   $stabs{"year"} = "ano";
 
   my @uptime = ("0", "0", "0", "0");
   $uptime[0] = `cat /proc/uptime | cut -d' ' -f1 | tr -d '\n'`;
   $uptime[0] = $uptime[0] / (60 * 60 * 24);
   $uptime[1] = int($uptime[0]);        # Day convert
   $uptime[0] = ($uptime[0] - $uptime[1]) * 24;
   $uptime[2] = $uptime[0];
   $uptime[2] = int($uptime[2]);        # Hour convert
   $uptime[0] = ($uptime[0] - $uptime[2]) * 60;
   $uptime[3] = $uptime[0];
   $uptime[3] = int($uptime[3]);        # Minute convert
   my $hname = `hostname -s | tr -d '\n'`;
   $msg[0] = "Sistema (<strong>$hname</strong>) ativo desde <strong>$uptime[1] dias(s), $uptime[2] hora(s) e $uptime[3] minuto(s)</strong>";
   $msg[1] = "System (<strong>$hname</strong>) has been up for <strong>$uptime[1] day(s), $uptime[2] hour(s) and $uptime[3] minute(s)</strong>";

print FILE << "HTMLCODE";
  </head>
  <body bgcolor="#F2F2F2" $STYLE onload="document.getElementById('tab_stats').style.display='block';">
  <!--<p><span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG]</span></p>-->

  <DIV align="center">

     <div><BR />$msg[$FW_LANG]<BR /><BR /></div>
HTMLCODE

   ### DIV of Firewall stats
   print FILE << "HTMLCODE";
    <span id="tab_stats" style="display: none;">
      <ul id="tabs">
HTMLCODE

   ### Make interface tabs (traffic)
   if ($stype eq "nettraf") {
      $msg[0] = "SISTEMA";
      $msg[1] = "SYSTEM";
      print FILE "          <li><a href=\"#\" name=\"#tab0\">$msg[$FW_LANG]</a></li>\n";
      my $tcount = 1;
      foreach my $iface (`ls /sys/class/net | grep -v lo`) {
         chomp($iface);
         if (not -e "$FW_DIR/webauth/$iface.stats.ignore") {
            $tcount++;
            print FILE "          <li><a href=\"#\" name=\"#tab$tcount\">$iface</a></li>\n";
         }
      }
   }
   elsif ($stype eq "allnettraf") {
      my $tcount = 0;
      my @btime = ("day", "week", "month", "year");
      foreach my $iface (@btime) {
         $stabs{$iface} = $iface if ($FW_LANG == 1);
         $tcount++;
         print FILE "          <li><a href=\"#\" name=\"#tab$tcount\">$stabs{$iface}</a></li>\n";
      }
   }
   print FILE << "HTMLCODE";
      </ul>
      <div id="content">

HTMLCODE
   if ($stype eq "nettraf") {
      print FILE "      <div id=\"tab0\">";
      print FILE "         <a href='/admin/rrdstats.cgi?stats'><img src='/admin/dynhttp/img/day.conntrack.png'></a><BR /><BR />";
      print FILE "         <a href='/admin/rrdstats.cgi?stats'><img src='/admin/dynhttp/img/day.cpu.png'></a><BR /><BR />";
      print FILE "         <a href='/admin/rrdstats.cgi?stats'><img src='/admin/dynhttp/img/day.mem.png'></a><BR /><BR />";
      print FILE "      </div>";

      $tcount = 1;
      foreach my $iface (`ls /sys/class/net | grep -v lo`) {
         chomp($iface);
         if (not -e "$FW_DIR/webauth/$iface.stats.ignore") {
            $tcount++;
            print FILE "      <div id=\"tab$tcount\">";
            print FILE "         <a href='/admin/rrdstats.cgi?allif=$iface'><img src='/admin/dynhttp/img/$iface-day.Bandwidth.png'></a><BR /><BR />";
            print FILE "         <a href='/admin/rrdstats.cgi?allif=$iface'><img src='/admin/dynhttp/img/$iface-day.Packets.png'></a><BR />";
            print FILE "      </div>";
         }
      }
   }
   elsif ($stype eq "allnettraf") {
      if ($url =~ /^\/admin\/rrdstats\.cgi\?allif=/) {
         my $tcount = 0;
         my (undef, $iface) = split /=/, $url, 2;
         my @btime = ("day", "week", "month", "year");
         foreach my $auxparam (@btime) {
            $tcount++;
            $stabs{$auxparam} = $auxparam if ($FW_LANG == 1);
            print FILE "      <div id=\"tab$tcount\">";
            print FILE "         <BR /><strong><font color='#800000'>$stabs{$auxparam}</font> - Interface $iface</strong><BR />";
            print FILE "         <img src='/admin/dynhttp/img/$iface-$auxparam.Bandwidth.png'><BR /><BR />";
            print FILE "         <img src='/admin/dynhttp/img/$iface-$auxparam.Packets.png'><BR />";
            print FILE "      </div>";
         }
      }
      elsif ($url =~ /^\/admin\/rrdstats\.cgi\?stats/) {
         my $tcount = 0;
         my @btime = ("day", "week", "month", "year");
         $msg[0] = "Estatísticas do sistema";
         $msg[1] = "System statistics";
         foreach my $auxparam (@btime) {
            $tcount++;
            $stabs{$auxparam} = $auxparam if ($FW_LANG == 1);
            print FILE "      <div id=\"tab$tcount\">";
            print FILE "         <BR /><strong><font color='#800000'>$stabs{$auxparam}</font> - $msg[$FW_LANG]</strong><BR />";
            print FILE "         <img src='/admin/dynhttp/img/$auxparam.conntrack.png'><BR /><BR />";
            print FILE "         <img src='/admin/dynhttp/img/$auxparam.cpu.png'><BR /><BR />";
            print FILE "         <img src='/admin/dynhttp/img/$auxparam.mem.png'><BR /><BR />";
            print FILE "      </div>";
         }
      }
   }

   print FILE << "HTMLCODE";
      </div>
  </div>
  </span></DIV>

  <script type="text/javascript" src="/js/csstab.js"></script>
  </body></HTML>
HTMLCODE
   close(FILE);

   return get_file("text/html", $htmlfile);
}

return 1

