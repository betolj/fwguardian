#!/usr/bin/perl -w

#Rev.1 - Version 5.0

# "POST /admin/chtfilter.cgi" -> apply button
sub chtfilter {
    my $s = shift;
    my $tftype = shift;
    my $res = HTTP::Response->new();

    my @dvalue = ();
    my $txtvalue = "";
    my $capfilter = "", $target = "";
    my @msg = ("", ""), @msg2 = ("", "");

    CGI::Session->name("FWGSESS");
    my $session = CGI::Session->load(undef, $read_cookie, {Directory=>'/tmp/sessions'});
    my $invalid = 0;
    my $count = 0, $use_auto = 0;
    my $bwport = $session->param("bwcount");
    my $peer = $session->param("_SESSION_REMOTE_ADDR");

    if($session->is_expired || $session->is_empty) {
       $invalid = 1;
       $session->delete;
       close_apps($read_cookie);
    }
    else {
      foreach my $lines (split /&/, $s) {
         $lines =~ s/\+/ /g if ($lines =~ /\+/);
         $lines = str_conv($lines);
         @dvalue = split /=/, $lines;

         if ($dvalue[0] =~ /^(iface|capfilter)$/ && $count < 2 && $dvalue[1]) {
            if ($dvalue[0] eq "iface") {
               $target = $dvalue[1];
               $session->param("iface", "$target");
               $use_auto = 1 if ($dvalue[1] eq "auto");
               $count++;
            }
            else {
               $capfilter = $dvalue[1];
               $capfilter =~ s/\+/ /;
               $session->param("capfilter", "$capfilter");
               if ($use_auto == 1) {
                  (undef, $target) = split /\s+/, $capfilter;
                  $target = `ip route get $target | head -1 | tr -d '\n'`;
                  $target =~ s/.*[ |\t]dev[ |\t]+([a-zA-Z0-9.:]+)[ |\t].*/$1/g; 
                  $session->param("iface", "$target") ;
               }
               $count++;
            }
         }
      }
    }

    my $check = `$FW_DIR/modules/tools/tfshow/tfshow -f \"$capfilter\" -j -t 2>/dev/null`;
    $check =~ s/\n//;
    if ($count gt 1 && $check eq "Ok") {
       $msg[0] = "Filtro aplicado com sucesso!";
       $msg[1] = "Filter updated successfully!";
       $txtvalue = msgbox("info", "$msg[$FW_LANG]", "");
    }
    else {
       if ($invalid == 0) {
          $msg[0] = "Filtro inválido!";
          $msg[1] = "Invalid filter!";
          $msg2[0] = "Restaurando valores padrão.";
          $msg2[1] = "Restoring default values.";

          $target = "any";
          $capfilter = "net 0.0.0.0/0";
          $session->param("iface", "$target");
          $session->param("capfilter", "$capfilter");
          $txtvalue = msgbox("denied", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
       }
       else {
          $msg[0] = "Sessão inválida!";
          $msg[1] = "Invalid session!";
          $txtvalue = msgbox("denied", "$msg[$FW_LANG]", "");
       }
    }

    if ($tftype eq "shell" && $invalid == 0) {
       if ($svsport) {
          system("$FW_DIR/webauth/shell.sh $FW_DIR/webauth start $read_cookie $bwport bandwidth $target $capfilter");
       }
       else {
          system("$FW_DIR/webauth/shell.sh $FW_DIR/webauth starthttp $read_cookie $bwport bandwidth $target $capfilter");
       }
    }
    $session->flush;
    $session->close;

    my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"2;URL=/admin/tfshow.cgi?$tftype\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
    $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page tfshow.html"
sub get_tfshow {
    my $tftype = shift;
    my $htmlfile="$HTMLDIR/admin/dynhttp/tfshow.html";
    my @msg = ("", ""), @msg2 = ("", "");

    ### Making lease.html
    open FILE, ">$htmlfile";

print FILE << "javascript";
  <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
  <html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />

javascript
if ($tftype eq "default") {
print FILE << "javascript";
  <link rel="stylesheet" media="screen" href="/js/mbar.css" type="text/css" />
  <script type="text/javascript" src="/js/mootools-core-1.3.2-full-compat-yc.js"></script>
  <script type="text/javascript" src="/js/moobargraph.js"></script>

  <script type="text/javascript">

    window.addEvent("domready", function(){

      var graph = new mooBarGraph({
	  container: \$('realTime'),
 	  data: [["1","Waiting for data","","#","Waiting for data"]],
	  width: 980,
          height: 480,
	  barSpace: 8,
          color: '#C4D7ED',
	  title: '<h3><small>Stats in Kbits/s</small></h3>',
	  realTime: true,
          legend: true,
          legendWidth: 180
      });

      setInterval( function(){ graph.draw('/admin/tfdata.js'); }, 4000 );
    });
javascript
}
else {
print FILE << "javascript";
  <style type="text/css">
    html, body {
       margin: 0;
       padding: 0;
       border:0;
    }
    #strealTime {
       height: 760;
       width: 1024;;
    }
  </style>

javascript

print FILE "  <script type=\"text/javascript\" src=\"/js/jquery-1.7.2.min.js\"></script>";
print FILE "  <script type=\"text/javascript\">";
}
print FILE << "javascript";

    jQuery(document).ready(function(){
       \$("#obj").width(\$(window).width()-80);
       \$("#obj").height(\$(window).height()-100);
    });

    function capfilter() {
       document.getElementById('chcondition').style.top = '10%';
       document.getElementById('chcondition').style.left = '45%';
       document.getElementById('chcondition').style.height = '50px';
       document.getElementById('chcondition').style.width = '500px';
       document.getElementById('chcondition').style.display = 'block';
javascript
if ($tftype eq "default") {
   print FILE "       document.getElementById('realTime').style.fontFamily = 'Times';";
   print FILE "       document.getElementById('realTime').style.fontSize = '12px';";
}
print FILE << "javascript";
    } 

  </script>
javascript
    my $mstyle = menustyle("Realtime Bandwidth");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE onload='return capfilter();'>
  <span id="text" style="font-weight:bold;">&nbsp; Realtime Bandwidth</span>

  <DIV align="center">
    <DIV align="center" valign="top" id="chcondition" >
      <span style="Font-Family: Arial, Helvetica;"><strong>PCAP filter...</strong></span><BR /><BR />
      <form action="/admin/chtfilter_$tftype.cgi" method="POST">
HTMLCODE
    print FILE "iface: <SELECT name=\"iface\" style=\"Font-Family: Arial, Helvetica;\">";
    print FILE "<OPTION value=\"auto\">auto</OPTION>";
    print FILE "<OPTION value=\"any\">any</OPTION>";
    selifnet("if");
    print FILE "</SELECT>";
    print FILE "      <INPUT type='text' name='capfilter' size='20' style='Font-Family: Arial, Helvetica;'> &nbsp;\n";
$msg[0] = "Aplicar";
$msg[1] = "Apply";
$msg2[0] = "Esconder";
$msg2[1] = "Hidden";
print FILE << "HTML";
      <INPUT type='submit' value='$msg[$FW_LANG]'>
      <INPUT type='button' value='$msg2[$FW_LANG]' onclick="document.getElementById('chcondition').style.display = 'none'">
      </form>
      <BR />
    </DIV>

HTML
if ($tftype eq "default") {
    print FILE "    <div id=\"realTime\"></div><BR />";
}
else {
    CGI::Session->name("FWGSESS");
    my $session = CGI::Session->load(undef, $read_cookie, {Directory=>'/tmp/sessions'});
    my $bwport = $session->param("bwcount");
    $session->flush;
    $session->close;

    my $pubd = $targetHost;
    $pubd =~ s/:[0-9]+//;
    if (-d "/var/lib/shellinabox" && $svsport) {
       print FILE "   <object id='obj' data=\"https://$pubd:$bwport\"></object><BR />\n";
    }
    else {
       print FILE "   <object id='obj' data=\"http://$pubd:$bwport\"></object><BR />\n";
    }
}
print FILE << "HTML";
  </DIV></body>
  </html>
HTML

    close(FILE);
    return get_file("text/html", $htmlfile);
}

return 1;
