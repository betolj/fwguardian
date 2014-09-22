#!/usr/bin/perl

#Rev.1 - Version 5.0

# "POST /admin/chmodules.cgi" -> save button
sub chmodules {
    my $s = shift;
    my $res = HTTP::Response->new();
    read_fwcfg;

    my %modules = ();
    my $rlfw = 0;
    my $rtime = 2;
    my $mcheck = "";
    my $txtvalue = "";
    my @msg = ('', ''), @msg2 = ('', '');

    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile ne "default" || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && $canch == 1) {
       # Setting "off" for all firewall modules
       foreach my $lines (`$HTMLDIR/../../fwguardian --show-modules | tail -n +2`) {
          my ($line, $auxline) = split(/[\s]+/, $lines, 2);
          if ($mcheck ne "disabled") {
             $mcheck = "";
             if ($auxline ne "" && $mcheck ne "disabled") {
                $line =~ s/\n//;
                $modules{$line} = "off";
             }
             else {
                $mcheck = "disabled";
             }
          }
       }
       # Setting "on" only to the checked modules
       foreach my $lines (split /&/, $s) {
           $lines =~ s/\+/ /g if ($lines =~ /\+/);
           my @dvalue = ();
           @dvalue = split /=/, $lines;
           if ($dvalue[0] ne "Save") {
              $dvalue[1] = str_conv($dvalue[1]);
              $modules{$dvalue[0]} = "on";
           }
       }
       # Apply module confs
       $msg[0] = "Configuração aplicada com sucesso!";
       $msg[1] = "Configuration applied successfully!";
       $txtvalue = msgbox("info", "$msg[$FW_LANG]", "");

       foreach $key (keys %modules) {
          if ($modules{$key} eq "on") { system("$HTMLDIR/../../fwguardian --enable $key" ); }
          else { system("$HTMLDIR/../../fwguardian --disable $key" ); }
       }

       rsyncupdate("modules", "default", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && $srcfile eq "default");
    }
    else {
       if ($canch == 1) {
          $msg[0] = "Aplicando as regras de firewall!";
          $msg[1] = "Applying firewall rules!";
          $msg2[0] = "<font size=\'2\'>Recarregando todas as regras...</font>";
          $msg2[1] = "<font size=\'2\'>Full reloading...</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "<font size=\'2\'>$msg2[$FW_LANG]</font>");

          system("$FW_DIR/fwguardian --ignore-cluster 1>&2 2>/dev/null &") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
          system("$FW_DIR/fwguardian --ignore-webserver 1>&2 2>/dev/null &");
          system("$FW_DIR/fwguardian 1>&2 2>/dev/null &");
       }
       else {
          $rtime = 0;
       }
    }

    my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/modules.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
    $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page modules.html" 
sub get_modules {
    my $htmlfile="$HTMLDIR/admin/dynhttp/modules.html";
    read_fwcfg;

    my @msg = ("", "");

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile ne "default" || not -e "/var/tmp/cluster.manager"));

    my $cl_lock=0;
    $cl_lock=1 if ($canch == 0);

    ### Making alias.html
    open FILE, ">$htmlfile";

print FILE << "javascript";
<html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />

  <link href="/css/ui.jqgrid.css" type="text/css" rel="stylesheet" />
  <link href="/css/jquery.checkbox.css" type="text/css" rel="stylesheet" />
  <link href="/css/jquery-ui.css" type="text/css" rel="stylesheet" />
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
    .ui-jqgrid
    { 
       font-size: 14px;
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

  </style>

  <script type="text/javascript" src="/js/jquery-1.7.2.min.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.core.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.widget.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.button.js"></script>
  <script type="text/javascript" src="/js/jquery.checkbox.min.js"></script>
  <script type="text/javascript">
        \$(function() {
           \$(".uibt" ).button();
           \$(".uibt_em" ).button();
           \$("#btsav").click(function() {
                 var cl_lock=$cl_lock;
                 if (!cl_lock) {
                    document.getElementById('chwait').style.display = 'block';
                    document.frtype.Save.click();
                 }
                 return false;
           });
           \$("#btrel").click(function() {
                 document.frtype.ReloadFw.click();
                 return false;
           });
        });
  </script>

  <script type="text/javascript">
      \$(document).ready(function() {
          \$('input:checkbox:not([safari])').checkbox();
      });
  </script>\n\n
javascript

    my $srcfs = "";
    if ($canch == 0) {
       $msg[0] = "Somente leitura (nó escravo) - a alteração é feita no grupo *default*!";
       $msg[1] = "Read-only (slave node) - The change is made in *default* group!";
       $srcfs = "<h5><FONT color=\"Red\"><strong>$msg[$FW_LANG]</strong></FONT></h5>";
    }

    $msg[0] = "Módulos do Firewall";
    $msg[1] = "Firewall Modules";
    my $mstyle = menustyle("$msg[$FW_LANG]");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE>
  <p><span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG] ($srcfile)</span></p>

  <DIV align="center">
HTMLCODE

    ## Waiting form
    print FILE "<DIV align=\"center\" valign=\"center\" id=\"chwait\">";
    $msg[0] = "Aguarde... isto pode demorar um pouco!";
    $msg[1] = "Wait... this may take a little time!";
    print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
    print FILE "</DIV>";

    my %modules = ();
    print FILE "<form name='frtype' style='font-size: 0.92em;' action='/admin/chmodules.cgi' method='POST' action='/admin/chmodules.cgi' >";
    print FILE "<table border='0' cellspacing='0' cellpadding='0' width='100%'><tbody><TR valign='bottom'><TD width='92%'>";
    foreach my $lines (`ls /usr/share/fwguardian/modules/* 2>/dev/null | sed \'s/.*\\\/\/\/;s/\\.ctl\$//\'`) {
       $lines =~ s/\n//;
       $modules{$lines} = "ok";
    }
    my $mcheck = "";
    foreach my $lines (`$HTMLDIR/../../fwguardian --show-modules | tail -n +2`) {
       my ($line, $auxline) = split(/[\s]+/, $lines, 2);
       if ($mcheck ne "disabled") {
          $mcheck = "";
          if ($auxline ne "" && $mcheck ne "disabled") {
             $line =~ s/\n//;
             $mcheck = "checked" if ($modules{$line} && $modules{$line} eq "ok");
             print FILE "<p>&nbsp; &nbsp; <input name=\"$line\" type=\"checkbox\" id=\"check\" $mcheck> <strong> &nbsp; $line</strong> - $auxline</p>";
          }
          else {
             $mcheck = "disabled";
          }
       }
    }
    print FILE "</TD></TR></tbody></table><BR />";
    print FILE "<INPUT type=\"submit\" name=\"Save\" value=\"Save\" style=\"visibility:hidden; position:absolute;\">";
    print FILE "<INPUT type=\"submit\" name=\"ReloadFw\" value=\"Reload firewall\" style=\"visibility:hidden; position:absolute;\">";
    print FILE "$srcfs";
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE "<a href=\"#\" id=\"btsav\" class=\"uibt\">$msg[$FW_LANG]</a>";
    $msg[0] = "Aplicar";
    $msg[1] = "Apply";
    print FILE " <a href=\"#\" id=\"btrel\" class=\"uibt\">$msg[$FW_LANG]</a>";
    print FILE "</form></DIV></body>";
    print FILE "</HTML>";
    close(FILE);

    return get_file("text/html", $htmlfile);
}

return 1;
