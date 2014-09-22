#!/usr/bin/perl

#Rev.0 - Version 5.0

# "POST /admin/chsrcctl.cgi" -> save button
sub chsrcctl {
    my $s = shift;
    my $txtvalue;
    my @dvalue = ();
    my @msg = ("", ""), @msg2 = ("", "");
    my $res = HTTP::Response->new();

    $s =~ s/\&Save([\s]*|$)//g;
    read_fwcfg;

    $txtvalue = $s;
    @dvalue = split /=/, $s;

    system("echo $dvalue[1] > /usr/share/fwguardian/webauth/control/sourcefile");
    rsyncupdate("/usr/share/fwguardian/webauth/control/sourcefile", "sourcefile", "change");

    $msg[0] = "Nova defini&ccedil;&atilde;o de origem (cluster):";
    $msg[1] = "New source definition (cluster):";
    $txtvalue = msgbox("info", "$msg[$FW_LANG] <FONT color=\"Navy\">$dvalue[1]</FONT>", "");

    my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"2;URL=/admin/srcctl.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
    $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page srcctl.html"
sub get_srcctl {
    my $htmlfile="$HTMLDIR/admin/dynhttp/srcctl.html";
    my @srclist = ();
    my @msg = ("", "");
    my $cksource = "";
    read_fwcfg;

    ### Making srcctl.html
    open FILE, ">$htmlfile";

print FILE << "javascript";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  <link href="/css/jquery-ui.css" type="text/css" rel="stylesheet" />
  <link href="/css/select2.css" type="text/css" media="screen" rel="stylesheet" />

  <style type="text/css">
    html, body {
       margin: 0;
       padding: 0;
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
  <script type="text/javascript" src="/js/select2.min.js"></script>

  <script type="text/javascript">
        \$(function() {
           \$(".uibt" ).button();
           \$("#btsav").click(function() {
                 document.frtype.Save.click();
                 return false;
           });
           \$("#lsource").select2();
        });
  </script>

javascript

    $msg[0] = "Grupo de controle (defini&ccedil;&otilde;es de arquivo)";
    $msg[1] = "Group control (file definitions)";
    my $mstyle = menustyle("$msg[$FW_LANG]");
    print FILE "$mstyle";

print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE>
  <p><span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG]</span></p>

  <DIV align="center">
HTMLCODE

    print FILE "<DIV align=\"left\"><i>";
    print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 20px;\">";
    if ($FW_LANG == 0) {
       print FILE "1. Este modulo lhe ajudar&aacute; na configura&ccedil;&atilde;o padrão ou em cluster (Regras de Input, Forward ou lista de banimento).<BR />\n";
       print FILE "2. Selecione o grupo do cluster ou *default* que voc&ecirc; deseja configurar.\n";
    }
    else {
       print FILE "1. This module help you to configure default or cluster files (Input and Forward Rules or Banned Access).<BR />\n";
       print FILE "2. To do this, select the cluster group or *default* that you should like to configue.\n";
    }
    print FILE "</span></i><BR /><BR /><BR />";

    print FILE "<form name=\"frtype\" action=\"/admin/chsrcctl.cgi\" method=\"POST\">";
    print FILE "<span style=\"Position: Relative; Left: 20px;\">";
    $msg[0] = "Fonte:";
    $msg[1] = "Source:";
    print FILE "$msg[$FW_LANG] <select id='lsource' name='lsSource' style='width:180px; font-size:small;'>";
    print FILE "<OPTION value=\"default\">default</OPTION>"; 
    @srclist = `grep group /opt/fw5.0/cluster/gluster.mapps | sed 's/.*\\s\\+//'`;
    foreach my $rsync (@srcrsync) {
      push(@srclist, "$rsync");
    }
    foreach (@srclist) {
       $_ =~ s/\n//;
       $cksource = "";
       $cksource = "Selected" if ($srcfile eq $_);
       print FILE "<OPTION value=\"$_\" $cksource>$_</OPTION>";
    }
    print FILE "</select></span>";
    print FILE "<INPUT type=\"submit\" name=\"Save\" value=\"Save\" style=\"visibility:hidden; position:absolute;\">";
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 40px;\">";
    print FILE "<a href=\"#\" id=\"btsav\" class=\"uibt\">$msg[$FW_LANG]</a></span>";

    print FILE "</DIV></form></DIV></body></HTML>";
    close(FILE);

    return get_file("text/html", $htmlfile); 
}

return 1;
