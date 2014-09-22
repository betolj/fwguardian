#!/usr/bin/perl

#Rev.0 - Version 5.0

# "POST /admin/chbanned.cgi" -> save or reload button
sub chbanned {
    my $s = shift;
    my $auxvalue;
    my @dvalue = ();
    my $auxtype;
    my $dtype = "routes";
    my $blctl = 0;
    my $count = 1;
    my $rtime = 2;
    my $dfile = "";
    my $bancur="", $bannew="";
    my @msg = ("", "");
    my @msg2 = ("", "");
    my $update = 1, $updateall = 1, $rlfw = 0;
    my $res = HTTP::Response->new();
    read_fwcfg;

    $dfile = $file_cfg{'accesslist/bannedroutes'};
    if ($s =~ /ReloadFw[AR]\=/) {
       $rlfw = 1;
       $dtype = "access" if ($s =~ /ReloadFwA/);
    }
    else {
      if ($s =~ /^lsAccess/) {
         $count = 0;
         $dtype = "access";
         $dfile = $file_cfg{'accesslist/bannedaccess'};
         $updateall = 0 if ($s =~ /^lsAccess=filtered/);
      }
    }

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && $canch == 1) {
       if (-e "$dfile") {
          my $fsize = -s "$dfile";
          system("echo '' >> $dfile") if ($fsize < 1);
       }

       open FILE, "<$dfile";
       open TMPFILE, ">/var/tmp/bannedfile";

       @dvalue = split /&/, $s;
       @dvalue = split /=/, $dvalue[1];
       $bancur = $dvalue[1];
       $bancur =~ s/---\+//;

       while (<FILE>) {
         $bannew = $_;
         $bannew =~ s/\n//g;
         $bannew =~ s/^[ |\t]*(port|net|resolv)[ |\t]+.*/$1/g;

         if ((eof FILE && $update == 1) || (($dtype eq "access") && ($bannew eq $bancur && $update == 1))) {
           if (eof FILE) {
              if ($dtype eq "routes") {
                 print TMPFILE $_ if ($bannew =~ /^[ |\t]*(#|;)/);
              }
              else {
                 print TMPFILE $_ if ($bannew ne $bancur && ($updateall < 1 || $bannew =~ /^[ |\t]*(#|;)/));
              }
           }
           foreach my $lines (split /&/, $s) {
             $lines =~ s/\+/ /g if ($lines =~ /\+/);
             @dvalue = split /=/, $lines;
             $dvalue[1] = str_conv($dvalue[1]);

             if ($dvalue[0] =~ /^[ |\t]*(lsAccess|lsRoute)$/) {
               if ($dvalue[1] =~ /^[ |\t]*--- (port|net|resolv)$/) {
                  print TMPFILE "\n" if ($count == 2);
                  $count = 1;
               }
               else {
                  if ($dvalue[1] !~ /^($|filtered)/ && $count > 0) {
                    print TMPFILE "$dvalue[1]\n" if ($dvalue[1] !~ /^$/ && $count > 0);
                    $count = 2;
                  }
               }
             }
             $blctl = 0;
             $update = 0;
             $updateall = 2 if ($updateall == 1);
           }
         }
         else {
           if ($_ =~ /^[ |\t]*(#|;|$)/ || (($bannew ne $bancur && $updateall == 0) && $dtype eq "access")) {
             if (!($_ =~ /^[ |\t]*($)/ && $blctl == 0) || $dtype eq "routes") {
                if ($_ !~ /^[ |\t]*(#|;|$)/) {
                  $blctl += 2;
                  print TMPFILE "\n" if ($blctl == 2);
                }
                print TMPFILE $_;
             }
           }
         }
       }
       close(FILE);
       close(TMPFILE);

       system("cp -f /var/tmp/bannedfile $dfile");
       system("rm -f /var/tmp/bannedfile 2>/dev/null");
       $msg[0] = "A lista negra foi atualizada (<font color=\'Navy\'><i>$dtype</i>)</font>!";
       $msg[1] = "The blacklist have been updated (<font color=\'Navy\'><i>$dtype</i></font>)!";
       $msg2[0] = "Clique em <strong><i>Aplicar</i></strong>.";
       $msg2[1] = "Click in <strong><i>Apply</i></strong>.";
       $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");

       rsyncupdate("$dfile", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
    }
    else {
       if ($canch == 1) {
          $msg[0] = "Aplicando as regras da lista negra (<font color=\'Navy\'>$dtype</font>)!";
          $msg[1] = "Applying the blacklist rules (<font color=\'Navy\'>$dtype</font>)!";
          $msg2[0] = "<font size=\'2\'>Regras definidas no arquivo banned$dtype!</font>";
          $msg2[1] = "<font size=\'2\'>Rules by banned$dtype file!</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "<font size=\'2\'>$msg2[$FW_LANG]");
          system("$FW_DIR/fwguardian --reload-banned $dtype 1>&2 2>/dev/null &");

          rsyncupdate("$dfile", "banned $dtype", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       }
       else {
         $rtime=0;
       }
    }

    my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/banned.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
    $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page banned.html"
sub get_banned {
    my $htmlfile="$HTMLDIR/admin/dynhttp/banned.html";
    my @auxtype = ();
    my $oldtype;
    my $newtype;
    read_fwcfg;

    ### Banned access list
    my @auxban = ();
    my %lsban = ();
    if (-e $file_cfg{'accesslist/bannedaccess'}) {
      open FILE, "<$file_cfg{'accesslist/bannedaccess'}";
      while (<FILE>)
      {
         if ($_ =~ /^[ |\t]*(port|net|resolv)/) {
           @auxban = split /[ |\t]+/, $_;
           push(@{$lsban{$auxban[0]}}, "$_");
         }
      }
      close (BAFILE);
    }

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making banned.html
    open FILE, ">$htmlfile";

print FILE << "javascript";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  <link href="/css/jquery-ui.css" type="text/css" rel="stylesheet" />
  <link href="/css/multi-select.css" type="text/css" media="screen" rel="stylesheet" />
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
         \$(".uibt_em" ).button();
         \$("#btcan").click(function() {
               document.location.reload(true);
               return false;
         });
         \$("#btrel1").click(function() {
               document.getElementById('chwait').style.display = 'block';
               document.fiBanned.ReloadFwR.click();
               return false;
         });
         \$("#btrel2").click(function() {
               document.getElementById('chwait').style.display = 'block';
               document.fiBanned.ReloadFwA.click();
               return false;
         });
         \$("#selFilter").select2();
         \$( "input[type=button]" ).button().css('font-size', '12px');
      });
  </script>

<script type="text/javascript">
<!--

function EnterKey(e, dtype)
{
   var key;
   if(window.event) key = window.event.keyCode;  //IE
   else key = e.which;  //firefox

   if(key == 13) {
     if (dtype == "rt") return selectall('rt');
     else return selectall('ac');
   }
   else return;
}

function newban(btype) {
  var canadd = 1;
  var ninput = "";
  if (btype == "rt") {
    var seldoc = document.fbanrt.lsRoute;
    var selid = 1;
javascript
$msg[0] = "Por favor entre com o endereço IP!";
$msg[1] = "Please enter the IP address!";
  print FILE << "javascript";
     ninput=prompt("$msg[$FW_LANG]","10.0.0.1");
  }
  else {
     var seldoc = document.fbanacc.lsAccess;
     var selid = document.fbanacc.FilterAc.selectedIndex;
     if (selid < 1) {
javascript
$msg[0] = "Selecione primeiro o tipo de filtro:\\\n- port, net ou resolv!";
$msg[1] = "Select the filter type first:\\\n- port, net or resolv!";
  print FILE << "javascript";
        alert('$msg[$FW_LANG]');
        return 0;
     }
     else {
javascript
$msg[0] = "Por favor identifique a porta, rede ou domínio!";
$msg[1] = "Please identify the port, network or domain!";
  print FILE << "javascript";
        var ftype = document.fbanacc.FilterAc.value;
        var auxftype = ftype;
        if (ftype === "port" ) ftype = "tcp 1863";
        else if (ftype === "net") ftype = "10.0.0.0/8";
        else ftype = "domain.com";
        ninput=prompt("$msg[$FW_LANG]", ftype);
        if (ninput !== null) ninput=auxftype + " " + ninput;
     }
  }

  if (selid > 0) {
    var rules = seldoc.length;

    for (var i = 0; i < seldoc.length ; i++) if (seldoc[i].value.replace(/\xC2\xA0/g, " ") == ninput) {
       canadd = 0;
       i = seldoc.length;
    }
    ninput = ninput.replace(/ |&nbsp;/g, "\xC2\xA0");
  
    if (canadd && ninput !== null) {
      document.fbanacc.FilterAc.disabled = true;
      seldoc.options[rules] = new Option(ninput, ninput, true, true);
      choptions(rules, btype);
    }
javascript
$msg[0] = "Este registro já existe!";
$msg[1] = "This record exist!";
print FILE "    else alert(\"$msg[$FW_LANG]\");\n";
print FILE << "javascript";
  }
}

function delban(btype) {
  var seldoc = document.fbanacc.lsAccess;
  if (btype == "rt") seldoc = document.fbanrt.lsRoute;

  var rules = seldoc.length;
  var ruleid = seldoc.selectedIndex;
  if (ruleid > -1) {
    var selval = seldoc[ruleid].value;
    var testval = /^(--- |filtered)/;
    if (selval && !testval.test(selval)) {
       seldoc[ruleid] = null;
       if (btype == "ac") document.fbanacc.FilterAc.disabled = true;
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

my $cl_lock=0;
$cl_lock=1 if ($canch ==0);

print FILE << "javascript";
}

function choptions(ruleid, btype) {
  var seldoc = document.fbanacc.lsAccess;
  if (btype == "rt") seldoc = document.fbanrt.lsRoute;
  var selvalue = seldoc[ruleid].value;

  if (selvalue.substring(0,3) == "---") {
    seldoc.options[ruleid].style.color = \'Black\';
    seldoc.options[ruleid].style.fontWeight = \'bold\';
  }
  else seldoc.options[ruleid].style.color = \'Black\';
}

function selectall(btype) {
  var cl_lock=$cl_lock;
  if (cl_lock) return false;
  document.getElementById('chwait').style.display = 'block';
  if (btype == "rt") {
     var seldoc = document.fbanrt.lsRoute;
     var selfrm = document.fbanrt;
  }
  else {
     var seldoc = document.fbanacc.lsAccess;
     var selfrm = document.fbanacc;
  }
  if (seldoc.length < 1) seldoc.options[0] = new Option("", "", false, false);

  seldoc.multiple = "true";
  var rules = seldoc.length;
  for ( var i=0; i<rules; i++ ) {
     seldoc.focus();
     seldoc.options[i].selected = "true";
     var auxvar = seldoc.options[i].value.replace(/(\xC2\xA0|\\s| )/g, " ");
     seldoc.options[i].value = auxvar; 
  }
  selfrm.submit();
}

javascript

    ### Make JavaScript Arrays (rule by profile)
    print FILE "\nfunction initarrays() {\n";
    print FILE "  if (document.fbanacc.FilterAc.selectedIndex < 1 ) return 0; \n";
    print FILE "  var seldoc = document.fbanacc.lsAccess; \n";
    print FILE "  var acfilter = document.fbanacc.FilterAc.value; \n";
    print FILE "  var rules = seldoc.length; \n";

    foreach my $baux ("port", "net", "resolv") {
      print FILE "  var arr$baux = new Array() ;\n";
      print FILE "  arr$baux.push(\"--- $baux\");\n";
      print FILE "  if (acfilter == \"$baux\") var arbanacc = arr$baux; \n";
      foreach (@{$lsban{"$baux"}}) {
        $_ =~ s/\n//;
        print FILE "  arr$baux.push(\"$_\");\n";
      }
    }

print FILE << "javascript";

  seldoc.length = 0;
  seldoc.options[0] = new Option("", "filtered", false, false);
  var lscount = 1;
  for ( var i in arbanacc ) {
    arbanaccvalue = arbanacc[i];
    arbanacc[i] = arbanacc[i].replace(/ |&nbsp;/g, "\xC2\xA0");

    seldoc.options[lscount] = new Option(arbanacc[i], arbanaccvalue, false, false);
    choptions(lscount);
    lscount++;
  }
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

    my @msg = ("", "");
    my @msg2 = ("", "");
    $msg[0] = "Lista negra - Rotas ou Filtro de Pacotes";
    $msg[1] = "Blacklist - Routes or Pkt Filter";
    my $mstyle = menustyle("$msg[$FW_LANG] ");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE>
  <span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG] ($srcfile)</span>

  <DIV align="center">
HTMLCODE

    $msg[0] = "<strong>Lista baseada em rotas</strong>: criar&aacute; rotas proibitivas!";
    $msg[1] = "<strong>Route Blacklist</strong>: will make prohibit routes!";
    $msg2[0] = "<strong>Lista baseada em Filtro de Pacotes</strong>: criar&aacute; bloqueios pelo netfilter (admite exce&ccedil;&otilde;es)!";
    $msg2[1] = "<strong>Pkt Filter Blacklist</strong>: will make netfilter blocks that can be bypassed!";

    print FILE "<DIV align=\"left\"><i>";
    print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 20px;\">";
    print FILE " 1. $msg[$FW_LANG]<BR />";
    print FILE " 2. $msg2[$FW_LANG]<BR />";
    print FILE "</span></i></DIV><BR /><BR />";

    ## Waiting form
    print FILE "<DIV align=\"center\" valign=\"center\" id=\"chwait\">";
    $msg[0] = "Aguarde... isto pode demorar um pouco!";
    $msg[1] = "Wait... this may take a little time!";
    print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
    print FILE "</DIV>";

    print FILE "<p><table align='center' border='0' cellpadding='0' cellspacing='0' width='60%' height='40%'><tbody><tr>";
    print FILE "<form name='fbanrt' action='/admin/chbanned.cgi' method='POST'><TD align='left' valign='center' width='50%'>";
    print FILE "<FONT style='font-size:small; Font-Family: Arial, Helvetica;'>";
    $msg[0] = "Rotas";
    $msg[1] = "Routes";
    print FILE "<i>$msg[$FW_LANG]</i></FONT><BR />";
    $msg[0] = "Rotas proibidas";
    $msg[1] = "Prohibit routes";

    ### Reading banned routes and access files
    print FILE "<div class='custom-header' style='background-color:#A4A4A4; border:0px; color:white; text-align:center; font-size:13px; width:240px'>$msg[$FW_LANG]</div>";
    print FILE "<SELECT size='16' name='lsRoute' style='width: 240px; border:1px solid #A4A4A4; color: #555; font-size: 14px;'>";
    print FILE "<OPTION></OPTION>";
    if (-e $file_cfg{'accesslist/bannedroutes'}) {
      open BRFILE, "<$file_cfg{'accesslist/bannedroutes'}";
      while (my $lines = <BRFILE>) {
        if ($lines !~ /^[ |\t]*(#|;|$)/) { 
          substr($lines, index($lines, '\n'), 1) = '';
          print FILE "<OPTION value=\"$lines\">$lines</OPTION>";
        }
      }
    }
    print FILE "</select><BR />";
    print FILE "<INPUT type=\"button\" value=\"+\" onclick=\"return newban(\'rt\');\" style=\"Font-Family: Arial, Helvetica;\">";
    print FILE "<INPUT type=\"button\" value=\"-\" onclick=\"return delban(\'rt\');\" style=\"Font-Family: Arial, Helvetica;\"> ";
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE "<INPUT type=\"button\" value=\"$msg[$FW_LANG]\" onclick=\"return selectall('rt')\" style=\"Font-Family: Arial, Helvetica;\">";
    print FILE "</td>";
    print FILE "</form>";
    close (BRFILE);

    print FILE "<form name='fbanacc' action='/admin/chbanned.cgi' method='POST'>";
    print FILE "<TD align='left' valign='center' width='50%'>";
    print FILE "<FONT style='font-size:small; Font-Family: Arial, Helvetica;'>";
    $msg[0] = "Filtro de Pacotes";
    $msg[1] = "Pkt Filter Blacklist";
    print FILE "<i>$msg[$FW_LANG]</i></FONT><BR />";
    $msg[0] = "Senten&ccedil;as proibidas";
    $msg[1] = "Denied sentences";
    print FILE "<div class='custom-header' style='background-color:#A4A4A4; border:0px; color:white; text-align:center; font-size:13px; width:240px'>$msg[$FW_LANG]</div>";
    print FILE "<SELECT size='16' name='lsAccess' style='width: 240px; border:1px solid #A4A4A4; color: #555; font-size: 14px;'>";

    foreach my $baux ("port", "net", "resolv") {
      print FILE "<OPTION></OPTION><OPTION style='color:Black;font-Weight:Bold' value=\"--- $baux\">--- $baux</OPTION>";
      foreach (@{$lsban{"$baux"}}) {
        if ($_ !~ /^[ |\t]*(#|;|$)/) { 
          $_ =~ s/\n//;
          print FILE "<OPTION value=\"$_\">$_</OPTION>";
        }
      }
    }
    print FILE "</select><BR />";

    ### Include or delete a denied sentence
    print FILE "<SELECT id=\"selFilter\" name=\"FilterAc\" onchange=\"return initarrays();\" style='width:100px; font-size:small;'>";
    $msg[0] = "Filtro";
    $msg[1] = "Filter";
    print FILE "<OPTION>-- $msg[$FW_LANG] --</OPTION><OPTION value=\"port\">port</OPTION><OPTION value=\"net\">net</OPTION><OPTION value=\"resolv\">resolv</OPTION></SELECT>&nbsp; ";
    print FILE "<INPUT type=\"button\" name=\"AddRule\" value=\"+\" onclick=\"return newban('ac');\" style=\"Font-Family: Arial, Helvetica;\">";
    print FILE "<INPUT type=\"button\" value=\"-\" onclick=\"return delban(\'ac\');\" style=\"Font-Family: Arial, Helvetica;\"> ";
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE "<INPUT type=\"button\" value=\"$msg[$FW_LANG]\" onclick=\"return selectall('ac')\" style=\"Font-Family: Arial, Helvetica;\"> ";

    print FILE "<BR /></td></form></tr>";
    print FILE "</tbody></table></p>";
    print FILE "$srcfs";

    ### Finish banned.html
    print FILE "<BR /><BR />";
    print FILE "<form name=\"fiBanned\" action=\"/admin/chbanned.cgi\" method=\"post\">";
    $msg[0] = "Aplicar Rotas";
    $msg[1] = "Apply Routes";
    $msg2[0] = "Aplicar Filtro de Pct";
    $msg2[1] = "Apply Pkt Filter";
    print FILE "<INPUT type=\"submit\" name=\"ReloadFwR\" value=\"$msg[$FW_LANG]\" style=\"visibility:hidden; position:absolute;\">";
    print FILE "<INPUT type=\"submit\" name=\"ReloadFwA\" value=\"$msg2[$FW_LANG]\" style=\"visibility:hidden; position:absolute;\">";
    $msg[0] = "Cancelar";
    $msg[1] = "Cancel";
    print FILE "<a href=\"#\" id=\"btcan\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
    $msg[0] = "Aplicar rotas";
    $msg[1] = "Apply routes";
    print FILE " &nbsp; <a href=\"#\" id=\"btrel1\" class=\"uibt\">$msg[$FW_LANG]</a>";
    $msg[0] = "Aplicar filtro pct";
    $msg[1] = "Apply access filters";
    print FILE " <a href=\"#\" id=\"btrel2\" class=\"uibt\">$msg[$FW_LANG]</a>";

    print FILE "</form></DIV></body>";
    print FILE "</HTML>"; 
    close(FILE);

    return get_file("text/html", $htmlfile);
}

return 1;
