#!/usr/bin/perl

#Rev.2 - Version 5.0

# "POST /admin/chfwprof.cgi" -> save or reload button
sub chfwprof {
    my $s = shift;

    my $rlfw = 0;
    my $chkmac = 0;
    my $canSync = 0;
    my $txtvalue = "";
    my @msg = ("", ""), @msg2 = ("", "");
    my $res = HTTP::Response->new();
    read_fwhosts;

    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && $canch == 1) {

       # Parsing json response (sorting by ID)
       my %json = ();
       my %htname = ();
       my @htset = ();
       my @unsortId = ();
       my %unsortData = ();
       $txtvalue = "NO";

       foreach my $auxjson (split /"[0-9]+":/, $s) {
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
                if ($dvalue[1]) {
                   if ($dvalue[0] =~ /h(Name|Mac|Prof)$/ || $dvalue[0] eq "Src") {
                      $json{$dvalue[0]} = pack( 'A20', str_conv($dvalue[1])) if ($dvalue[1] !~ /^[\s]*$/);
                   }
                   elsif ($dvalue[0] eq "hLog") {
                      $json{'hLog'} = "";
                      $json{'hLog'} = "log" if ($dvalue[1] eq "Yes");
                   }
                   elsif ($dvalue[0] eq "hProtect") {
                      $json{'hProtect'} = "";
                      $json{'hProtect'} = "protect" if ($dvalue[1] eq "Yes");
                   }
                   elsif ($dvalue[0] eq "hNobanned") {
                      $json{'hNobanned'} = "";
                      $json{'hNobanned'} = "nobanned" if ($dvalue[1] eq "Yes");
                   }
                   elsif ($dvalue[0] eq "Cond") {
                      $json{'Cond'} = "";
                      $json{'Cond'} = "$dvalue[1]" if ($dvalue[1] ne "none");
                   }
                   elsif ($dvalue[0] =~ /^(Control|hDefaults|id)/) {
                      if ($dvalue[0] eq "hDefaults") {
                         $json{$dvalue[0]} = str_conv($dvalue[1]);
                      }
                      else {
                         $json{$dvalue[0]} = $dvalue[1];
                      }
                      $chkmac = 1 if ($dvalue[0] eq "Control" && $json{'Control'} eq "chkmac");
                   }
                   elsif ($dvalue[0] eq "fLog" || $dvalue[0] eq "Desc") {
                      $json{$dvalue[0]} = str_conv($dvalue[1]);
                   }
                }
             }
             $json{'hProtect'} = "protect" if ($json{'hNobanned'} eq "nobanned");
             $json{'hLog'} = "log" if ($json{'hProtect'} eq "protect");

             if (($json{'hName'} ne "" && $json{'Src'} ne "" && $json{'hMac'} ne "" && $json{'hProf'} ne "") && $json{'Control'} ne "set") {
                $canSync = 1;

                # Checking MAC address
                if ($json{'Cond'} ne "disabled") {
                   my $auxmac = $json{'hMac'};
                   $auxmac =~ s/[\s]+$//;
                   $auxmac =~ s/!//;
                   if ($chkmac == 1 || $json{'Cond'} eq "mac-check" || $auxmac =~ /^(detect|mac-detect)/) {
                      my $tg_dev = `ip route get $json{'Src'} | head -1 | sed 's/.* dev \\([a-zA-Z0-9\\.@]\\+\\) .*/\\1/' | tr -d '\\n'`;
                      $tg_dev = "-I $tg_dev" if (length($tg_dev) > 2);
                      $json{'hMac'} = `arping -w1 -c1 $json{'Src'} $tg_dev | grep reply | sed 's/.* \\[\\(.*\\)\\] .*/\\1/' | tr -d '\\n'`;
                   }
                   if ($json{'hMac'} ne $auxmac && $json{'hMac'} ne "") {
                      $json{'Cond'} = "mac-check" if ($auxmac !~ /^(detect|mac-detect)/ && $chkmac == 1);
                   }
                   else {
                      $json{'hMac'} = $auxmac;
                   }
                   $json{'Cond'} = "mac-check" if ($json{'hMac'} =~ /^(detect|mac-detect)/);
                }
                $json{'hMac'} = pack ( 'A20', "$json{'hMac'}" );

                # HOST profile rules
                my $auxname = $json{'hName'};
                $auxname =~ s/[\s]+$//;
                if ($json{'Cond'} eq "disabled" || $htname{$auxname} ne $auxname) {
                   $htname{$auxname} = $auxname if ($json{'Cond'} ne "disabled");

                   my $auxentry = "$json{'hName'} $json{'Src'} $json{'hMac'} $json{'hProf'}";
                   $auxentry = "$auxentry $json{'hLog'}" if ($json{'hLog'});
                   $auxentry = "$auxentry $json{'hProtect'}" if ($json{'hProtect'});
                   $auxentry = "$auxentry $json{'hNobanned'}" if ($json{'hNobanned'});
                   $auxentry = "$auxentry chk=$json{'Cond'}" if ($json{'Cond'});
                   $auxentry = "$auxentry log-desc=\"$json{'fLog'}\"" if (length($json{'fLog'}) > 1);
                   $auxentry = "$auxentry desc=\"$json{'Desc'}\"" if (length($json{'Desc'}) > 1);
                   push(@unsortId, $json{'id'});
                   push(@{$unsortData{$json{'id'}}}, $auxentry);
                }
             }
             if ($json{'Control'} eq "set" || $json{'hDefaults'} ne "") {
                my ($set1, $set2) = split /\//, $json{'hDefaults'};
                push(@htset, "set protect on \"$set1\"");
                push(@htset, "set log \"$set2\"");
                $canSync = 1;
             }
          }
       }
       if ($canSync == 1) {
          open FILE, ">$file_cfg{'fwhosts'}";

          # Writing fwhosts comments
          foreach my $htRules (@fwhostcomments) {
              $htRules =~ s/\n//;
              $htRules =~ s/\\"/\"/g;
              $htRules =~ s/\\'/\'/g;
              print FILE "$htRules\n" if ($htRules);
          }

          # Writing fwhosts set definitions
          print FILE "\n";
          foreach my $htRules (@htset) {
              $htRules =~ s/\n//;
              $htRules =~ s/\\"/\"/g;
              $htRules =~ s/\\'/\'/g;
              print FILE "$htRules\n" if ($htRules);
          }

          # Writing fwhosts rules
          print FILE "\n";
          my @sortedId = sort { $a <=> $b } @unsortId;
          foreach (@sortedId) {
             foreach my $line (@{$unsortData{"$_"}}) {
                print FILE "$line\n";
             }
          }
          close(FILE);
          $txtvalue="OK";

          rsyncupdate("$file_cfg{'fwhosts'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
    }
    else {
       my $rtime = 2;
       if ($canch == 1) {
          $msg[0] = "Recarregando as regras de firewall!";
          $msg[1] = "Reloading firewall rules!";
          $msg2[0] = "<font size=\'2\'>Recarregando os perfis...</font>";
          $msg2[1] = "<font size=\'2\'>Reloading the hosts profile...</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
          system("$FW_DIR/fwguardian --reload-fwhosts 1>&2 2>/dev/null &");

          rsyncupdate("$file_cfg{'fwhosts'}", "fwhosts", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       }
       else {
          $rtime = 0;
       }
       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/fwprof.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page fwprofile.html"
sub get_fwprofile {
    my $htmlfile="$HTMLDIR/admin/dynhttp/fwprofile.html";
    read_profiles;
    read_fwhosts;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $defSrc = `ip route ls scope link | grep 'proto kernel' | head -1 | sed 's/.* src \\([0-9.]\\+\\) .*/\\1/'`;
    $defSrc =~ s/\n//;

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making fwprofile.html
    splitalias;
    open FILE, ">$htmlfile";

print FILE << "javascript";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />

  <link href="/css/ui.jqgrid.css" type="text/css" rel="stylesheet" />
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
       z-index: 1;
    }
    .ui-jqgrid .ui-pg-table 
    { 
       font-size: 12px;
       color: #2e6e9e;
       z-index: 1;
    }
    .ui-jqgrid .ui-state-highlight td {
       font-size: 13px;
       color: Black;
       background-color: #A4A4A4;
    }
    .ui-jqgrid
    { 
       font-size: 14px;
       color: #2e6e9e;
       z-index: 1;
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
  <script type="text/javascript" src="/js/i18n/grid.locale-en.js"></script>
  <script type="text/javascript" src="/js/i18n/grid.locale-pt-br.js"></script>
  <script type="text/javascript" src="/js/jquery.jqGrid.min.js"></script>
  <script type="text/javascript" src="/admin/js/gridctl.js"></script>
  <script type="text/javascript">
        jQuery.jgrid.no_legacy_api = true;
        jQuery.jgrid.useJSON = true;

        \$(function() {
           \$(".uibt" ).button();
           \$(".uibt_em" ).button();
           \$("#btsav").click(function() {
                 fHostGrid.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 fHostGrid.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.flsFwProf.ReloadFw.click();
                 return false;
           });
        });
  </script>

  <script type="text/javascript">
     jQuery(document).ready(function(){

        // Rules array
        var saveall = 0;
        var rulesCt = 0;
        var newRow = new Array();
        var rulesGrid = new Array();         // Main data

        // Make jqgrid
        var scrollPosition = 0;
        jQuery("#fwHostGrid").jqGrid({
           url:'/admin/getfwhosts.json',
           datatype: "json",
           height: \$(window).height() - 270,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'Nome', 'IP de origem', 'End. MAC', 'Perfil', 'Log', 'Proteger', 'Não banir', 'Condição', 'Log info', 'Descrição', 'Control', 'defaults' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'Name', 'Source IP', 'MAC addr.', 'Profile', 'Log', 'Protect', 'No banned', 'Condition', 'Log info', 'Description', 'Control', 'defaults' ],\n";
}
$msg[0] = selGridifnet("ipnet");
my $halias = $msg[0];
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id', sortable:true, sorttype: "int", key: true, width:30 },
              { name:"hName",   index:'hName', sortable:true, editable:true, width:100 },
              { name:"Src",     index:'Src', sortable:true, editable:true, width:140 },
              { name:"hMac",    index:'hMac', sortable:true, editable:true, width:140 },
javascript
    $msg[0] = "LOG:LOG;%A:ACCEPT;%D:DROP;%R:REJECT";
    foreach (@fwprof) {
       $_ =~ s/\n//;
       if ($_ !~ /chk=disabled$/) {
          $_ =~ s/\?chk=.*//;
          my $line = "$_:$_";
          $msg[0] = "$msg[0];$line" if ($_ !~ /^[\s]*(mangle:|rsquid|vpop3)/);
       }
    }
print FILE "{ name:\"hProf\",  index:'hProf', sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:100 },\n";
print FILE << "javascript";
              { name:"hLog",   index:'hLog', sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, width:60 },
              { name:"hProtect",  index:'hProtect', sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, width:60 },
              { name:"hNobanned", index:'hNobanned', sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, width:80 },
javascript
    $msg[0] = "none:none;disabled:disabled;mac-check:mac-check";
    foreach (@fwchk) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       $msg[0] = "$msg[0];$line";
    }
print FILE "{ name:\"Cond\",  index:'Cond', sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:120 },\n";
print FILE << "javascript";
              { name:"fLog",  index:'fLog', sortable:false, editable:true, dataType:'string', width:250 },
              { name:"Desc",  index:'Desc', sortable:false, editable:true, dataType:'string', width:320 },
              { name:"Control", index:'Control', sortable:false, editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 },
              { name:"hDefaults",  index:'hDefaults', sortable:false, editable:true, hidden:true, dataType:'string', width:380 }
           ],
           pager: '#pfwHostGrid',
           editurl: 'clientArray',
           rowNum: '',
           rowList: [],
           sortname: 'id',
           pgbuttons: false,
           pgtext: null,
           gridview: true,
           viewrecords: false,
           sortable: true,
           shrinkToFit: false,
           ondblClickRow: function (selid, iRow,iCol) {
              editRow(jQuery("#fwHostGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$halias", "fwprof");
              newRow = updnewRow();
           },
           gridComplete: function(data, response) {
              rulesGrid=GridComplete(jQuery("#fwHostGrid"), rulesGrid, rulesCt, saveall, "fwprof");

              rulesCt++;
              saveall = 0;
              jQuery("#fwHostGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Perfil de acesso por IP";
$msg[1] = "Access profile per IP";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#fwHostGrid").css('font-size', '13px');
        jQuery("#fwHostGrid").jqGrid('navGrid',"#pfwHostGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#fwHostGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwprof");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#fwHostGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwprof");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Edit button
        \$("#fwHostGrid").jqGrid('navButtonAdd','#pfwHostGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#fwHostGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$halias", "fwprof");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#fwHostGrid").jqGrid('navButtonAdd','#pfwHostGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             document.getElementById('enMac').checked = true;
             rulesGrid = cloneRow(jQuery("#fwHostGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwprof", "$defSrc");
             newRow = updnewRow();
           }
        });

        // Delete row in click event
        jQuery("#delgd").click( function() {
javascript
$msg[0] = "Por favor... selecione a linha a ser removida!";
$msg[1] = "Please... Select the line to delete!";
print FILE << "javascript";
           rulesCt = 1;
           rulesGrid = delRow(jQuery("#fwHostGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
        });

        // Add button
        \$("#fwHostGrid").jqGrid('navButtonAdd','#pfwHostGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             document.getElementById('enMac').checked = true;
             rulesGrid = addRow(jQuery("#fwHostGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwprof", "$defSrc", "$halias");
             newRow = updnewRow();
           }
        });

        // Saving all rows in click event
        jQuery("#savegd").click( function() {
javascript
$msg[0] = "INFO: Regras atualizadas com sucesso!";
$msg[1] = "INFO: Rules updated successfully!";
my $cl_lock=0;
$cl_lock=1 if ($canch == 0);
print FILE << "javascript";
           var cl_lock=$cl_lock;
           if (cl_lock) return false;
           saveall = 1;
           rulesCt = 0;
           saveAll(jQuery("#fwHostGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "fwprof", "/admin/getfwhosts.json", "/admin/chfwprof.cgi");
           newRow = updnewRow();
        });

        \$("#fwHostGrid").jqGrid('navButtonAdd','#pfwHostGrid',{
           caption:"&nbsp; Info",
           onClickButton:function(){
             var selid = jQuery("#fwHostGrid").jqGrid('getGridParam','selrow');
             var clret = jQuery("#fwHostGrid").jqGrid('getRowData', selid);
             if (clret['Desc'] !== "") alert(clret['Desc']);
           }
        });

        // Grid resize
        \$(window).bind('resize', function() {
            \$("#jqgrid").setGridWidth(\$(window).width() - 120);
        }).trigger('resize');
     });
  </script>

<script type="text/javascript">
<!--

function MacTest() {
   var regex = /^(([0-9A-F]{2}[:-]){5}[0-9A-F]{2}|mac\-detect)\$/i;
   var mac = document.flsFwProf.profmacaddr.value;
   if ( mac == "mac-detect" || mac == "detect" ) return;
   if( regex.test( mac ) ){
       return;
   }  
   else {
javascript
$msg[0] = "Endereço MAC inválido!";
$msg[1] = "Invalid MAC Address!";
print FILE "       alert(\"$msg[$FW_LANG]\");\n";
print FILE << "javascript";
       return false;
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

    $msg[0] = "Filtro de pacotes: Atribuir perfil";
    $msg[1] = "Packet filter: Profile rules";
    my $mstyle = menustyle("$msg[$FW_LANG]");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE>
  <span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG] ($srcfile)</span>

  <DIV align="center">
HTMLCODE

    ## Default options
    foreach my $lines (@fwhostset) {
       if ($lines =~ /set[\s]+protect[\s]+on[\s]/) {
          $protectif = $lines;
          $protectif =~ s/set[\s]+protect[\s]+on[\s]+//;
       }
       else {
          $deflogdesc = $lines;
          $deflogdesc =~ s/set[\s]+log[\s]+//;
       }
    }

    ## Waiting form
    print FILE "<DIV align=\"center\" valign=\"center\" id=\"chwait\">";
    $msg[0] = "Aguarde... isto pode demorar um pouco!";
    $msg[1] = "Wait... this may take a little time!";
    print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
    print FILE "</DIV>";

    ### Grid rules
    print FILE "<FORM name=\"flsFwProf\" action=\"/admin/chfwprof.cgi\" method=\"post\">";
    print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
    print FILE "<tbody><TR valign=\"bottom\" align=\"left\"><TD width=\"96%\">";
    print FILE "<p><FONT size=\"-1\">";
    $msg[0] = "Verificar MAC (todas regras)";
    $msg[1] = "Enable MAC checks (all rules)";
    print FILE "<i>$msg[$FW_LANG]</i> <INPUT type=\"checkbox\" id=\"enMac\" name=\"CkenMac\">";
    $msg[0] = "Apelidos";
    $msg[1] = "Alias";
    print FILE " &nbsp; &nbsp; <i>$msg[$FW_LANG]</i> <INPUT type=\"checkbox\" id=\"enAlias\" name=\"CkenAlias\">\n";
    $msg[0] = "Interfaces Protegidas";
    $msg[1] = "Protected Interfaces";
    print FILE "  &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; <i>$msg[$FW_LANG]</i> </FONT>&nbsp;";
    print FILE "<input name=\"protectif\"  id=\"hProtIf\" style=\"background-color: #bec2c8;\" type=\"textbox\" size=\"12\" value=\"$protectif\">&nbsp;";
    print FILE "<input name=\"deflogdesc\" id=\"hProtDesc\" style=\"background-color: #bec2c8;\" type=\"textbox\" size=\"30\" value=\"$deflogdesc\"></p>";
print FILE << "HTMLCODE";
    <table id="fwHostGrid" width="100%" style="font-size:12px;"></table>
    <div id="pfwHostGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
    print FILE "</TD><TD width=\"4%\">";
    print FILE "&nbsp;<a href=\"javascript: document.fHostGrid.gdmoveup.click();\">";
    print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "&nbsp;<a href=\"javascript: document.fHostGrid.gdmovedown.click();\">";
    print FILE "<img src=\"buttons/mv_down.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "</TD></TR></tbody></table>";
    print FILE "<INPUT type=\"submit\" name=\"ReloadFw\" value=\"Reload firewall rules\" style=\"visibility:hidden; position:absolute;\">";
    print FILE "</FORM><BR />";
    print FILE "$srcfs";
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE "<a href=\"#\" id=\"btsav\" class=\"uibt\">$msg[$FW_LANG]</a>";
    $msg[0] = "Cancelar";
    $msg[1] = "Cancel";
    print FILE " &nbsp; <a href=\"#\" id=\"btcan\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
    $msg[0] = "Apagar";
    $msg[1] = "Delete";
    print FILE " <a href=\"#\" id=\"btdel\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
    $msg[0] = "Recarregar";
    $msg[1] = "Reload";
    print FILE " &nbsp; <a href=\"#\" id=\"btrel\" class=\"uibt\">$msg[$FW_LANG]</a>";

print FILE << "HTML";
    <form name="fHostGrid">
    <input type="BUTTON" id="gdUp" name="gdmoveup" value="Up" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="gdDown" name="gdmovedown" value="Down" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="savegd" name="savegd" value="Save" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="delgd" name="delgd" value="Delete" style="visibility:hidden; position:absolute;" />
    </form></DIV></body>
    </HTML>
HTML
    close(FILE);

    return get_file("text/html", $htmlfile);
}

return 1;
