#!/usr/bin/perl

#Rev.1 - Version 5.0

# "POST /admin/chinterface.cgi" -> save button
sub chinterfaces {
    my $s = shift;
    my $txtvalue = "NO";

    my $res = HTTP::Response->new();
    read_fwcfg;
    read_interfaces;

    my $rlfw = 0;
    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canSync = 0;

    if ($rlfw == 0) {

        # Parsing json response (sorting by ID)
        my %json = ();
        my @unsortId = ();
        my %unsortData = ();

        my @dvalue = ();
        foreach my $auxjson (split /"[0-9]+":/, $s) {
           $auxjson =~ s/{//g;
           $auxjson =~ s/}//g;
           $auxjson =~ s/,$//;

           if ($auxjson && $auxjson ne "") {
              %json = ();
              my $acount = 0;
              foreach my $auxjson2 (split/,/, $auxjson) {
                 $auxjson2 =~ s/\"//g;
                 $auxjson2 =~ s/\'//g;
                 my @dvalue = ();
                 @dvalue = split /:/, $auxjson2;

                 my $alen="A14";
                 if ($dvalue[0] !~ /^(Desc|Control)$/) {
                    if ($acount == 2 || $acount == 9) {
                       $alen="A18";
                    }
                    elsif ($acount == 3 || ($acount >= 6 && $acount <= 11)) {
                       $alen="A6";
                       if ($dvalue[0] eq "opt10") {
                          my $auxopt10 = $dvalue[1];
                          $dvalue[1] = 1;
                          $dvalue[1] = 0 if ($auxopt10 eq "No");
                       }
                       elsif ($dvalue[0] eq "opt11") {
                          my $auxopt11 = $dvalue[1];
                          $dvalue[1] = 1;
                          $dvalue[1] = 0 if ($auxopt11 eq "No");
                       }
                    }
                    elsif ($acount == 4) {
                       $alen="A24";
                    }
                    $json{$dvalue[0]} = pack("$alen", str_conv($dvalue[1]));
                    $acount++;
                 }
                 else {
                    $json{$dvalue[0]} = str_conv($dvalue[1]);
                 }
              }
              if ($json{'opt1'} ne "" && $json{'opt2'} ne "" && $json{'Control'} ne "set") {
                 $canSync = 1;
                 my $auxentry = "$json{'opt1'} $json{'opt2'} $json{'opt3'} $json{'opt4'} $json{'opt5'} $json{'opt6'} $json{'opt7'} $json{'opt8'} $json{'opt9'} $json{'opt10'} $json{'opt11'}   $json{'Desc'}";
                 push(@unsortId, $json{'id'});
                 push(@{$unsortData{$json{'id'}}}, $auxentry);
              }
              $canSync = 1 if ($json{'Control'} eq "set");
           }
        }

        if ($canSync == 1) {
           open FILE, ">$file_cfg{'interfaces'}";

           # Writing interfaces comments
           foreach my $fRules (@fwinterfacescomments) {
               $fRules =~ s/\n//;
               $fRules =~ s/\\"/\"/g;
               $fRules =~ s/\\'/\'/g;
               print FILE "$fRules\n" if ($fRules);
           }

           # Writing interfaces rules
           print FILE "\n";
           my @sortedId = sort { $a <=> $b } @unsortId;
           foreach (@sortedId) {
              foreach my $line (@{$unsortData{"$_"}}) {
                 print FILE "$line\n";
              }
           }
           close(FILE);
           $txtvalue="OK";
        }
    }
    else {
       my $rtime = 2;
       $msg[0] = "Recarregando as regras de firewall!";
       $msg[1] = "Reloading firewall rules!";
       $msg2[0] = "<font size=\'2\'>Recarregando todas as regras...</font>";
       $msg2[1] = "<font size=\'2\'>Full reloading...</font>";
       $txtvalue = msgbox("info", "$msg[$FW_LANG]", "<font size=\'2\'>$msg2[$FW_LANG]</font>");

       system("$FW_DIR/fwguardian --ignore-cluster 1>&2 2>/dev/null &") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       system("$FW_DIR/fwguardian --ignore-webserver 1>&2 2>/dev/null &");
       system("$FW_DIR/fwguardian 1>&2 2>/dev/null &");

       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/interfaces.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page interfaces.html" 
sub get_interfaces {
    my $htmlfile="$HTMLDIR/admin/dynhttp/interfaces.html";
    read_fwcfg;
    read_interfaces;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    ### Making interfaces.html
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
                 document.fintGrid.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 document.fintGrid.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.finterface.ReloadFw.click();
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

        var scrollPosition = 0;
        jQuery("#intGrid").jqGrid({
           url:'/admin/getinterface.json',
           datatype: "json",
           height: \$(window).height() - 350,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'Interface', 'Endereço MAC', 'MTU', 'VLANS', 'Ponte', 'rp_filter', 'arp_filter', 'Tamanho fila', 'CPUs', 'IPS', 'P2P', 'Descrição', 'Control' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'Interface', 'MAC address', 'MTU', 'VLANS', 'Bridge', 'rp_filter', 'arp_filter', 'Queue length', 'CPUs', 'IPS', 'P2P', 'Description', 'Control' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",       index:'id', sorttype: "int", key: true, width:30 },
javascript
$msg[0] = "lo";
    my $cint = 0;
    foreach (`ls /sys/class/net/ | tr ' ' '\n' | grep -v \"\^lo\$\"`) {
       $_ =~ s/\n//;
       if ($_ !~ /^ifb/) {
          my $line = "$_:$_";
          if ($cint gt 0) {
             $msg[0] = "$msg[0];$line";
          }
          else { $msg[0] = "lo:lo;$line"; }
          $cint++;
       }
    }
print FILE "              { name:\"opt1\",   index:'opt1', sortable:false, editable:true, edittype:\"select\", editoptions:{value:\"$msg[0]\"}, width:110 },\n";
print FILE << "javascript";
              { name:"opt2",  index:'opt2',  sortable:false, editable:true, defaultValue:"auto", width:140 },
              { name:"opt3",  index:'opt3',  sortable:false, editable:true, defaultValue:"auto", width:70 },
              { name:"opt4",  index:'opt4',  sortable:false, editable:true, defaultValue:"auto", width:140 },
              { name:"opt5",  index:'opt5',  sortable:false, editable:true, defaultValue:"auto", width:110 },
              { name:"opt6",  index:'opt6',  sortable:false, editable:true, edittype:"select", editoptions:{value:"auto:auto;0:0;1:1;2:2"}, defaultValue:"auto", width:70 },
              { name:"opt7",  index:'opt7',  sortable:false, editable:true, edittype:"select", editoptions:{value:"auto:auto;0:0;1:1"}, defaultValue:"auto", width:70 },
              { name:"opt8",  index:'opt8',  sortable:false, editable:true, edittype:"select", editoptions:{value:"auto:auto;100:100;500:500;1000:1000;2000:2000;5000:5000;8000:8000;10000:10000"}, defaultValue:"auto", width:90 },
              { name:"opt9",  index:'opt9',  sortable:false, editable:true, defaultValue:"auto", width:140 },
              { name:"opt10", index:'opt10', sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No", defaultValue:"No"}, width:60 },
              { name:"opt11", index:'opt11', sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No", defaultValue:"No"}, width:60 },
              { name:"Desc" ,   index:'Desc',    sortable:false, editable:true, width:320 },
              { name:"Control", index:'Control', sortable:false, editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 }
           ],
           pager: '#pintGrid',
           editurl: 'clientArray',
           rowNum: '',
           rowList: [],
           pgbuttons: false,
           pgtext: null,
           gridview: true,
           viewrecords: false,
           sortable: true,
           shrinkToFit: false,
           ondblClickRow: function (selid, iRow,iCol) {
              editRow(jQuery("#intGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "interface");
              newRow = updnewRow();
           },
           gridComplete: function(data, response) {
              rulesGrid=GridComplete(jQuery("#intGrid"), rulesGrid, rulesCt, saveall, "interface");

              rulesCt++;
              saveall = 0;
              jQuery("#intGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Definições de interface de rede";
$msg[1] = "Network interface definitions";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#intGrid").css('font-size', '13px');
        jQuery("#intGrid").jqGrid('navGrid',"#pintGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#intGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "interface");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#intGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "interface");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Edit button
        \$("#intGrid").jqGrid('navButtonAdd','#pintGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#intGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "interface");
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
           rulesGrid = delRow(jQuery("#intGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
        });

        // Add button
        \$("#intGrid").jqGrid('navButtonAdd','#pintGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = addRow(jQuery("#intGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "interface", "", "");
             newRow = updnewRow();
           }
        });

        // Saving all rows in click event
        jQuery("#savegd").click( function() {
javascript
$msg[0] = "INFO: Regras atualizadas com sucesso!";
$msg[1] = "INFO: Rules updated successfully!";
print FILE << "javascript";
           saveall = 1;
           saveAll(jQuery("#intGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "interface", "/admin/getinterface.json", "/admin/chinterface.cgi");
           newRow = updnewRow();
           if (newRow.length < 1) rulesCt = 0;
        });

        // Grid resize
        \$(window).bind('resize', function() {
            \$("#jqgrid").setGridWidth(\$(window).width() - 120);
        }).trigger('resize');

    });
  </script>\n\n
javascript

    $msg[0] = "Interfaces de rede";
    $msg[1] = "Network interfaces";
    my $mstyle = menustyle("$msg[$FW_LANG]");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE>
  <span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG]</span>

  <DIV align="center">
HTMLCODE

    print FILE "<DIV align=\"left\"><i>";
    print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 20px;\">";
    if ($FW_LANG eq "0") {
       print FILE " <strong>Valores padrão</strong>: Selecione *auto* para manter a configuração padrão do sistema!<BR /><BR />";
       print FILE " 1. <strong>Ponte</strong>: Defina *use_vlanid* em *ponte* caso deseje criar uma ponte por VLAN.<BR />";
       print FILE " 2. <strong>Proteção spoof</strong>: Defina o valor *1* em *rp_filter* para ativar a proteção (ou *2* para autorizar roteamento assimétrico).<BR />";
    }
    else {
       print FILE " <strong>Default values</strong>: Select *auto* to keep the default system setting!<BR /><BR />";
       print FILE " 1. <strong>Bridge</strong>: Define *use_vlanid* in *bridge* if you want to create a bridge per VLAN.<BR />";
       print FILE " 2. <strong>Spoof protection</strong>: Define *1* in *rp_filter* to enable this protection (or *2* to allow asymmetric routing.<BR />";
    }
    print FILE "</span></i></DIV><BR /><BR />";

    ## Waiting form
    print FILE "<DIV align=\"center\" valign=\"center\" id=\"chwait\">";
    $msg[0] = "Aguarde... isto pode demorar um pouco!";
    $msg[1] = "Wait... this may take a little time!";
    print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
    print FILE "</DIV><BR />";

    print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\"><tbody><TR valign=\"bottom\" align=\"center\">";
    print FILE "<TD width=\"96%\">";
print FILE << "HTMLCODE";
    <table id="intGrid" width="100%" style="font-size:12px;"></table>
    <div id="pintGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
    print FILE "<BR />";
    print FILE "</TD><TD width=\"4%\" align=\"left\">";
    print FILE "&nbsp;<a href=\"javascript: document.fintGrid.gdmoveup.click();\">";
    print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "&nbsp;<a href=\"javascript: document.fintGrid.gdmovedown.click();\">";
    print FILE "<img src=\"buttons/mv_down.png\" style=\"border: 0px solid ;\"></a><BR /><BR />";
    print FILE "</TD></TR></tbody></table>";
    print FILE "<FORM name='finterface' action='/admin/chinterface.cgi' method='POST'>";
    print FILE "<INPUT type=\"submit\" name=\"ReloadFw\" value=\"Reload firewall rules\" style=\"visibility:hidden; position:absolute;\">";
    print FILE "</FORM>";
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
    <form name="fintGrid">
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
