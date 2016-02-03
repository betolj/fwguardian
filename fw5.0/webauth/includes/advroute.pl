#!/usr/bin/perl

#Rev.2 - Version 5.0

# "POST /admin/chadvlkroute.cgi" -> save or reload button
sub chadvlkroute {
    my $s = shift;

    my $rlfw = 0;
    my $canSync = 0;
    my $txtvalue = "";
    my @msg = ("", ""), @msg2 = ("", "");
    my $res = HTTP::Response->new();
    read_advroute;

    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && $canch == 1) {

       # Parsing json response (sorting by ID)
       my %json = ();
       my @advset = ();
       my @sortedId = ();
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
                   if ($dvalue[0] =~ /ar(If|Gw|Name|DGD)$/ || $dvalue[0] eq "Dst") {
                      $json{$dvalue[0]} = pack( 'A20', str_conv($dvalue[1])) if ($dvalue[1] !~ /^[\s]*$/);
                   }
                   elsif ($dvalue[0] eq "arPrio" && $dvalue[1] gt 0) {
                      $json{'arPrio'} = "";
                      $json{'arPrio'} = "prio=$dvalue[1]" if ($dvalue[1]);
                   }
                   elsif ($dvalue[0] eq "arRpdb" || $dvalue[0] eq "arFail") {
                      $json{$dvalue[0]} = "";
                      $json{$dvalue[0]} = $dvalue[1] if ($dvalue[1] ne "default" && $dvalue[0] eq "arRpdb");
                      $json{$dvalue[0]} = "onfail-$dvalue[1]" if ($dvalue[1] ne "none" && $dvalue[0] eq "arFail");
                   }
                   elsif ($dvalue[0] eq "arLbgp" || $dvalue[0] eq "arFogp") {
                      my $lbgp = str_conv($dvalue[1]);
                      $json{$dvalue[0]} = "";
                      $json{$dvalue[0]} = "lbgroup=$lbgp" if ($dvalue[1] ne "none" && $dvalue[0] eq "arLbgp");
                      $json{$dvalue[0]} = "fogroup=$lbgp" if ($dvalue[1] ne "none" && $dvalue[0] eq "arFogp");
                   }
                   elsif ($dvalue[0] eq "Cond") {
                      $json{'Cond'} = "";
                      $json{'Cond'} = "$dvalue[1]" if ($dvalue[1] ne "none");
                   }
                   elsif ($dvalue[0] =~ /^(Control|arDefaults|id)/) {
                      $json{$dvalue[0]} = $dvalue[1];
                   }
                   elsif ($dvalue[0] eq "Desc") {
                      $json{$dvalue[0]} = str_conv($dvalue[1]);
                   }
                }
             }

             if (($json{'arIf'} ne "" && $json{'Dst'} ne "" && $json{'arGw'} ne "" && $json{'arName'} ne "") && $json{'Control'} ne "set") {
                $canSync = 1;

                # Routing path rules
                my $auxentry = "$json{'arIf'} $json{'Dst'} $json{'arGw'} $json{'arName'} $json{'arDGD'}";
                $auxentry = "$auxentry $json{'arPrio'}" if ($json{'arPrio'});
                $auxentry = "$auxentry $json{'arRpdb'}" if ($json{'arRpdb'});
                $auxentry = "$auxentry $json{'arFail'}" if ($json{'arFail'});
                $auxentry = "$auxentry $json{'arLbgp'}" if ($json{'arLbgp'});
                $auxentry = "$auxentry $json{'arFogp'}" if ($json{'arFogp'});
                $auxentry = "$auxentry chk=$json{'Cond'}" if ($json{'Cond'});
                $auxentry = "$auxentry desc=\"$json{'Desc'}\"" if (length($json{'Desc'}) > 1);
                push(@sortedId, $auxentry);
             }
             if ($json{'Control'} eq "set" || $json{'arDefaults'} ne "") {
                my ($set1, $set2, $set3) = split /\s/, $json{'arDefaults'}, 3;
                $set3 = "on" if ($set3 eq "on" || $set3 eq "true");
                $set3 = "off" if ($set3 ne "on");
                push(@advset, "set route.source $set1");
                push(@advset, "set lb.keepalive.timeout $set2");
                push(@advset, "set lb.equalize $set3");
                $canSync = 1;
             }
          }
       }
       if ($canSync == 1) {
          open FILE, ">$file_cfg{'routing/fwroute.tables'}";

          # Writing fwroute.table comments
          foreach my $advRules (@advroutecomments) {
              $advRules =~ s/\n//;
              $advRules =~ s/\\"/\"/g;
              $advRules =~ s/\\'/\'/g;
              print FILE "$advRules\n" if ($advRules);
          }

          # Writing fwroute.table set definitions
          print FILE "\n";
          foreach my $advRules (@advset) {
              $advRules =~ s/\n//;
              $advRules =~ s/\\"/\"/g;
              $advRules =~ s/\\'/\'/g;
              print FILE "$advRules\n" if ($advRules);
          }

          # Writing fwroute.table link rules
          print FILE "\n";
          print FILE "set-link\n";
          foreach my $line (@sortedId) {
              print FILE "$line\n";
          }

          # Writing fwroute.table policy rules
          my $curpol = "";
          foreach my $advRules (@advrouterules) {
              ($auxpol, $auxrule) = split/\s/, $advRules, 2;
              $auxpol =~ s/\?chk=/ chk=/;
              print FILE "\nset-policy $auxpol\n" if ($curpol ne $auxpol);

              $advRules =~ s/\n//;
              $advRules =~ s/\\"/\"/g;
              $advRules =~ s/\\'/\'/g;
              print FILE "$auxrule\n" if ($advRules);
              $curpol = $auxpol;
          }
          close(FILE);
          $txtvalue="OK";

          rsyncupdate("$file_cfg{'routing/fwroute.tables'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
    }
    else {
       my $rtime = 2;
       if ($canch == 1) {
          $msg[0] = "Recarregando as regras de firewall!";
          $msg[1] = "Reloading firewall rules!";
          $msg2[0] = "<font size=\'2\'>Recarregando as definições de roteamento...</font>";
          $msg2[1] = "<font size=\'2\'>Reloading routing settings...</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
          system("$FW_DIR/fwguardian --reload-advrouting 1>&2 2>/dev/null &");

          rsyncupdate("$file_cfg{'routing/fwroute.tables'}", "advrouting", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       }
       else {
          $rtime = 0;
       }

       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/advlkroute.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page advroute.html"
sub get_advlkroute {
    my $htmlfile="$HTMLDIR/admin/dynhttp/advroute.html";
    read_advroute;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $defgw = `ip route ls scope link | grep 'proto kernel' | head -1 | sed 's/.* src \\([0-9.]\\+\\) .*/\\1/'`;
    $defgw =~ s/\n//;
    $defgw =~ s/\.[0-9]+$/\.254/;

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making advroute.html
    splitalias;
    open FILE, ">$htmlfile";

print FILE << "javascript";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />

  <link href="/css/ui.jqgrid.css" type="text/css" rel="stylesheet" />
  <link href="/css/jquery-ui.css" type="text/css" rel="stylesheet" />
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
    .select2-search { font-size:small; }
    .select2-search input { background-color: #A4A4A4; font-size:small; }
    .select2-results { font-size:small; }

  </style>

  <script type="text/javascript" src="/js/jquery-1.7.2.min.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.core.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.widget.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.button.js"></script>
  <script type="text/javascript" src="/js/select2.min.js"></script>
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
                 fadvRouteGrid.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 fadvRouteGrid.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.flsadvRoute.ReloadFw.click();
                 return false;
           });

           \$("#arsrcRpdb").select2();
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
        jQuery("#advRouteGrid").jqGrid({
           url:'/admin/getadvlkroute.json',
           datatype: "json",
           height: \$(window).height() - 290,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'Nome do Link', 'Interface', 'Rede', 'Roteador', 'DGD - End. de teste', 'Prio', 'Limitadores', 'Ao falhar', 'Grupo LB', 'Grupo FO', 'Condição', 'Descrição', 'defaults', 'Control' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'Link Name', 'Interface', 'Network', 'Gateway', 'DGD - Test addr.', 'Prio', 'Limiters', 'Failure action', 'LB Group', 'FO Group', 'Condition', 'Description', 'defaults', 'Control' ],\n";
}
$msg[0] = selGridifnet("ipnet");
my $aralias = $msg[0];
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id', sortable:true, sorttype: "int", key: true, width:30 },
              { name:"arName",  index:'arName', sortable:false, editable:true, width:120 },
javascript
$msg[0] = selGridifnet("if");
print FILE "              { name:\"arIf\",    index:'arIf',  sortable:false, editable:true, edittype:\"select\", editoptions:{value:\"$msg[0]\"}, width:78 },\n";
print FILE << "javascript";
              { name:"Dst",     index:'Dst',    sortable:false, editable:true, width:140 },
              { name:"arGw",    index:'arGw',   sortable:false, editable:true, width:100 },
              { name:"arDGD",   index:'arDGD',  sortable:false, editable:true, width:220 },
              { name:"arPrio",  index:'arPrio', sortable:false, editable:true, hidden:true, width:30 },
              { name:"arRpdb",  index:'arRpdb', sortable:false, editable:true, hidden:true, edittype:"select", editoptions:{value:"default:default;only-table:only-table;only-iproute:only-iproute"}, width:120 },
              { name:"arFail",  index:'arFail', sortable:false, editable:true, hidden:true, edittype:"select", editoptions:{value:"none:none;throw:throw;prohibit:prohibit;blackhole:blackhole"}, width:90 },
              { name:"arLbgp",  index:'arLbgp', sortable:false, editable:true, width:120 },
              { name:"arFogp",  index:'arFogp', sortable:false, editable:true, hidden:true, width:120 },
javascript
    $msg[0] = "none:none;disabled:disabled";
    foreach (@fwchk) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       $msg[0] = "$msg[0];$line";
    }
print FILE "{ name:\"Cond\",  index:'Cond',  sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:120 },\n";
print FILE << "javascript";
              { name:"Desc",  index:'Desc', sortable:false, editable:true, dataType:'string', width:320 },
              { name:"arDefaults",  index:'arDefaults', sortable:false, editable:true, hidden:true, dataType:'string', width:380 },
              { name:"Control",     index:'Control', sortable:false, editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 }
           ],
           pager: '#padvRouteGrid',
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
              editRow(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$aralias", "advroute");
              newRow = updnewRow();
           },
           gridComplete: function(data, response) {
              rulesGrid=GridComplete(jQuery("#advRouteGrid"), rulesGrid, rulesCt, saveall, "advroute");

              rulesCt++;
              saveall = 0;
              jQuery("#advRouteGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Definições de link";
$msg[1] = "Link definitions";
print FILE "           caption: '$msg[$FW_LANG]'\n";
$msg[0] = "Configuração de rede (gateway)";
$msg[1] = "Network config (gateway)";
print FILE << "javascript";
        });
        jQuery("#advRouteGrid").jqGrid('setGroupHeaders', {
             useColSpanStyle: true, 
             groupHeaders:[
                {startColumnName: 'arName', numberOfColumns: 4, titleText: '<font size="2">$msg[$FW_LANG]</font>'},
                {startColumnName: 'arPrio', numberOfColumns: 3, titleText: '<font size="2">RPDB</font>'}
             ]
        });
        jQuery("#advRouteGrid").css('font-size', '13px');
        jQuery("#advRouteGrid").jqGrid('navGrid',"#padvRouteGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "advroute");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "advroute");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Advanced
        \$("#advRouteGrid").jqGrid('navButtonAdd','#padvRouteGrid',{
javascript
$msg[0] = "*Avançado ";
$msg[1] = "*Advanced ";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
               \$("#advRouteGrid").showCol("arPrio");
               \$("#advRouteGrid").showCol("arRpdb");
               \$("#advRouteGrid").showCol("arFail");
               \$("#advRouteGrid").showCol("arFogp");
           }
        });

        // Edit button
        \$("#advRouteGrid").jqGrid('navButtonAdd','#padvRouteGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$aralias", "advroute");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#advRouteGrid").jqGrid('navButtonAdd','#padvRouteGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = cloneRow(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "advroute", "$defgw");
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
           rulesGrid = delRow(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
        });

        // Add button
        \$("#advRouteGrid").jqGrid('navButtonAdd','#padvRouteGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = addRow(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "advroute", "$defgw", "$aralias");
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
           saveAll(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "advroute", "/admin/getadvlkroute.json", "/admin/chadvlkroute.cgi");
           newRow = updnewRow();
           if (newRow.length < 1) rulesCt = 0;
        });

        \$("#advRouteGrid").jqGrid('navButtonAdd','#padvRouteGrid',{
           caption:"&nbsp; Info",
           onClickButton:function(){
             var selid = jQuery("#advRouteGrid").jqGrid('getGridParam','selrow');
             var clret = jQuery("#advRouteGrid").jqGrid('getRowData', selid);
             if (clret['Desc'] !== "") alert(clret['Desc']);
           }
        });

        // Grid resize
        \$(window).bind('resize', function() {
            \$("#jqgrid").setGridWidth(\$(window).width() - 120);
        }).trigger('resize');
     });
  </script>\n\n
javascript

    my $srcfs = "";
    if ($canch == 0) {
       $msg[0] = "Somente leitura (nó escravo)!";
       $msg[1] = "Read-only (slave node)!";
       $srcfs = "<h5><FONT color=\"Red\"><strong>$msg[$FW_LANG]</strong></FONT></h5>";
    }

    $msg[0] = "Roteamento avançado: Caminhos alternativos";
    $msg[1] = "Advanced routing: Alternative paths";
    my $mstyle = menustyle("$msg[$FW_LANG]");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor="#F2F2F2" $STYLE>
  <span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG] ($srcfile)</span>

  <DIV align="center">
HTMLCODE

    ## Default options
    my $selnone = "", $selnet = "", $selip = ""; 
    foreach my $lines (@advrouteset) {
       if ($lines =~ /set[\s]+route\.source[\s]/) {
          $rtsource = $lines;
          $rtsource =~ s/set[\s]+route\.source[\s]+//;
          $selnone = "selected" if ($rtsource =~ /none[\s]*/);
          $selnet = "selected" if ($rtsource =~ /net[\s]*/);
          $selip = "selected" if ($rtsource =~ /ip[\s]*/);
       }
       else {
          if ($lines =~ /set[\s]+lb\.keepalive\.timeout[\s]/) {
             $rtkeepalive = $lines;
             $rtkeepalive =~ s/set[\s]+lb\.keepalive\.timeout[\s]+//;
          }
          else {
             $rtequalize = "";
             $rtequalize = "checked" if ($lines =~/set[\s]+lb.equalize[\s]+(1|on|yes)[\s]*$/);
          }
       }
    }
    $rtkeepalive = "600" if (not $rtkeepalive);

    ## Waiting form
    print FILE "<DIV align=\"center\" valign=\"center\" id=\"chwait\">";
    $msg[0] = "Aguarde... isto pode demorar um pouco!";
    $msg[1] = "Wait... this may take a little time!";
    print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
    print FILE "</DIV>";

    ### Grid rules
    print FILE "<FORM name='flsadvRoute' action='/admin/chadvlkroute.cgi' method='POST'>";
    print FILE "<table border='0' cellspacing='0' cellpadding='0'>";
    print FILE "<tbody><TR valign=\"bottom\" align=\"left\"><TD width=\"96%\">";
    $msg[0] = "Apelidos";
    $msg[1] = "Alias";
    print FILE "<FONT size=\"-1\"><p><i>";
    print FILE "  Equalize <INPUT type='checkbox' name='rtequalize' id='enEqual' $rtequalize>";
    print FILE " &nbsp; &nbsp; $msg[$FW_LANG] <INPUT type=\"checkbox\" id=\"enAlias\" name=\"CkenAlias\">";
    print FILE " &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; ";
    $msg[0] = "Persistência (caminho aprendido)";
    $msg[1] = "Timeout (learned path)";
    print FILE " &nbsp; &nbsp; $msg[$FW_LANG] ";
    print FILE " <input name='rtekeepalive' id='arkalive' style='background-color: #bec2c8;' type='textbox' size='4' value='$rtkeepalive'>s";
    $msg[0] = "Mapeamento de origem padrão (RPDB)";
    $msg[1] = "Default source lookup (RPDB)";
    print FILE " &nbsp; / &nbsp; <span style=\"Font-Family: Arial, Helvetica;\">$msg[$FW_LANG]: </span>";
    print FILE "<select size='1' name='lsSrcRpdb' id='arsrcRpdb' style='width:80px; font-size:small;'>";
    print FILE "<OPTION value='none' $selnone>none</OPTION><OPTION value='net' $selnet>net</OPTION><OPTION value='ip' $selip>ip</OPTION></select>";
    print FILE "</FONT></i></p>\n";
print FILE << "HTMLCODE";
    <table id="advRouteGrid" width="100%" style="font-size:12px;"></table>
    <div id="padvRouteGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
    print FILE "</TD><TD width=\"4%\">";
    print FILE "&nbsp;<a href=\"javascript: document.fadvRouteGrid.gdmoveup.click();\">";
    print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "&nbsp;<a href=\"javascript: document.fadvRouteGrid.gdmovedown.click();\">";
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
    <form name="fadvRouteGrid">
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


# "POST /admin/chadvrlroute.cgi" -> save or reload button
sub chadvrlroute {
    my $s = shift;

    my $rlfw = 0;
    my $canSync = 0;
    my $txtvalue = "";
    my @msg = ("", ""), @msg2 = ("", "");
    my $res = HTTP::Response->new();
    read_advroute;

    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && $canch == 1) {

       # Parsing json response (sorting by ID)
       my %json = ();
       my @sortedId = ();
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
                   if ($dvalue[0] =~ /^ar(If|IfOut|Name)$/ || $dvalue[0] =~ /^(Src|Dst)$/) {
                      if ($dvalue[0] eq "arIfOut" && $dvalue[1] ne "any") {
                         $json{'arIf'} =~ s/[\s]+$//;
                         $json{'arIf'} = "$json{'arIf'}\->$dvalue[1]";
                         $json{'arIf'} = pack( 'A20', str_conv($json{'arIf'}) );
                      }
                      else {
                         $json{$dvalue[0]} = pack( 'A20', str_conv($dvalue[1]) ) if ($dvalue[1] !~ /^[\s]*$/);
                      }
                   }
                   elsif ($dvalue[0] =~ /^(Group|arNat)$/ || $dvalue[0] =~ /^(proto|sport|dport)$/) {
                      $json{$dvalue[0]} = str_conv($dvalue[1]) if ($dvalue[1] ne "" && $dvalue[1] ne "none");
                   }
                   elsif ($dvalue[0] eq "Cond") {
                      $json{'Cond'} = "";
                      $json{'Cond'} = "$dvalue[1]" if ($dvalue[1] ne "none");
                   }
                   elsif ($dvalue[0] =~ /^(Control|arDefaults|id)/) {
                      $json{$dvalue[0]} = $dvalue[1];
                   }
                   elsif ($dvalue[0] eq "Desc") {
                      $json{$dvalue[0]} = str_conv($dvalue[1]);
                   }
                }
             }

             if (($json{'arIf'} ne "" && $json{'Src'} ne "" && $json{'Dst'} ne "" && $json{'arName'} ne "") && $json{'Control'} ne "set") {
                $canSync = 1;

                # Routing policy rules
                my $auxentry = "$json{'Group'} $json{'arIf'} $json{'Src'} $json{'Dst'} $json{'arName'}";
                if ($json{'Group'} !~ /^iproute/ && ($json{'proto'} eq "tcp" || $json{'proto'} eq "udp")) {
                   my $protoentry = "$json{'proto'}";
                   if ($json{'sport'} || $json{'dport'}) {
                      $auxentry = "$auxentry sport=$protoentry/$json{'sport'}" if ($json{'sport'});
                      $auxentry = "$auxentry dport=$protoentry/$json{'dport'}" if ($json{'dport'});
                   }
                   else {
                      $auxentry = "$auxentry dport=$protoentry";
                   }
                }
                $auxentry = "$auxentry chk=$json{'Cond'}" if ($json{'Cond'});
                if ($json{'arNat'}) {
                   $json{'arNat'} = "autosnat" if ($json{'arNat'} eq "AUTO");
                   $json{'arNat'} = "masq" if ($json{'arNat'} eq "MASQ");
                   $auxentry = "$auxentry $json{'arNat'}";
                }
                $auxentry = "$auxentry desc=\"$json{'Desc'}\"" if (length($json{'Desc'}) gt 1);

                push(@sortedId, $auxentry);
             }
             $canSync = 1 if ($json{'Control'} eq "set");
          }
       }
       if ($canSync == 1) {
          open FILE, ">$file_cfg{'routing/fwroute.tables'}";

          # Writing fwroute.table comments
          foreach my $advRules (@advroutecomments) {
              $advRules =~ s/\n//;
              $advRules =~ s/\\"/\"/g;
              $advRules =~ s/\\'/\'/g;
              print FILE "$advRules\n" if ($advRules);
          }

          # Writing fwroute.table set definitions
          print FILE "\n";
          foreach my $advRules (@advrouteset) {
              $advRules =~ s/\n//;
              $advRules =~ s/\\"/\"/g;
              $advRules =~ s/\\'/\'/g;
              print FILE "$advRules\n" if ($advRules);
          }

          # Writing fwroute.table link rules
          print FILE "\n";
          print FILE "set-link\n";
          foreach my $advRules (@advroutelink) {
              $advRules =~ s/\n//;
              $advRules =~ s/\\"/\"/g;
              $advRules =~ s/\\'/\'/g;
              print FILE "$advRules\n" if ($advRules);
          }

          # Writing fwroute.table policy rules
          my $curpol = "";
          my $group = "";
          foreach my $advRules (@sortedId) {
              ($auxpol, $auxrule) = split/\s/, $advRules, 2;

              $group = $auxpol;
              $group =~ s/\?chk=/ chk=/;
              print FILE "\nset-policy $group\n" if ($curpol ne $auxpol);

              $advRules =~ s/\n//;
              $advRules =~ s/\\"/\"/g;
              $advRules =~ s/\\'/\'/g;
              print FILE "$auxrule\n" if ($advRules);
              $curpol = $auxpol;
          }
          close(FILE);
          $txtvalue="OK";

          rsyncupdate("$file_cfg{'routing/fwroute.tables'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
    }
    else {
       my $rtime = 2;
       if ($canch == 1) {
          $msg[0] = "Recarregando as regras de firewall!";
          $msg[1] = "Reloading firewall rules!";
          $msg2[0] = "<font size=\'2\'>Recarregando as definições de roteamento...</font>";
          $msg2[1] = "<font size=\'2\'>Reloading routing settings...</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
          system("$FW_DIR/fwguardian --reload-advrouting 1>&2 2>/dev/null &");

          rsyncupdate("$file_cfg{'routing/fwroute.tables'}", "advrouting", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       }
       else {
          $rtime = 0;
       }

       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/advrlroute.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page advrlroute.html"
sub get_advrlroute {
    my $htmlfile="$HTMLDIR/admin/dynhttp/advrlroute.html";
    read_advroute;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making advroute.html
    splitalias;
    open FILE, ">$htmlfile";

print FILE << "javascript";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />

  <link href="/css/ui.jqgrid.css" type="text/css" rel="stylesheet" />
  <link href="/css/jquery-ui.css" type="text/css" rel="stylesheet" />
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
    .select2-search { font-size:small; }
    .select2-search input { background-color: #A4A4A4; font-size:small; }
    .select2-results { font-size:small; }

  </style>

  <script type="text/javascript" src="/js/jquery-1.7.2.min.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.core.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.widget.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.button.js"></script>
  <script type="text/javascript" src="/js/select2.min.js"></script>
  <script type="text/javascript" src="/js/i18n/grid.locale-en.js"></script>
  <script type="text/javascript" src="/js/jquery.jqGrid.min.js"></script>
  <script type="text/javascript" src="/admin/js/gridctl.js"></script>
  <script type="text/javascript">
        jQuery.jgrid.no_legacy_api = true;
        jQuery.jgrid.useJSON = true;

        \$(function() {
           \$(".uibt" ).button();
           \$(".uibt_em" ).button();
           \$("#btsav").click(function() {
                 fadvRouteGrid.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 fadvRouteGrid.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.flsadvRoute.ReloadFw.click();
                 return false;
           });
           \$("#arDefGroup").select2();
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
        jQuery("#advRouteGrid").jqGrid({
           url:'/admin/getadvrlroute.json',
           datatype: "json",
           height: \$(window).height() - 270,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'Politica', 'Int (Ori)', 'Origem', 'Int (Dest)', 'Destino', 'Nome do Link', 'Proto', 'Porta de origem', 'Porta de destino', 'Condição', 'SNAT', 'Descrição', 'defaults', 'Control' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'Policy', 'Int (Src)', 'Source', 'Int (Dst)', 'Destination', 'Link Name', 'Proto', 'Source port', 'Destination port', 'Condition', 'SNAT', 'Description', 'defaults', 'Control' ],\n";
}
$msg[0] = selGridifnet("net");
my $aralias = $msg[0];
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id',    sortable:true, width: 4, sorttype: "int", key: true, width:25 },
              { name:"Group",   index:'Group', hidden:true,  width:30,
                  formatter: function (cellval, opts, rowObject, action) {
                      var groupIdPrefix = opts.gid + "ghead_",
                          groupIdPrefixLength = groupIdPrefix.length;

                      var fwtrigger = /\\?chk=/;
                      if (opts.rowId.substr(0, groupIdPrefixLength) === groupIdPrefix && typeof action === "undefined") {
                         return (fwtrigger.test(cellval) ? ('<span class="ui-icon ui-icon-alert" style="float: left;"></span>' + '<span style="color:#800000; margin-left: 5px;">') : "<span>") + cellval + '</span>';
                      }
                      return cellval;
                  }
               },
javascript
$msg[0] = selGridifnet("if");
print FILE "              { name:\"arIf\",    index:'arIf',  sortable:false, editable:true, edittype:\"select\", editoptions:{value:\"$msg[0]\"}, width:78 },\n";
print FILE << "javascript";
              { name:"Src",     index:'Src',     sortable:false, editable:true, width:140 },
              { name:"arIfOut", index:'arIfOut', sortable:false, editable:true, edittype:\"select\", editoptions:{value:\"$msg[0]\"}, width:78 },
              { name:"Dst",     index:'Dst',     sortable:false, editable:true, width:140 },
javascript
    my $clink = 0;
    foreach (@rtlink) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       if ($clink gt 0) {
          $msg[0] = "$msg[0];$line";
       }
       else { $msg[0] = "$line"; }
       $clink++;
    }
print FILE << "javascript";
              { name:"arName", index:'arName', sortable:false, editable:true, edittype:"select", editoptions:{value:\"main:main;$msg[0]\"}, width:120 },
              { name:"proto",  index:'proto',  sortable:false, editable:true, edittype:"select", editoptions:{value:"any:any;tcp:tcp;udp:udp;icmp:icmp;gre:gre;ah:ah;esp:esp;ospf:ospf;vrrp:vrrp"}, width:70 },
              { name:"sport",  index:'sport', sortable:false, editable:true, hidden:true, width:162 },
              { name:"dport",  index:'dport', sortable:false, editable:true, width:162 },
javascript
    $msg[0] = "none:none;disabled:disabled";
    foreach (@fwchk) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       $msg[0] = "$msg[0];$line";
    }
print FILE "              { name:\"Cond\",  index:'Cond', sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:120 },\n";
print FILE << "javascript";
              { name:"arNat",  index:'arNat', sortable:false, editable:true, hidden:true, edittype:'select', editoptions:{value:"none:none;MASQ:MASQ;AUTO:AUTO"}, width:60 },
              { name:"Desc",  index:'Desc', sortable:false, editable:true, dataType:'string', width:320 },
              { name:"arDefaults",  index:'arDefaults', sortable:false, editable:true, hidden:true, dataType:'string', width:380 },
              { name:"Control", index:'Control', sortable:false, editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 }
           ],
           pager: '#padvRouteGrid',
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
              if (document.getElementById('mvPol').checked == true) {
                 var selcur = jQuery("#advRouteGrid").jqGrid('getRowData', selid);
                 var curPol = selcur['Group'];
                 var arPol = /\\?chk=/;
                 if (arPol.test(curPol)) curPol = curPol.replace(/.*\\?chk=/, "");
                 else curPol = "";

                 document.fchcond.idcond.value = curPol;
                 document.getElementById('chcondition').style.display = 'block';
              }
              else {
                 editRow(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$aralias", "advrouterl");
                 newRow = updnewRow();
              }
           },
           groupingView : {
              groupField : ['Group'],
              groupColumnShow : [false],
              groupCollapse : false,
              groupDataSorted : false,
              groupSorted : false,
              groupText : ['<b><FONT color="Black">{0}</b>  {1}</FONT>']
           },
           gridComplete: function(data, response) {
              rulesGrid=GridComplete(jQuery("#advRouteGrid"), rulesGrid, rulesCt, saveall, "advrouterl");

              rulesCt++;
              saveall = 0;
              jQuery("#advRouteGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Regras de encaminhamento";
$msg[1] = "Forwarding rules";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#advRouteGrid").css('font-size', '13px');
        jQuery("#advRouteGrid").jqGrid('navGrid',"#padvRouteGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "advrouterl");
           newRow = updnewRow();
           doReload = upddoReload();

           if (document.getElementById('mvPol').checked == true) {
              selid = updselidGrp();
              refreshGroup(jQuery("#advRouteGrid"), rulesGrid, rulesGrid.length, selid);

              var k = ((parseInt(selid) / 16) * 350);
              jQuery("#advRouteGrid").closest(".ui-jqgrid-bdiv").scrollTop(k);
              jQuery("#advRouteGrid").setSelection(selid, true);
           }
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "advrouterl");
           newRow = updnewRow();
           doReload = upddoReload();

           if (document.getElementById('mvPol').checked == true) {
              selid = updselidGrp();
              refreshGroup(jQuery("#advRouteGrid"), rulesGrid, rulesGrid.length, selid);

              var k = ((parseInt(selid) / 16) * 350);
              jQuery("#advRouteGrid").closest(".ui-jqgrid-bdiv").scrollTop(k);
              jQuery("#advRouteGrid").setSelection(selid, true);
           }
        });

        // Advanced
        \$("#advRouteGrid").jqGrid('navButtonAdd','#padvRouteGrid',{
javascript
$msg[0] = "*Avançado ";
$msg[1] = "*Advanced ";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
               \$("#advRouteGrid").showCol("sport");
               \$("#advRouteGrid").showCol("arNat");
           }
        });

        // Edit button
        \$("#advRouteGrid").jqGrid('navButtonAdd','#padvRouteGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$aralias", "advrouterl");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#advRouteGrid").jqGrid('navButtonAdd','#padvRouteGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             var selid = jQuery("#advRouteGrid").jqGrid('getGridParam','selrow');
             var selcur = jQuery("#advRouteGrid").jqGrid('getRowData', selid);

             rulesGrid = cloneRow(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "advrouterl", selcur['Group']);
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
           rulesGrid = delRow(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
        });

        // Add button
        \$("#advRouteGrid").jqGrid('navButtonAdd','#padvRouteGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             var selid = jQuery("#advRouteGrid").jqGrid('getGridParam','selrow');

             var defGroup = "iproute";
             if (selid > 0) {      
                var selcur = jQuery("#advRouteGrid").jqGrid('getRowData', selid);
                defGroup = selcur['Group'];
             }
             else {
                var rules = rulesGrid.length;
                defGroup = document.getElementById('arDefGroup').value;

                if (rules > 0) {
                   for (var i=0; i < rules; i++) {
                       selid = i;
                       if (rulesGrid[i]['Group'] === defGroup) i=rules;
                   }
                   selid = selid + 1;
                   jQuery("#advRouteGrid").setSelection(selid, true);
                }
             }

             rulesGrid = addRow(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "advrouterl", defGroup);
             newRow = updnewRow();
           }
        });

        // Change Policy condition
        jQuery("#chCond").click( function() {
           chGroupCond(jQuery("#advRouteGrid"), rulesGrid, document.fchcond.idcond.value);
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
           saveAll(jQuery("#advRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "advrouterl", "/admin/getadvrlroute.json", "/admin/chadvrlroute.cgi");
           newRow = updnewRow();
           if (newRow.length < 1) rulesCt = 0;
        });

        \$("#advRouteGrid").jqGrid('navButtonAdd','#padvRouteGrid',{
           caption:"&nbsp; Info",
           onClickButton:function(){
             var selid = jQuery("#advRouteGrid").jqGrid('getGridParam','selrow');
             var clret = jQuery("#advRouteGrid").jqGrid('getRowData', selid);
             if (clret['Desc'] !== "") alert(clret['Desc']);
           }
        });

        // Grid resize
        \$(window).bind('resize', function() {
            \$("#jqgrid").setGridWidth(\$(window).width() - 120);
        }).trigger('resize');
     });
  </script>\n\n
javascript

    my $srcfs = "";
    if ($canch == 0) {
       $msg[0] = "Somente leitura (nó escravo)!";
       $msg[1] = "Read-only (slave node)!";
       $srcfs = "<h5><FONT color=\"Red\"><strong>$msg[$FW_LANG]</strong></FONT></h5>";
    }

    $msg[0] = "Roteamento avançado: Regras de encaminhamento";
    $msg[1] = "Advanced routing: Forwarding rules";
    my $mstyle = menustyle("$msg[$FW_LANG]");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor="#F2F2F2" $STYLE>
  <span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG] ($srcfile)</span>

  <DIV align="center">
HTMLCODE

    ## Waiting form
    print FILE "<DIV align=\"center\" valign=\"center\" id=\"chwait\">";
    $msg[0] = "Aguarde... isto pode demorar um pouco!";
    $msg[1] = "Wait... this may take a little time!";
    print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
    print FILE "</DIV>";

    ## Condition form
    print FILE "<DIV align=\"center\" valign=\"center\" id=\"chcondition\">";
    print FILE "<form name=\"fchcond\">";
    $msg[0] = "Entre com um novo filtro *condition*";
    $msg[1] = "Enter with new condition";
    print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
    ckcond("idcond");
    $msg[0] = "Troca";
    $msg[1] = "Change";
    print FILE " <INPUT type=\"button\" id=\"chCond\" value=\"$msg[$FW_LANG]\">";
    $msg[0] = "Cancela";
    $msg[1] = "Cancel";
    print FILE "<INPUT type=\"button\" value=\"$msg[$FW_LANG]\" onclick=\"return document.getElementById('chcondition').style.display = 'none';\">";
    print FILE "</form></DIV>";

    ### Grid rules
    print FILE "<FORM name='flsadvRoute' action='/admin/chadvrlroute.cgi' method='POST'>";
    print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
    print FILE "<tbody><TR valign=\"bottom\" align=\"left\"><TD width=\"96%\">";
    print FILE "<FONT size='-1'><p>";
    print FILE "<select size='1' name='lsDefGroup' id='arDefGroup' style='width:120px; font-size:small;'>";
    print FILE "<OPTION value=\"iproute\">iproute</OPTION><OPTION value=\"netfilter\">netfilter</OPTION>";
    print FILE "</select>";
    print FILE " &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; ";
    $msg[0] = "Alterar";
    $msg[1] = "Change";
    print FILE "<i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"mvPol\" name=\"CkMvPol\">";
    $msg[0] = "Apelidos";
    $msg[1] = "Alias";
    print FILE " &nbsp; <i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"enAlias\" name=\"CkenAlias\"></FONT></p>\n";
print FILE << "HTMLCODE";
    <table id="advRouteGrid" width="100%" style="font-size:12px;"></table>
    <div id="padvRouteGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
    print FILE "</TD><TD width=\"4%\">";
    print FILE "&nbsp;<a href=\"javascript: document.fadvRouteGrid.gdmoveup.click();\">";
    print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "&nbsp;<a href=\"javascript: document.fadvRouteGrid.gdmovedown.click();\">";
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
    <form name="fadvRouteGrid">
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
