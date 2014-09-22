#!/usr/bin/perl -w

#Rev.1 - Version 5.0

# "POST /admin/chqosegress.cgi" -> save jqgrid event (root qdisc)
sub chqosegress {
    my $s = shift;

    my $rlfw = 0;
    my $canSync = 0;
    my $txtvalue = "";
    my $res = HTTP::Response->new();
    read_fwqos;

    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && $canch == 1) {

       # Parsing json response (sorting by ID)
       my %json = ();
       my @unsortId = ();
       my %unsortData = ();
       $txtvalue = "NO";

       foreach my $auxjson (split /"[0-9]+":/, $s) {
          $auxjson =~ s/{//g;
          $auxjson =~ s/}//g;
          $auxjson =~ s/,$//;

          if ($auxjson && $auxjson ne "") {
             %json = ();
             my $callow = 0;
             foreach my $auxjson2 (split/,/, $auxjson) {
                $auxjson2 =~ s/\"//g;
                $auxjson2 =~ s/\'//g;
                my @dvalue = ();
                @dvalue = split /:/, $auxjson2;

                if ($dvalue[0] eq "ifNClass" && $dvalue[1] ne "") {
                   $json{'ifPClass'} =~ s/\s+$//;
                   $json{'ifPClass'} = "$json{'ifPClass'}\->$dvalue[1]";
                   $json{'ifPClass'} = pack( 'A30', str_conv($json{'ifPClass'}) );
                   $callow = 1;
                }
                elsif ($dvalue[0] =~ /^(Control|id)$/) {
                   $json{$dvalue[0]} = $dvalue[1];
                }
                else {
                   $json{$dvalue[0]} = str_conv($dvalue[1]) if ($dvalue[1] && $dvalue[1] ne "none" && $dvalue[1] ne "0");
                }
             }

             if ($json{'ifPClass'} ne "" && $json{'ifRate'} ne "" && $callow == 1) {
                # shape.conf rules
                $canSync = 1;
                $auxentry = "set-egress\t$json{'ifPClass'} $json{'ifRate'}:$json{'ifRateMax'}\t";
                $auxentry = "$auxentry burst=$json{'ifBurst'}"  if ($json{'ifBurst'});
                if ($json{'ifLatency'} && $json{'ifLatency'} ne "none") {
                   $json{'ifLatency'} = "$json{'ifLatency'}ms" if ($json{'ifLatency'} !~ /ms$/);
                   $auxentry = "$auxentry latency=$json{'ifLatency'}";
                }
                $auxentry = "$auxentry prio=$json{'ifPrio'}"  if ($json{'ifPrio'});
                $auxentry = "$auxentry $json{'ifType'}" if ($json{'ifType'} && $json{'ifType'} ne "classify-rule");
                if ($json{'ifSFQf'} ne "default") {
                   if ($json{'ifSFQf'} ne "disabled") { $auxentry = "$auxentry sfq-flow=$json{'ifSFQf'}/$json{'ifSFQh'}"; }
                   else { $auxentry = "$auxentry sfq-flow=disabled"; };
                }
                if ($json{'ifPkts'} ne "default" && $json{'ifPkts'} ne "none") {
                   $auxentry = "$auxentry packets=$json{'ifPkts'}";
                }
                if ($json{'ifnfLb'} eq "Yes") {
                   $auxentry = "$auxentry nf-lb";
                   if ($json{'ifTrack'} ne "none") {
                      foreach my $lbtrack (split /,/, $json{'ifTrack'}) {
                         $auxentry = "$auxentry track-new"  if ($lbtrack eq "track-new");
                         $auxentry = "$auxentry track-dst"  if ($lbtrack eq "track-dst");
                         $auxentry = "$auxentry fixed"  if ($lbtrack eq "fixed");
                      }
                   }
                }
                $auxentry = "$auxentry chk=$json{'Cond'}" if ($json{'Cond'});
                $auxentry = "$auxentry desc=\"$json{'Desc'}\"" if (length($json{'Desc'}) > 1);
                push(@unsortId, $json{'id'});
                push(@{$unsortData{$json{'id'}}}, $auxentry);
             }
             $canSync = 1 if ($json{'Control'} eq "set");
          }
       }

       if ($canSync == 1) {
          open FILE, ">$file_cfg{'tfshape/shape.conf'}";

          # Writing qos comments
          foreach my $qRules (@qoscomments) {
              $qRules =~ s/\n//;
              $qRules =~ s/\\"/\"/g;
              $qRules =~ s/\\'/\'/g;
              print FILE "$qRules\n" if ($qRules);
          }

          # Writing set-qos rules
          print FILE "\n";
          foreach my $qRules (@qosset) {
             $qRules =~ s/\n//;
             $qRules =~ s/\\"/\"/g;
             $qRules =~ s/\\'/\'/g;
             print FILE "$qRules\n" if ($qRules);
          }

          # Writing set-filter
          print FILE "\nset-filter\n";
          foreach my $qRules (@qosrules) {
             $qRules =~ s/\n//;
             $qRules =~ s/\\"/\"/g;
             $qRules =~ s/\\'/\'/g;
             print FILE "$qRules\n" if ($qRules);
          }

          # Writing set-egress
          my @sortedId = sort { $a <=> $b } @unsortId;
          foreach (@sortedId) {
             foreach my $qRules (@{$unsortData{"$_"}}) {
                if ($qRules) {
                   print FILE "\n$qRules";
                   my (undef, $auxqRules, undef) = split /[\s]+/, $qRules, 3;
                   foreach my $arRules (@{$qosegressrules{"$auxqRules"}}) {
                      $aqRules =~ s/\n//;
                      $aqRules =~ s/\\"/\"/g;
                      $aqRules =~ s/\\'/\'/g;
                      print FILE "\n$arRules";
                   }
                   print FILE "\n";
                }
             }
          }
          close(FILE);
          $txtvalue="OK";

          rsyncupdate("$file_cfg{'tfshape/shape.conf'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
    }
    else {
       my $rtime = 2;
       if ($canch == 1) {
          $msg[0] = "Aplicando as regras de QoS!";
          $msg[1] = "Applying QoS rules!";
          $msg2[0] = "<font size=\'2\'>Recarregando tfshape...</font>";
          $msg2[1] = "<font size=\'2\'>tfshape reloading...</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
          system("$FW_DIR/fwguardian --reload-qos 1>&2 2>/dev/null &");

          rsyncupdate("$file_cfg{'tfshape/shape.conf'}", "qos", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       }
       else {
          $rtime = 0;
       }
       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/tfegressclass.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page qosegress.html"
sub get_qosegress {
    my $htmlfile="$HTMLDIR/admin/dynhttp/qosegress.html";
    read_fwqos;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    $defType="htb";

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making tfshape.html
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
       font-size: 12px;
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
                 document.fifQosGrid.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 document.fifQosGrid.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.fqosset.ReloadFw.click();
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
        jQuery("#ifQosGrid").jqGrid({
           url:'/admin/getegressqos.json',
           datatype: "json",
           height: \$(window).height() - 330,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
    print FILE "           colNames:['ID', 'Classe pai', 'Nova classe', 'Taxa', 'Taxa máxima', 'Rajada', 'Latência', 'Prio', 'Classificação', 'Fluxo SFQ', 'hash SFQ', 'Pacotes', 'Netfilter LB', 'LB maps', 'Condição', 'Descrição', 'Control' ],\n";
}
else {
    print FILE "           colNames:['ID', 'Parent class', 'New class', 'Rate', 'Max rate', 'Burst', 'Latency', 'Prio', 'Classification', 'SFQ Flow', 'SFQ hash', 'Packets', 'Netfilter LB', 'Track LB', 'Condition', 'Description', 'Control' ],\n";
}
    my $countp=0;
    foreach (@qosparent) {
       $countp++;
       $_ =~ s/\n//;
       my $line = "$_:$_";
       if ($countp gt 1) { $msg[0] = "$msg[0];$line"; }
       else { $msg[0] = "$line"; }
    }
print FILE << "javascript";
           colModel: [
              { name:"id",        index:'id', width: 30, sorttype: "int", key: true },
              { name:"ifPClass",  index:'ifPClass',  sortable:true,  editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:140 },
              { name:"ifNClass",  index:'ifPNlass',  sortable:true,  editable:true, width:140 },
              { name:"ifRate",    index:'ifRate',    sortable:true,  editable:true, defaultValue: '1Mbit', width:80 },
              { name:"ifRateMax", index:'ifRateMax', sortable:true,  editable:true, defaultValue: '1Mbit', width:80 },
              { name:"ifBurst",   index:'ifBurst',   sortable:false, editable:true, dataType:'string', defaultValue:'minburst', width:70 },
              { name:"ifLatency", index:'ifLatency', sortable:false, editable:true, dataType:'string', defaultValue:'minburst', width:70 },
              { name:"ifPrio",  index:'ifPrio', sortable:false, editable:true, hidden:true, width:40 },
              { name:"ifType",  index:'ifType', sortable:false, editable:true, edittype:"select", editoptions:{value:"classify-rule:classify-rule;mark-rule:mark-rule;premark-rule:premark-rule;postmark:postmark-rule;tc-rule:tc-rule"}, hidden:true, width:120 },
              { name:"ifSFQf",  index:'ifSFQ',  sortable:false, editable:true, edittype:"select", editoptions:{value:"default:default;src:src;dst:dst;proto:proto;proto-src:proto-src;proto-dst:proto-dst;nfct-src:nfct-src;nfct-dst:nfct-dst;disabled:disabled", multiple: true, size: 3}, hidden:true, width:100 },
              { name:"ifSFQh",  index:'ifSFQh',  sortable:false, editable:true, hidden:true, width:100 },
              { name:"ifPkts",  index:'ifPkts',  sortable:false, editable:true, hidden:true, width:80 },
              { name:"ifnfLb",  index:'ifnfLb',  sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, hidden:true, width:90 },
              { name:"ifTrack", index:'ifTrack', sortable:false, editable:true, edittype:"select", editoptions:{value:"none:none;track-new:track-new;track-dst:track-dst;fixed:fixed", multiple: true, size: 3}, hidden:true, width:90 },
javascript
    $msg[0] = "none:none;disabled:disabled";
    foreach (@fwchk) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       $msg[0] = "$msg[0];$line";
    }
print FILE "{ name:\"Cond\",  index:'Cond',  sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:120 },\n";
print FILE << "javascript";
              { name:"Desc",    index:'Desc',  sortable:false, editable:true, dataType:'string', width:320 },
              { name:"Control",  index:'Control',  sortable:false,  editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 }
           ],
           pager: '#pifQosGrid',
           editurl:'clientArray',
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
              editRow(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "qosclass");
              newRow = updnewRow();
           },
           gridComplete: function(data, response) {
              rulesGrid=GridComplete(jQuery("#ifQosGrid"), rulesGrid, rulesCt, saveall, "qosclass");

              rulesCt++;
              saveall = 0;
              jQuery("#ifQosGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Definições das classes (Egress)";
$msg[1] = "Class definitions (Egress)";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#ifQosGrid").jqGrid('setGroupHeaders', {
             useColSpanStyle: true, 
             groupHeaders:[
               {startColumnName: 'ifSFQf', numberOfColumns: 3, titleText: '<font size="2">SFQ/Leaf</font>'},
javascript
$msg[0] = "Taxa (bits)";
$msg[1] = "Rate (bits)";
print FILE << "javascript";
               {startColumnName: 'ifRate', numberOfColumns: 2, titleText: '<font size="2">$msg[$FW_LANG]</font>'},
javascript
$msg[0] = "Balanceamento de carga";
$msg[1] = "Load balance";
print FILE << "javascript";
               {startColumnName: 'ifnfLb', numberOfColumns: 2, titleText: '<font size="2">$msg[$FW_LANG]</font>'} ]
        });

        jQuery("#ifQosGrid").css('font-size', '13px');
        jQuery("#ifQosGrid").jqGrid('navGrid',"#pifQosGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "qosclass");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "qosclass");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Advanced
        \$("#ifQosGrid").jqGrid('navButtonAdd','#pifQosGrid',{
javascript
$msg[0] = "*Avançado ";
$msg[1] = "*Advanced ";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
               \$("#ifQosGrid").showCol("ifPrio");
               \$("#ifQosGrid").showCol("ifType");
               \$("#ifQosGrid").showCol("ifSFQf");
               \$("#ifQosGrid").showCol("ifSFQh");
               \$("#ifQosGrid").showCol("ifPkts");
               \$("#ifQosGrid").showCol("ifnfLb");
               \$("#ifQosGrid").showCol("ifTrack");
           }
        });

        // Edit button
        \$("#ifQosGrid").jqGrid('navButtonAdd','#pifQosGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "qosclass");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#ifQosGrid").jqGrid('navButtonAdd','#pifQosGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = cloneRow(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "qosclass", "$defType");
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
           rulesGrid = delRow(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
javascript
$msg[0] = "Cuidado: todas as regras associadas a classe serão removidas após clicar em *salvar*.";
$msg[1] = "Caution: all rules associated with class will be removed after *save* click.";
print FILE << "javascript";
           if (rulesGrid.length > 0) alert('$msg[$FW_LANG]');
        });

        // Add button
        \$("#ifQosGrid").jqGrid('navButtonAdd','#pifQosGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = addRow(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "qosclass", "$defType", "");
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
           saveAll(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "qosclass", "/admin/getegressqos.json", "/admin/chegress.cgi");
           newRow = updnewRow();
           if (newRow.length < 1) rulesCt = 0;
        });

        \$("#ifQosGrid").jqGrid('navButtonAdd','#pifQosGrid',{
           caption:"&nbsp; Info",
           onClickButton:function(){
             var selid = jQuery("#ifQosGrid").jqGrid('getGridParam','selrow');
             var clret = jQuery("#ifQosGrid").jqGrid('getRowData', selid);
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

   $msg[0] = "QoS: Taxas - classes de enfileiramento!";
   $msg[1] = "QoS: Rate - class queuing!";
   my $mstyle = menustyle("$msg[$FW_LANG]");
   print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE>
  <span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG] ($srcfile)</span>

  <DIV align="center">
HTMLCODE

   ## Waiting form
   print FILE "<DIV align=\"center\" valign=\"center\" id=\"chwait\">";
   $msg[0] = "Aguarde... isto pode demorar um pouco!";
   $msg[1] = "Wait... this may take a little time!";
   print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
   print FILE "</DIV>";

   ### DIV QoS options
   print FILE "<DIV align=\"left\"><i>";
   print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 20px;\">";
   if ($FW_LANG == 0) {
      print FILE "1. Limites de tráfego: 'Taxa' e 'Taxa máxima' (limitado pelo pai).<BR />";
      print FILE "2. Opte preferêncialmente pela divisão justa de banda com SFQ - as opções de LB são experimentais. <BR />";
      print FILE "3. Classes especiais: 'default...'(identifica a classe padrão) e 'realtime...'(identifica uma classe RT - HFSC).<BR />";
      print FILE "4. Metodos de classificação: classify-rule (netfilter CLASSIFY - padrão), mark-rule (netfilter MARK) ou tc-rule (iproute2 tc).<BR />";
   }
   else {
      print FILE "1. Rate limits: 'Rate' and 'Max rate' (parent limited).<BR />";
      print FILE "2. Preferably opt for a fair sharing of bandwidth with SFQ - LB options are experimental.<BR />";
      print FILE "3. Special classes: 'default...'(identifies the default class) and 'realtime...'(identifies a RT class - HFSC).<BR />";
      print FILE "4. Classification methods: classify-rule (netfilter CLASSIFY - default), mark-rule (netfilter MARK) ou tc-rule (iproute2 tc).<BR />";
   }
   print FILE "</span></i></DIV><BR />";

   ### Grid rules
   print FILE "<FORM name=\"fqosset\" action=\"/admin/chegress.cgi\" method=\"post\">";
   print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
   print FILE "<tbody><TR valign=\"bottom\"><TD width=\"96%\">";
   print FILE << "HTMLCODE";
   <table id="ifQosGrid" width="100%" style="font-size:12px;"></table>
   <div id="pifQosGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
   print FILE "</TD><TD width=\"4%\" align=\"left\">";
   print FILE "&nbsp;<a href=\"javascript: document.fifQosGrid.gdmoveup.click();\">";
   print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
   print FILE "&nbsp;<a href=\"javascript: document.fifQosGrid.gdmovedown.click();\">";
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
   $msg[0] = "Aplicar";
   $msg[1] = "Apply";
   print FILE " &nbsp; <a href=\"#\" id=\"btrel\" class=\"uibt\">$msg[$FW_LANG]</a>";

print FILE << "HTML";
    <form name="fifQosGrid">
    <input type="BUTTON" id="gdUp" name="gdmoveup" value="Up" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="gdDown" name="gdmovedown" value="Down" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="savegd" name="savegd" value="Save" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="delgd" name="delgd" value="Delete" style="visibility:hidden; position:absolute;" />
    </form></DIV></body>
    </html>
HTML
  close(FILE);

  return get_file("text/html", $htmlfile);
}

return 1;
