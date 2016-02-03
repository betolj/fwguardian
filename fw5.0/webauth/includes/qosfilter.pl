#!/usr/bin/perl -w

#Rev.2 - Version 5.0

# "POST /admin/chtffilter.cgi" -> save jqgrid event (root qdisc)
sub chtffilter {
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
             foreach my $auxjson2 (split/,/, $auxjson) {
                $auxjson2 =~ s/\"//g;
                $auxjson2 =~ s/\'//g;
                my @dvalue = ();
                @dvalue = split /:/, $auxjson2;

                if ($dvalue[0] eq "ifInt" || $dvalue[0] eq "fwTarg" || $dvalue[0] eq "Src" || $dvalue[0] eq "Dst") {
                   if ( $dvalue[0] eq "ifInt" || $dvalue[0] eq "fwTarg" ) { $json{$dvalue[0]} = pack( 'A15', str_conv($dvalue[1]) ); }
                   else { $json{$dvalue[0]} = pack( 'A35', str_conv($dvalue[1]) ); }
                }
                else {
                   my $auxvalue = str_conv($dvalue[1]);
                   if ($auxvalue && $auxvalue ne "0" && $auxvalue ne "0:0" && $auxvalue ne "none" && $auxvalue !~ /^0(k|K|m|M|g|G)(bit|bits)$/) {
                      if ($dvalue[0] =~ /^(proto|sport|dport|Desc)$/) {
                         $json{$dvalue[0]} = $auxvalue;
                      }
                      elsif ($dvalue[0] =~ /^(Control|id)$/) {
                         $json{$dvalue[0]} = $dvalue[1];
                      }
                      else {
                         $json{$dvalue[0]} = $auxvalue;
                      }
                   }
                }
             }

             if ($json{'ifInt'} ne "" && $json{'Src'} ne "" && $json{'Dst'} ne "" && $json{'fwTarg'} ne "" && $json{'Control'} ne "set") {
                # shape.conf rules
                $canSync = 1;
                $auxentry = "$json{'ifInt'} $json{'Src'} $json{'Dst'} $json{'fwTarg'}";
                if ($json{'qRate'} && $json{'qRate'} ne "") {
                   $auxentry = "$auxentry $json{'qRate'}";
                   $auxentry = "$auxentry burst=$json{'qBurst'}" if ($json{'qBurst'});
                }
                if ($json{'proto'} ne "any" && $json{'proto'} ne "") {
                   my $protoentry = "$json{'proto'}";
                   if ($json{'sport'} || $json{'dport'}) {
                      $auxentry = "$auxentry sport=$protoentry/$json{'sport'}" if ($json{'sport'});
                      $auxentry = "$auxentry dport=$protoentry/$json{'dport'}" if ($json{'dport'});
                   }
                   else {
                      $auxentry = "$auxentry dport=$protoentry";
                   }
                }

                $auxentry = "$auxentry connbytes=$json{'qcbytes'}" if ($json{'qcbytes'});
                $auxentry = "$auxentry connpkts=$json{'qcpkts'}" if ($json{'qcpkts'});
                $auxentry = "$auxentry connlimit=$json{'qclimit'}" if ($json{'qclimit'} && $json{'qclimit'} ne "0/32");
                $auxentry = "$auxentry length=$json{'qlength'}" if ($json{'qlength'});
                $auxentry = "$auxentry geoip=$json{'qgeoip'}" if ($json{'qgeoip'} && $json{'qgeoip'} ne "any");
                $auxentry = "$auxentry ndpi=$json{'nDpi'}" if ($json{'nDpi'});

                $auxentry = "$auxentry chk=$json{'Cond'}" if ($json{'Cond'});
                $auxentry = "$auxentry desc=\"$json{'Desc'}\"" if (length($json{'Desc'}) gt 1);

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
          if (scalar @unsortId > 0) {
             print FILE "\nset-filter\n";
             my @sortedId = sort { $a <=> $b } @unsortId;
             foreach (@sortedId) {
                foreach my $line (@{$unsortData{"$_"}}) {
                   print FILE "$line\n";
                }
             }
          }

          # Writing set-egress
          foreach my $qRules (@qosegress) {
             if ($qRules) {
                my $countqRules = 0;
                print FILE "\n$qRules";
                my (undef, $auxqRules, undef) = split /\s+/, $qRules, 3;
                foreach my $arRules (@{$qosegressrules{"$auxqRules"}}) {
                   $aqRules =~ s/\n//;
                   $aqRules =~ s/\\"/\"/g;
                   $aqRules =~ s/\\'/\'/g;
                   print FILE "\n$arRules";
                }
                print FILE "\n";
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
          $msg[0] = "Recarregando as regras de QoS!";
          $msg[1] = "Reloading QoS rules!";
          $msg2[0] = "<font size=\'2\'>Recarregando tfshape...</font>";
          $msg2[1] = "<font size=\'2\'>tfshape reloading...</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
          system("$FW_DIR/fwguardian --reload-qos 1>&2 2>/dev/null &");

          rsyncupdate("$file_cfg{'tfshape/shape.conf'}", "qos", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       }
       else {
          $rtime = 0;
       }
       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/tffilter.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page qosfilter.html"
sub get_qosfilter {
    my $htmlfile="$HTMLDIR/admin/dynhttp/qosfilter.html";
    read_fwcfg;
    read_fwqos;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $defType="htb";
    my $qosapp=`iptables -m ndpi --help | tail -169 | grep -v "\\(ftp\\|tftp\\|pptp\\|sip\\|h323\\|irc\\|twitter\\|netflix\\|facebook\\|dropbox\\|googlegmail\\|googlemaps\\|google\\|youtube\\|appleitunes\\|apple\\|appleicloud\\|viber\\|lastfm\\|grooveshark\\|tuenti\\)" | sed 's/--\\([a-zA-Z0-9]\\+\\) .*/\\1/' | awk '{ print \$1":"\$1; }' | tr '\\n' ';'`;
    $qosapp="none:none;ftp:ftp;tftp:tftp;pptp:pptp;sip:sip;h323:h323;irc:irc;$qosapp";
    $qosapp =~ s/\;$//;

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making tfshape.html
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
                 document.fqosfilter.ReloadFw.click();
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
           url:'/admin/getfilterqos.json',
           datatype: "json",
           height: \$(window).height() - 290,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
    print FILE "           colNames:['ID', 'Interface', 'Origem', 'Destino', 'Alvo', 'Taxa', 'Rajada', 'Proto', 'Porta de origem', 'Porta de destino', 'n Bytes', 'Pacotes', 'Conexões', 'Tamanho pct', 'Geo-IP', 'Aplicação', 'Condição', 'Descrição', 'Control' ],\n";
}
else {
    print FILE "           colNames:['ID', 'Interface', 'Source', 'Destination', 'Target', 'Rate', 'Burst', 'Proto', 'Source port', 'Destination port', 'n Bytes', 'Packets', 'Connections', 'Pkt length', 'Geo-IP', 'Application', 'Condition', 'Description', 'Control' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id', sortable:false, width: 30, sorttype: "int", key: true },
javascript
    $msg[0] = selGridifnet("net");
    my $qalias = $msg[0];

    my $cint = 0;
    foreach (@fwifs) {
       $_ =~ s/\n//;
       if ($_ !~ /^ifb/) {
          my $line = "$_:$_";
          if ($cint gt 0) {
             $msg[0] = "$msg[0];$line";
          }
          else { $msg[0] = "any:any;$line"; }
          $line = "$_+:$_+";
          $msg[0] = "$msg[0];$line";
          $cint++;
       }
    }

print FILE << "javascript";
              { name:"ifInt",   index:'ifInt',   sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:78 },
              { name:"Src",     index:'Src',   sortable:false, editable:true, width:140 },
              { name:"Dst",     index:'Dst',   sortable:false, editable:true, width:140 },
              { name:"fwTarg",  index:'fwTarg', sortable:false, editable:true, edittype:'select', editoptions:{value:"INGRESS:INGRESS;IN-IGNORE:IN-IGNORE;IGNORE:IGNORE;TC-IGNORE:TC-IGNORE;MIRROR:MIRROR;LB:LB"}, width:84 },
              { name:"qRate",   index:'qRate',  sortable:false, editable:true, defaultValue: '0', width:80 },
              { name:"qBurst",  index:'qBurst', sortable:false, editable:true, dataType:'string', defaultValue:'minburst', hidden:true, width:70 },
              { name:"proto",   index:'proto', sortable:false, editable:true, edittype:"select", editoptions:{value:"any:any;tcp:tcp;udp:udp;icmp:icmp;gre:gre;ah:ah;esp:esp;ospf:ospf;vrrp:vrrp;ipp2p:ipp2p"}, width:70 },
              { name:"sport",   index:'sport', sortable:false, editable:true, width:162 },
              { name:"dport",   index:'dport',    sortable:false, editable:true, width:162 },
              { name:"qcbytes", index:'qcbytes',  sortable:false, editable:true, hidden:true, width:90 },
              { name:"qcpkts",  index:'qcpkts',   sortable:false, editable:true, hidden:true, width:90 },
              { name:"qclimit", index:'qclimit',  sortable:false, editable:true, hidden:true, width:90 },
              { name:"qlength", index:'qlength',  sortable:false, editable:true, hidden:true, width:90 },
javascript
    $msg[0] = "any:any";
    foreach (`cat $FW_DIR/modules/tools/geoip.list`) {
       $_ =~ s/\n//;
       my $country_id = $_;
       my $country_name = $country_id;
       $country_id =~ s/\s.*//;
       $country_name =~ s/^(([A-Z0-9])+){2}\s//;
       my $line = "$country_id:$country_name";
       $msg[0] = "$msg[0];$line";
    }
print FILE << "javascript";
              { name:"qgeoip",  index:'qgeoip',   sortable:false, editable:true, edittype:'select', formatter:'select', editoptions:{value:\"$msg[0]\", multiple: true, size: 4}, width:120 },
              { name:"nDpi",    index:'nDpi',     sortable:false, editable:true, edittype:"select", editoptions:{value:\"$qosapp\", multiple: true, size: 4}, hidden:true, width:120 },
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
           ondblClickRow: function (selid, iRow,iCol) {
              editRow(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$qalias", "qosfilter");
              newRow = updnewRow();
           },
           gridComplete: function(data, response) {
              rulesGrid=GridComplete(jQuery("#ifQosGrid"), rulesGrid, rulesCt, saveall, "qosfilter");

              rulesCt++;
              jQuery("#ifQosGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Filtragem global (ingress, LB ou bypass)";
$msg[1] = "Global filtering (ingress, LB or bypass)";
print FILE "           caption: '$msg[$FW_LANG]'\n";
$msg[0] = "Limites via netfilter";
$msg[1] = "Netfilter limits";
print FILE << "javascript";
        });
        jQuery("#ifQosGrid").jqGrid('setGroupHeaders', {
             useColSpanStyle: true, 
             groupHeaders:[
               { startColumnName: 'qcbytes', numberOfColumns: 5, titleText: '<font size="2">$msg[$FW_LANG]</font>'},
javascript
$msg[0] = "Opções Ingress";
$msg[1] = "Ingress options";
print FILE << "javascript";
               { startColumnName: 'qRate', numberOfColumns: 2, titleText: '<font size="2">$msg[$FW_LANG]</font>'}
             ]
        });
        jQuery("#ifQosGrid").css('font-size', '13px');
        jQuery("#ifQosGrid").jqGrid('navGrid',"#pifQosGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "qosfilter");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "qosfilter");
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
               \$("#ifQosGrid").showCol("qBurst");
               \$("#ifQosGrid").showCol("qcbytes");
               \$("#ifQosGrid").showCol("qcpkts");
               \$("#ifQosGrid").showCol("qclimit");
               \$("#ifQosGrid").showCol("qlength");
               \$("#ifQosGrid").showCol("qgeoip");
               \$("#ifQosGrid").showCol("nDpi");
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
              editRow(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$qalias", "qosfilter");
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
             rulesGrid = cloneRow(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "qosfilter", "");
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
        });

        // Add button
        \$("#ifQosGrid").jqGrid('navButtonAdd','#pifQosGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = addRow(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "qosfilter", "", "");
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
           saveAll(jQuery("#ifQosGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "qosfilter", "/admin/getfilterqos.json", "/admin/chtffilter.cgi");
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

   $msg[0] = "QoS: Filtros alternativos!";
   $msg[1] = "QoS: Alternative filters!";
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

   ### Grid rules
   print FILE "<FORM name=\"fqosfilter\" action=\"/admin/chtffilter.cgi\" method=\"post\">";
   print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
   print FILE "<tbody><TR valign=\"bottom\"><TD width=\"96%\">";
   $msg[0] = "Apelidos";
   $msg[1] = "Alias";
   print FILE "<FONT size=\"-1\"><p> &nbsp; <i>$msg[$FW_LANG]</i> <INPUT type=\"checkbox\" id=\"enAlias\" name=\"CkenAlias\"></FONT></p>\n";
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
   $msg[0] = "Recarregar";
   $msg[1] = "Reload";
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
