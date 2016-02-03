#!/usr/bin/perl

# Rev.2 - Version 5.0

# "POST /admin/chmasq.cgi" -> "delete" or "add" button
sub chmasq {
    my $s = shift;

    my $rlfw = 0;
    my $canSync = 0;
    my $txtvalue = "";
    my @msg = ("", ""), @msg2 = ("", "");
    my $res = HTTP::Response->new();
    read_fwmasq;

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
                if ($dvalue[1]) {
                   if ($dvalue[0] eq "mSrcIf" || $dvalue[0] eq "mDstIf") {
                      if ($dvalue[0] eq "mDstIf") {
                         $json{'mSrcIf'} =~ s/[\s]+$//;
                         $json{'mSrcIf'} = "$json{'mSrcIf'}\->$dvalue[1]";
                         $json{'mSrcIf'} = pack( 'A20', str_conv($json{'mSrcIf'}) );
                      }
                      else {
                         $json{'mSrcIf'} = str_conv($dvalue[1]);
                      }
                   }
                   else {
                      if ($dvalue[0] =~ /^(mpHttp|mpPop3|mDefProf|mLimProf)$/ ) {
                         $json{$dvalue[0]} = "";
                         if ($dvalue[1] ne "none") {
                            $json{$dvalue[0]} = $dvalue[1] if ($dvalue[0] ne "mLimProf");
                            $json{$dvalue[0]} = str_conv($dvalue[1]) if ($dvalue[0] eq "mLimProf");
                         }
                      }
                      elsif ($dvalue[0] eq "mTrans") {
                         $json{'mTrans'} = "";
                         $json{'mTrans'} = "redirect" if ($dvalue[1] eq "Yes");
                      }
                      elsif ($dvalue[0] eq "mdHttp") {
                         $json{'mdHttp'} = "";
                         $json{'mdHttp'} = "denyhttp" if ($dvalue[1] eq "Yes");
                      }
                      elsif ($dvalue[0] eq "NatType") {
                         $json{'NatType'} = "nomasq";
                         $json{'NatType'} = "" if ($dvalue[1] eq "MASQ");
                         $json{'NatType'} = "autosnat" if ($dvalue[1] eq "AUTO");
                      }
                      elsif ($dvalue[0] eq "Cond") {
                         $json{'Cond'} = "";
                         $json{'Cond'} = "$dvalue[1]" if ($dvalue[1] ne "none");
                      }
                      elsif ($dvalue[0] =~ /^(Control|id)$/) {
                         $json{$dvalue[0]} = $dvalue[1];
                      }
                      else {
                         $json{$dvalue[0]} = pack( 'A35', str_conv($dvalue[1]) ) if ($dvalue[1] !~ /^[\s]*$/);
                      }
                   }
                }
             }

             if (($json{'mSrcIf'} ne "" && $json{'Src'} ne "") && $json{'Control'} ne "set") {
                # fwmasq.net rules
                $canSync = 1;
                my $auxentry = "$json{'mSrcIf'} $json{'Src'}";
                $auxentry = "$auxentry proxyport=$json{'mpHttp'}" if ($json{'mpHttp'});
                if ($json{'mTrans'} eq "redirect") {
                   $auxentry = "$auxentry redirect";
                }
                else {
                   $auxentry = "$auxentry $json{'mdHttp'}" if ($json{'mdHttp'});
                }
                $auxentry = "$auxentry p3scan=$json{'mpPop3'}" if ($json{'mpPop3'});
                $auxentry = "$auxentry defprof=$json{'mDefProf'}" if ($json{'mDefProf'});
                $auxentry = "$auxentry limitprof=$json{'mLimProf'}" if ($json{'mLimProf'});
                $auxentry = "$auxentry $json{'NatType'}" if ($json{'NatType'});
                $auxentry = "$auxentry chk=$json{'Cond'}" if ($json{'Cond'});
                $auxentry = "$auxentry desc=\"$json{'Desc'}\"" if (length($json{'Desc'}) > 1);
                push(@unsortId, $json{'id'});
                push(@{$unsortData{$json{'id'}}}, $auxentry);
             }
             $canSync = 1 if ($json{'Control'} eq "set");
          }
       }
       if ($canSync == 1) {
          open FILE, ">$file_cfg{'fwmasq.net'}";

          # Writing fwmasq comments
          foreach my $mRules (@fwmasqcomments) {
              $mRules =~ s/\n//;
              $mRules =~ s/\\"/\"/g;
              $mRules =~ s/\\'/\'/g;
              print FILE "$mRules\n" if ($mRules);
          }

          # Writing fwmasq rules
          print FILE "\n";
          my @sortedId = sort { $a <=> $b } @unsortId;
          foreach (@sortedId) {
             foreach my $line (@{$unsortData{"$_"}}) {
                print FILE "$line\n";
             }
          }
          close(FILE);
          $txtvalue="OK";

          rsyncupdate("$file_cfg{'fwmasq.net'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
    }
    else {
       my $rtime = 2;
       if ($canch == 1) {
          $msg[0] = "Recarregando as regras de firewall!";
          $msg[1] = "Reloading firewall rules!";
          $msg2[0] = "<font size=\'2\'>Recarregando todas as regras...</font>";
          $msg2[1] = "<font size=\'2\'>Full reloading...</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");

          system("$FW_DIR/fwguardian --ignore-cluster 1>&2 2>/dev/null &") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
          system("$FW_DIR/fwguardian --ignore-webserver 1>&2 2>/dev/null &");
          system("$FW_DIR/fwguardian 1>&2 2>/dev/null &");

          rsyncupdate("$file_cfg{'fwmasq.net'}", "all", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       }
       else {
          $rtime = 0;
       }
       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/fwmasq.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page fwmasq.html"
sub get_fwmasq {
    my $htmlfile="$HTMLDIR/admin/dynhttp/fwmasq.html";
    read_profiles;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $defmSrc = `ip route ls scope link | grep 'proto kernel' | head -1 | sed 's/\\s.*//'`;
    $defmSrc =~ s/\n//;

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making banned.html
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
                 fMasqGrid.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 fMasqGrid.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.fmasq.ReloadFw.click();
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
        jQuery("#fwMasqGrid").jqGrid({
           url:'/admin/getfwmasq.json',
           datatype: "json",
           height: \$(window).height() - 360,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'Int (LAN)', 'Int (WAN)', 'End. de rede', 'Porta (Proxy HTTP)', 'Transparente', 'Bloquear HTTP', 'Porta (p3scan)', 'Condição', 'Perfil padrão', 'Perfis limitadores', 'SNAT', 'Descrição', 'Control' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'Int (LAN)', 'Int (WAN)', 'Net addr', 'Port (HTTP Proxy)', 'Transparent', 'Drop HTTP', 'Port (p3scan)', 'Condition', 'Default profile', 'Limiter profiles', 'SNAT', 'Description', 'Control' ],\n";
}
$msg[0] = selGridifnet("ipnet");
my $malias = $msg[0];
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id', sortable:true, sorttype: "int", key: true, width:30 },
javascript
    my $cint = 0;
    foreach (@{$fwcfg{"IFLAN"}},@{$fwcfg{"IFLOCAL"}}) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       if ($cint gt 0) {
          $msg[0] = "$msg[0];$line";
       }
       else { $msg[0] = "$line"; }
       $line = "$_+:$_+";
       $msg[0] = "$msg[0];$line";
       $cint++;
    }
print FILE << "javascript";
              { name:"mSrcIf", index:'mIntSrc', sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:74 },
javascript
    $cint = 0;
    foreach (@{$fwcfg{"IFPUB"}},@{$fwcfg{"IFNET"}},@{$fwcfg{"IFWAN"}}) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       if ($cint gt 0) {
          $msg[0] = "$msg[0];$line";
       }
       else { $msg[0] = "$line"; }
       $line = "$_+:$_+";
       $msg[0] = "$msg[0];$line";
       $cint++;
    }
print FILE << "javascript";
              { name:"mDstIf", index:'mIntDst', sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:78 },
              { name:"Src",    index:'Src', sortable:true, editable:true, width:140 },
              { name:"mpHttp", index:'mpHttp', sortable:true, editable:true, width:140 },
              { name:"mTrans", index:'mTrans', sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, width:90 },
              { name:"mdHttp", index:'mdHttp', sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, hidden:true, width:90 },
              { name:"mpPop3", index:'mpPop3', sortable:true, editable:true, hidden:true, width:100 },
javascript
    $msg[0] = "none:none;disabled:disabled";
    foreach (@fwchk) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       $msg[0] = "$msg[0];$line";
    }
print FILE "{ name:\"Cond\",  index:'Cond',  sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:120 },\n";
    $msg[0] = "none:none;%A:ACCEPT;%D:DROP;%R:REJECT";
    foreach (@fwprof) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       $msg[0] = "$msg[0];$line" if ($_ !~ /(^[\s]*(mangle:|rsquid|vpop3)|\?chk=)/);
    }
print FILE "{ name:\"mDefProf\",  index:'mDefProf', sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, hidden:true, width:82 },\n";
    $msg[0] = "none:none";
    foreach (@fwltprof) {
       $_ =~ s/\n//;
       $_ =~ s/.*://;
       my $line = "$_:$_";
       $msg[0] = "$msg[0];$line";
    }
print FILE "{ name:\"mLimProf\",  index:'mLimProf', sortable:true, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\", multiple: true, size: 3}, hidden:true, width:120 },\n";
print FILE << "javascript";
              { name:"NatType",   index:'NatType', sortable:false, editable:true, edittype:'select', editoptions:{value:"none:none;MASQ:MASQ;AUTO:AUTO"}, hidden:true, width:76 },
              { name:"Desc",      index:'Desc', sortable:false, editable:true, dataType:'string', width:320 },
              { name:"Control",   index:'Control', sortable:false, editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 }
           ],
           pager: '#pfwMasqGrid',
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
              editRow(jQuery("#fwMasqGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$malias", "fwmasq");
              newRow = updnewRow();
           },
           gridComplete: function(data, response) {
              rulesGrid=GridComplete(jQuery("#fwMasqGrid"), rulesGrid, rulesCt, saveall, "fwmasq");

              rulesCt++;
              saveall = 0;
              jQuery("#fwMasqGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Definições rápidas para acessos de Internet";
$msg[1] = "Quick definitions for Internet access";
print FILE "           caption: '$msg[$FW_LANG]'\n";
$msg[0] = "Fluxo de rede";
$msg[1] = "Network flow";
print FILE << "javascript";
        });
        jQuery("#fwMasqGrid").jqGrid('setGroupHeaders', {
             useColSpanStyle: true, 
             groupHeaders:[
               {startColumnName: 'mSrcIf', numberOfColumns: 3, titleText: '<font size="2">$msg[$FW_LANG]</font>'},
javascript
$msg[0] = "Proxy HTTP";
$msg[1] = "HTTP Proxy";
print FILE << "javascript";
               {startColumnName: 'mpHttp', numberOfColumns: 3, titleText: '<font size="2">$msg[$FW_LANG]</font>'} ]
        });
        jQuery("#fwMasqGrid").css('font-size', '13px');
        jQuery("#fwMasqGrid").jqGrid('navGrid',"#pfwMasqGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#fwMasqGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwmasq");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#fwMasqGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwmasq");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Advanced
        \$("#fwMasqGrid").jqGrid('navButtonAdd','#pfwMasqGrid',{
javascript
$msg[0] = "*Avançado ";
$msg[1] = "*Advanced ";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
               \$("#fwMasqGrid").showCol("mdHttp");
               \$("#fwMasqGrid").showCol("mpPop3");
               \$("#fwMasqGrid").showCol("mDefProf");
               \$("#fwMasqGrid").showCol("mLimProf");
               \$("#fwMasqGrid").showCol("NatType");
           }
        });

        \$("#fwMasqGrid").jqGrid('navButtonAdd','#pfwMasqGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#fwMasqGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$malias", "fwmasq");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#fwMasqGrid").jqGrid('navButtonAdd','#pfwMasqGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
$msg[0] = "Por favor... selecione a linha a ser removida!";
$msg[1] = "Please... Select the line to delete!";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = cloneRow(jQuery("#fwMasqGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwmasq", "$defmSrc");
             newRow = updnewRow();
           }
        });

        // Delete row in click event
        jQuery("#delgd").click( function() {
           rulesCt = 1;
           rulesGrid = delRow(jQuery("#fwMasqGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
        });

        \$("#fwMasqGrid").jqGrid('navButtonAdd','#pfwMasqGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = addRow(jQuery("#fwMasqGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwmasq", "$defmSrc", "$malias");
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
           saveAll(jQuery("#fwMasqGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "fwmasq", "/admin/getfwmasq.json", "/admin/chmasq.cgi");
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

    my $srcfs = "";
    if ($canch == 0) {
       $msg[0] = "Somente leitura (nó escravo)!";
       $msg[1] = "Read-only (slave node)!";
       $srcfs = "<h5><FONT color=\"Red\"><strong>$msg[$FW_LANG]</strong></FONT></h5>";
    }

    $msg[0] = "Configura&ccedil;&atilde;o b&aacute;sica: Internet";
    $msg[1] = "Basic config: Internet";
    my $mstyle = menustyle("$msg[$FW_LANG] ");
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

    ## Main forms
    print FILE "<DIV align=\"left\"><i>";
    print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 20px;\">";
    if ($FW_LANG == 0) {
       print FILE " 1. Configuração rápida para gateways de Internet.<BR />";
       print FILE " 2. Faz NAT de saída e autoriza proxy para as redes configuradas.<BR />";
       print FILE " 3. Limites de conexão podem ser aplicados com perfis limitadores (modo avançado).<BR />";
    }
    else {
       print FILE " 1. Quick configuration to Internet Gateways.<BR />";
       print FILE " 2. Makes outbound NAT and allow proxy for configured networks.<BR />";
       print FILE " 3. Connection limits can be configured with profiles limiters (advanced mode).<BR />";
    }
    print FILE "</span></i></DIV><BR />";

    print FILE "<table style=\"font-size: 0.92em;\"; border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align=\"center\">";
    print FILE "<tbody><TR valign=\"bottom\"><TD align=\"left\" width=\"96%\">";
    $msg[0] = "Apelidos";
    $msg[1] = "Alias";
    print FILE " <p><FONT size=\"-1\"> &nbsp; <i>$msg[$FW_LANG]</i> <INPUT type=\"checkbox\" id=\"enAlias\" name=\"CkenAlias\"></FONT></p>\n";
print FILE << "HTMLCODE";
    <table id="fwMasqGrid" width="100%" style="font-size:12px;"></table>
    <div id="pfwMasqGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE

    print FILE "</TD><TD width=\"4%\">";
    print FILE "&nbsp;<a href=\"javascript: document.fMasqGrid.gdmoveup.click();\">";
    print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "&nbsp;<a href=\"javascript: document.fMasqGrid.gdmovedown.click();\">";
    print FILE "<img src=\"buttons/mv_down.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "</TD></TR></tbody></table>";
    print FILE "<FORM name='fmasq' action='/admin/chmasq.cgi' method='POST'>";
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
    <form name="fMasqGrid">
    <input type="BUTTON" id="gdUp" name="gdmoveup" value="Up" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="gdDown" name="gdmovedown" value="Down" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="savegd" name="savegd" value="Save" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="delgd" name="delgd" value="Delete" style="visibility:hidden; position:absolute;" />
    </form></DIV></body>
    </html>
HTML
    close (FILE);

    return get_file("text/html", $htmlfile);
}

return 1;
