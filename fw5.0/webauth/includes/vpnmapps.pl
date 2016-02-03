#!/usr/bin/perl

#Rev.2 - Version 5.0

# "POST /admin/chvpnmapps.cgi" -> save or reload button
sub chvpnmapps {
    my $s = shift;

    my $rlfw = 0;
    my $canSync = 0;
    my $txtvalue = "";
    my $res = HTTP::Response->new();
    read_fwvpn;

    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && $canch == 1) {

       # Parsing json response (sorting by ID)
       my %json = ();
       my %gpName = ();
       my %groupData = ();
       my $group = "IP-USERMAPS";
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
                   my $auxvalue = str_conv($dvalue[1]);
                   if ($auxvalue && $auxvalue ne "0" && $auxvalue ne "none") {
                      if ($dvalue[0] eq "vUser") {
                         $json{$dvalue[0]} = pack( 'A20', str_conv($dvalue[1]) );
                      }
                      elsif ($dvalue[0] =~ /^(Dst|vType)$/) {
                         $json{$dvalue[0]} = pack( 'A35', $auxvalue);
                      }
                      elsif ($dvalue[0] =~ /^(Control|Cond|id)$/) {
                         $json{$dvalue[0]} = $dvalue[1];
                      }
                      else {
                         $json{$dvalue[0]} = $auxvalue if ($dvalue[1] !~ /^[\s]*$/);
                      }
                   }
                }
             }

             if ($json{'Group'} =~ /^IP-USERMAPS/ && $json{'vUser'} ne "" && $json{'Dst'} ne "" && $json{'vType'} ne "") {
                # vpn.conf rules
                $canSync = 1;
                $json{'fwTarg'} = "SET" if ($json{'vType'} =~ /ppp\s/);
                $json{'fwTarg'} = "ACCEPT" if ($json{'vType'} =~ /ssh\s/ && $json{'fwTarg'} eq "SET");
                $auxentry = "$json{'vUser'} $json{'Dst'} $json{'vType'} $json{'fwTarg'}\t";

                if ($json{'vType'} =~ /ppp\s/) {
                   my $vpass = "";
                   $vpass = $json{'vPass'} if ($json{'vPass'});
                   $auxentry = "$auxentry passwd=\"$vpass\"";
                   $auxentry = "$auxentry with-pap" if ($json{'vAuth'} eq "pap");
                   $auxentry = "$auxentry with-chpap" if ($json{'vAuth'} eq "chpap");
                }
                $auxentry = "$auxentry chk=$json{'Cond'}" if ($json{'Cond'});
                $auxentry = "$auxentry desc=\"$json{'Desc'}\"" if (length($json{'Desc'}) > 1);

                # policy rules
                push(@{$groupData{$group}}, $auxentry);
                $gpName{$group} = $json{'Group'};
                $gpName{$group} =~ s/\?chk=/ chk=/;
             }
             $canSync = 1 if ($json{'Control'} eq "set");
          }
       }

       if ($canSync == 1) {
          open FILE, ">$file_cfg{'vpn/vpn.conf'}";

          # Writing vpn comments
          foreach my $fRules (@vpncomments) {
              $fRules =~ s/\n//;
              $fRules =~ s/\\"/\"/g;
              $fRules =~ s/\\'/\'/g;
              print FILE "$fRules\n" if ($fRules);
          }

          # Writing vpn rules
          foreach my $fRules (@vpngroup) {
             my $bkRules = $fRules;
             $fRules =~ s/\?chk=.*//;
             my $setPol = $bkRules;
             $setPol =~ s/\?chk=/ chk=/;
             $setPol = $gpName{$fRules} if ($gpName{$fRules} && $groupData{"$fRules"}[0]);
             print FILE "\nset-policy $setPol";
             if ($groupData{"$fRules"}[0]) {
                foreach my $aRules (@{$groupData{"$fRules"}}) {
                   $aRules =~ s/\n//;
                   $aRules =~ s/\\"/\"/g;
                   $aRules =~ s/\\'/\'/g;
                   print FILE "\n$aRules";
                }
             }
             else {
                foreach my $aRules (@{$vpnrules{"$bkRules"}}) {
                   $aRules =~ s/\n//;
                   $aRules =~ s/\\"/\"/g;
                   $aRules =~ s/\\'/\'/g;
                   print FILE "\n$aRules" if ($aRules !~ /^status\s/);
                }
             }
             print FILE "\n";
          }
          close(FILE);
          $txtvalue="OK";

          rsyncupdate("$file_cfg{'vpn/vpn.conf'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
    }
    else {
       my $rtime = 2;
       if ($canch == 1) {
          $msg[0] = "Recarregando as regras de VPN!";
          $msg[1] = "Reloading VPN rules!";
          $msg2[0] = "<font size=\'2\'>Recarregando vpnfw...</font>";
          $msg2[1] = "<font size=\'2\'>vpnfw reloading...</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
          system("$FW_DIR/fwguardian --reload-vpn 1>&2 2>/dev/null &");

          rsyncupdate("$file_cfg{'vpn/vpn.conf'}", "vpn", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       }
       else {
          $rtime = 0;
       }
       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/vpnmapps.cgi\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page vpnmapps.html"
sub get_vpnmapps {

    my $htmlfile="$HTMLDIR/admin/dynhttp/vpnmapps.html";
    read_profiles;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making vpnmapps.html
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
                 document.fvpn.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 document.fvpn.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.fivpn.ReloadFw.click();
                 return false;
           });
        });
  </script>

  <script type="text/javascript">
     jQuery(document).ready(function(){

        // Rules array
        var saveall = 0;
        var rulesCt = 0;
        var rulesGrid = new Array();         // Main data
        var newRow = new Array();

        // Make jqgrid
        var scrollPosition = 0;
        jQuery("#fwVpnGrid").jqGrid({
           url:'/admin/getvpnmapps.json',
           datatype: "json",
           height: \$(window).height() - 300,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
    print FILE "           colNames:['ID', 'Politica', 'Usuário', 'Endereço (Dst)', 'Tipo', 'Alvo', 'Senha', 'Autenticação', 'Condição', 'Descrição', 'Control' ],\n";
}
else {
    print FILE "           colNames:['ID', 'Policy', 'User', 'Address (Dst)', 'Type', 'Target', 'Password', 'Auth', 'Condition', 'Description', 'Control' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id', sortable:false, width: 30, sorttype: "int", key: true },
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
    $msg[0] = selGridifnet("net");
    my $valias = $msg[0];

print FILE << "javascript";
              { name:"vUser",   index:'vUser',   sortable:false, editable:true, width:80 },
              { name:"Dst",     index:'Dst',     sortable:false, editable:true, width:120 },
              { name:"vType",   index:'vType',   sortable:false, editable:true, edittype:'select', editoptions:{value:"ppp:ppp;ssh:ssh"}, width:78 },
javascript
$msg[0] = "SET:SET;ACCEPT:ACCEPT;DROP:DROP;REJECT:REJECT";
foreach (@fwprof) {
   $_ =~ s/\n//;
   if ($_ !~ /(^[\s]*(rsquid|vpop3)$|\?chk=)/) {
      my $auxdesc = $_;
      $auxdesc =~ s/.*://;
      my $line = "$auxdesc:$auxdesc";
      $msg[0] = "$msg[0];$line";
   }
}
print FILE << "javascript";
              { name:"fwTarg", index:'fwTarg', sortable:false, editable:true, edittype:'select', editoptions:{value:"$msg[0]"}, width:120 },
              { name:"vPass",  index:'vPass', sortable:false, editable:true, width:120 },
              { name:"vAuth",  index:'vAuth', sortable:false, editable:true, edittype:"select", editoptions:{value:"chap:chap;pap:pap;chpap:chpap"}, width:80 },
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
              { name:"Control", index:'Control', sortable:false,  editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 }
           ],
           pager: '#pfwVpnGrid',
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
                 var selcur = jQuery("#fwVpnGrid").jqGrid('getRowData', selid);
                 var curPol = selcur['Group'];
                 var frPol = /\\?chk=/;
                 if (frPol.test(curPol)) curPol = curPol.replace(/.*\\?chk=/, "");
                 else curPol = "";

                 document.fchcond.idcond.value = curPol;
                 document.getElementById('chcondition').style.display = 'block';
              }
              else {
                 editRow(jQuery("#fwVpnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$valias", "vpnmapps");
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
              rulesGrid=GridComplete(jQuery("#fwVpnGrid"), rulesGrid, rulesCt, saveall, "vpnmapps");

              rulesCt++;
              jQuery("#fwVpnGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Mapeamentos";
$msg[1] = "Mappings";
print FILE "           caption: '$msg[$FW_LANG]'\n";
$msg[0] = "Autenticação PPP";
$msg[1] = "PPP Authentication";
print FILE << "javascript";
        });
        jQuery("#fwVpnGrid").jqGrid('setGroupHeaders', {
             useColSpanStyle: true, 
             groupHeaders:[ {startColumnName: 'vPass', numberOfColumns: 2, titleText: '<font size="2">$msg[$FW_LANG]</font>'} ]
        });
        jQuery("#fwVpnGrid").css('font-size', '13px');
        jQuery("#fwVpnGrid").jqGrid('navGrid',"#pfwVpnGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#fwVpnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "vpnmapps");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#fwVpnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "vpnmapps");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Edit button
        \$("#fwVpnGrid").jqGrid('navButtonAdd','#pfwVpnGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#fwVpnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$valias", "vpnmapps");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#fwVpnGrid").jqGrid('navButtonAdd','#pfwVpnGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
$msg[0] = "Por favor... selecione a linha a ser removida!";
$msg[1] = "Please... Select the line to delete!";
print FILE << "javascript";
           onClickButton:function(){
             var gridrules = jQuery("#fwVpnGrid").jqGrid('getDataIDs').length;
             if (gridrules > 0) {
                var clret = jQuery("#fwVpnGrid").jqGrid('getRowData', gridrules);
                rulesGrid = cloneRow(jQuery("#fwVpnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "vpnmapps", clret['Group']);
                newRow = updnewRow();
             }
           }
        });

        // Delete row in click event
        jQuery("#delgd").click( function() {
           rulesCt = 1;
           rulesGrid = delRow(jQuery("#fwVpnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
        });

        // Add button
        \$("#fwVpnGrid").jqGrid('navButtonAdd','#pfwVpnGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             var defGroup = "IP-USERMAPS";
             var gridrules = jQuery("#fwVpnGrid").jqGrid('getDataIDs').length;
             if (gridrules > 0) {
                var clret = jQuery("#fwVpnGrid").jqGrid('getRowData', gridrules);
                defGroup = clret['Group'];
             }

             rulesGrid = addRow(jQuery("#fwVpnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "vpnmapps", defGroup, "$valias");
             newRow = updnewRow();
           }
        });

        // Change Policy condition
        jQuery("#chCond").click( function() {
           var selid = \$("#fwVpnGrid").jqGrid('getGridParam','selrow');
           chGroupCond(jQuery("#fwVpnGrid"), rulesGrid, document.fchcond.idcond.value);
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
           saveAll(jQuery("#fwVpnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "vpnmapps", "/admin/getvpnmapps.json", "/admin/chvpnmapps.cgi");
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

    $msg[0] = "VPN: Mapeamento de usuários!";
    $msg[1] = "VPN: Users Mapping!";
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

   ## Grid rules
   print FILE "<FORM name=\"fivpn\" action=\"/admin/chvpnmapps.cgi\" method=\"post\">";
   print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
   print FILE "<tbody><TR valign=\"bottom\"><TD width=\"96%\">";
   print FILE "<font size=\"-1\"><p>";
   $msg[0] = "Alterar";
   $msg[1] = "Change";
   print FILE "<i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"mvPol\" name=\"CkMvPol\">";
   $msg[0] = "Apelidos";
   $msg[1] = "Alias";
   print FILE " &nbsp; <i>$msg[$FW_LANG]<i><INPUT type=\"checkbox\" id=\"enAlias\" name=\"CkenAlias\"></FONT></p>\n";
   print FILE << "HTMLCODE";
   <table id="fwVpnGrid" width="100%" style="font-size:12px;"></table>
   <div id="pfwVpnGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
   print FILE "</TD><TD width=\"4%\" align=\"left\">";
   print FILE "&nbsp;<a href=\"javascript: document.fvpn.gdmoveup.click();\">";
   print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
   print FILE "&nbsp;<a href=\"javascript: document.fvpn.gdmovedown.click();\">";
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
    <form name="fvpn">
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

return 1
