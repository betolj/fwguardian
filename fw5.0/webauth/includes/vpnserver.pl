#!/usr/bin/perl

#Rev.2 - Version 5.0

# "POST /admin/chvpnserver.cgi" -> save or reload button
sub chvpnserver {
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
       my $group = "";
       my $auxOption = "";
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
                if ($dvalue[1] && $dvalue[1]) {
                   my $auxvalue = str_conv($dvalue[1]);
                   $json{'vValue'} = "none" if ($dvalue[0] eq "vValue");
                   if ($auxvalue && (($auxvalue ne "0" && $auxvalue ne "none") || $dvalue[0] eq "vOption")) {
                      if ($dvalue[0] eq "vOption") {
                         $auxOption = $auxvalue;
                         $json{$dvalue[0]} = pack( 'A20', $auxvalue);
                      }
                      elsif ($dvalue[0] eq "vValue") {
                         $auxvalue = "yes" if ($auxvalue eq "Yes");
                         $json{$dvalue[0]} = pack( 'A35', $auxvalue);
                      }
                      elsif ($dvalue[0] =~ /^(Group|Control|Cond|id)$/) {
                         $json{$dvalue[0]} = $dvalue[1];
                      }
                   }
                }
             }

             if ($json{'Group'} =~ /^(PPTP|IPSEC)-SERVER/ && $auxOption ne "status" && $auxOption ne "") {
                # vpn.conf rules
                $canSync = 1;
                if ($auxOption eq "default-psk" && $json{'vValue'} =~ /^auto\s/) {
                   $json{'vValue'} = `pwgen -s 30 1`;
                   if ($json{'vValue'} && $json{'vValue'} !~ /^(auto\s|$|\n$)/) {
                      $json{'vValue'} = pack( 'A35', "$json{'vValue'}");
                   }
                   else {
                      $json{'vValue'} = pack( 'A35', "none");
                      log_warning("WARN: default-psk require *pwgen* tool to create a proper racoon ipsec psk!");
                   }
                }
                else {
                   $json{'vValue'} = "none" if ($json{'vValue'} eq "" || !$json{'vValue'});
                }

                $auxentry = "$json{'vOption'} $json{'vValue'}";
                $auxentry = "$auxentry \tchk=$json{'Cond'}" if ($json{'Cond'});

                # policy rules
                $group = $json{'Group'};
                $group =~ s/\?chk=.*// if ($group =~ /\?chk=/);
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
                   print FILE "\n$aRules";
                }
             }
             print FILE "\n";
          }
          close(FILE);
          $txtvalue="OK";

          rsyncupdate("$file_cfg{'vpn/vpn.conf'}", "vpnserver", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
          system("$FW_DIR/fwguardian --configure-vpnserver 1>&2 2>/dev/null");
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
       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/vpnservers.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page vpnserver.html"
sub get_vpnserver {

    my $htmlfile="$HTMLDIR/admin/dynhttp/vpnserver.html";
    read_fwcfg;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making vpnserver.html
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
           url:'/admin/getvpnserver.json',
           datatype: "json",
           height: \$(window).height() - 270,
           width: \$(window).width() - 50,
javascript
if ($FW_LANG == 0) {
    print FILE "           colNames:['ID', 'Politica', 'Opção', 'Valor', 'Condição', 'Control' ],\n";
}
else {
    print FILE "           colNames:['ID', 'Policy', 'Option', 'Value', 'Condition', 'Control' ],\n";
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
              { name:"vOption", index:'vOption', sortable:false, editable:false, width:220 },
              { name:"vValue",  index:'vValue',  sortable:false, editable:true, width:380 },
javascript
    $msg[0] = "none:none;disabled:disabled";
    foreach (@fwchk) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       $msg[0] = "$msg[0];$line";
    }
print FILE "{ name:\"Cond\",  index:'Cond',  sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:120 },\n";
print FILE << "javascript";
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
             var selcur = jQuery("#fwVpnGrid").jqGrid('getRowData', selid);
             if (document.getElementById('mvPol').checked == true) {
                 var curPol = selcur['Group'];
                 var frPol = /\\?chk=/;
                 if (frPol.test(curPol)) curPol = curPol.replace(/.*\\?chk=/, "");
                 else curPol = "";

                 document.fchcond.idcond.value = curPol;
                 document.getElementById('chcondition').style.display = 'block';
              }
              else if (selcur['vOption'] !== "status") {
                 if (selcur['vOption'] === "proxy-arp" || selcur['vOption'] === "default" || selcur['vOption'] === "optional-mppe" || selcur['vOption'] === "l2tp") jQuery("#fwVpnGrid").jqGrid('setColProp','vValue',{edittype:'checkbox',editoptions:{value:"Yes:No"}});
                 else {
                    if (selcur['vOption'] === "default-psk") selcur['vValue'] = "auto";
                    if (selcur['vOption'] === "peerkey") jQuery("#fwVpnGrid").jqGrid('setColProp','vValue',{edittype:'select', editoptions:{value:"psk:psk;cert:cert"}});
                    else jQuery("#fwVpnGrid").jqGrid('setColProp','vValue',{edittype:'text', editoptions:{value:selcur['vValue']}});
                 }
                 editRow(jQuery("#fwVpnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "vpnserver");
                 newRow = updnewRow();
              }
           },
           groupingView : {
              groupField : ['Group'],
              groupColumnShow : [false],
              groupCollapse : true,
              groupDataSorted : false,
              groupSorted : false,
              groupText : ['<b><FONT color="Black">{0}</b>  {1}</FONT>']
           },
           gridComplete: function(data, response) {
              rulesGrid=GridComplete(jQuery("#fwVpnGrid"), rulesGrid, rulesCt, saveall, "vpnserver");

              rulesCt++;
              jQuery("#fwVpnGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Servidores";
$msg[1] = "Servers";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#fwVpnGrid").css('font-size', '13px');
        jQuery("#fwVpnGrid").jqGrid('navGrid',"#pfwVpnGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Edit button
        \$("#fwVpnGrid").jqGrid('navButtonAdd','#pfwVpnGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#fwVpnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "vpnserver");
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
           saveAll(jQuery("#fwVpnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "vpnserver", "/admin/getvpnserver.json", "/admin/chvpnserver.cgi");
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

    $msg[0] = "VPN: Servidores (Road Warrior)!";
    $msg[1] = "VPN: Server (Road Warrior)!";
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
   print FILE "<FORM name='fivpn' action='/admin/chvpnserver.cgi' method='POST'>";
   print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
   print FILE "<tbody><TR valign=\"bottom\"><TD>";
   print FILE "<font size=\"-1\"><p>";
   $msg[0] = "Alterar";
   $msg[1] = "Change";
   print FILE "<i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"mvPol\" name=\"CkMvPol\"></FONT></p>\n";
   print FILE << "HTMLCODE";
   <table id="fwVpnGrid" width="100%" style="font-size:12px;"></table>
   <div id="pfwVpnGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
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
   $msg[0] = "Recarregar";
   $msg[1] = "Reload";
   print FILE " &nbsp; <a href=\"#\" id=\"btrel\" class=\"uibt\">$msg[$FW_LANG]</a>";

print FILE << "HTML";
    <form name="fvpn">
    <input type="BUTTON" id="savegd" name="savegd" value="Save" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="delgd" name="delgd" value="Delete" style="visibility:hidden; position:absolute;" />
    </form></DIV></body>
    </html>
HTML
  close(FILE);

  return get_file("text/html", $htmlfile);
}

return 1
