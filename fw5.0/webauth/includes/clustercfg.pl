#!/usr/bin/perl

#Rev.1 - Version 5.0

# "POST /admin/chcluster.cgi" -> save or reload button
sub chcluster {
    my $s = shift;
    my $cltype = shift;

    my $rlfw = 0;
    my $canSync = 0;
    my $txtvalue = "NO";
    read_fwcfg;
    read_cluster;

    my $res = HTTP::Response->new();

    $rlfw = 1 if ($s =~ /ReloadFw/);

    if ($rlfw == 0) {
       # Parsing json response (sorting by ID)
       my %json = ();
       my $group = "";
       $txtvalue = "NO";

       foreach my $auxjson (split /"[0-9]+":/, $s) {
          $auxjson =~ s/\[//g;
          $auxjson =~ s/\]//g;
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
                if ($dvalue[1] && $dvalue[0] && $dvalue[1] !~ / & | && |;|\|/) {
                   if ($cltype eq "base") {
                      if ($dvalue[0] =~ /^(cluster_(id|prio)|member_pass|gluster_(server|group)|mac_type)$/) {
                         $clrules{$dvalue[0]} = $dvalue[1];
                      }
                      elsif($dvalue[0] =~ /^(self_member|preempt|sync_state|active_active)$/) {
                         $dvalue[1] = "no" if ($dvalue[1] =~ /^((n|N)o|false)$/);
                         $dvalue[1] = "yes" if ($dvalue[1] =~ /^((y|Y)es|true)$/);
                         $clrules{$dvalue[0]} = $dvalue[1];
                      }
                   }
                   elsif ($dvalue[1] ne "none") {
                      my $auxvalue = str_conv($dvalue[1]);
                      if ($dvalue[0] =~ /^(Src|Dst)$/) {
                         $json{$dvalue[0]} = pack( 'A45', $auxvalue);
                      }
                      elsif ($dvalue[0] =~ /^(clType|clState|clVId|ifInt|clPass)$/) {
                         if ($dvalue[0] eq "ifInt") {
                            $json{$dvalue[0]} = pack( 'A16', $auxvalue);
                         }
                         else {
                            $json{$dvalue[0]} = pack( 'A16', $dvalue[1]);
                         }
                      }
                      elsif ($dvalue[0] =~ /^(clAdv|clPrio)$/) {
                         $json{$dvalue[0]} = pack( 'A5', $dvalue[1]);
                      }
                      elsif ($dvalue[0] =~ /^(Group|Control|Cond|id)$/) {
                         $json{$dvalue[0]} = $dvalue[1];
                      }
                      else {
                         $json{$dvalue[0]} = $auxvalue if ($dvalue[1] !~ /^[\s]*$/);
                      }
                   }
                }
             }

             if ($json{'Group'} ne "" && $json{'ifInt'} ne "") {
                ## Cluster grid rules
                $canSync = 1;
                if ($json{'Group'} eq "interface") {
                   $auxentry = "$json{'clType'} $json{'ifInt'} $json{'Src'} $json{'Dst'}\t";
                }
                elsif ($json{'Group'} eq "vipconf") {
                   $auxentry = "$json{'clState'} $json{'clVId'} $json{'ifInt'} $json{'clAdv'} $json{'clPrio'} $json{'clPass'}\t";
                } 
                elsif ($json{'Group'} eq "vipaddr") {
                   $auxentry = "$json{'ifInt'} $json{'clVId'} $json{'Dst'}\t";
                }

                $auxentry = "$auxentry chk=$json{'Cond'}" if ($json{'Cond'});
                $auxentry = "$auxentry desc=\"$json{'Desc'}\"" if (length($json{'Desc'}) > 1);
                push(@sortedId, $auxentry);
             }
             $canSync = 1 if ($cltype eq "base");
          }
       }

       if ($canSync == 1) {
          open FILE, ">$FW_DIR/cluster/cluster.conf";

          # Writing cluster comments
          foreach my $fRules (@clcomments) {
              $fRules =~ s/\n//;
              $fRules =~ s/\\"/\"/g;
              $fRules =~ s/\\'/\'/g;
              print FILE "$fRules\n" if ($fRules);
          }

          # Writing the main cluster settings
          print FILE "\ncluster_id       $clrules{'cluster_id'} $clrules{'cluster_prio'}\n";
          print FILE "member_pass      $clrules{'member_pass'}\n\n";

          $clrules{'gluster_server'} = "none" if (not $clrules{'gluster_server'} || $clrules{'gluster_server'} eq "");
          $clrules{'gluster_server'} = "any" if ($clrules{'gluster_server'} eq "127.0.0.1" || $clrules{'gluster_server'} eq "self");
          print FILE "gluster_server   $clrules{'gluster_server'}\n";
          print FILE "gluster_group    $clrules{'gluster_group'}\n\n";

          print FILE "self_member      $clrules{'self_member'}\n\n";

          if ($clrules{'active_active'} eq "yes") {
             $clrules{'mac_type'} = "default";
             $clrules{'sync_state'} = "yes";
          }
          print FILE "mac_type         $clrules{'mac_type'}\n";
          print FILE "preempt          $clrules{'preempt'}\n";
          print FILE "sync_state       $clrules{'sync_state'}\n";
          print FILE "active_active    $clrules{'active_active'}\n\n";

          # Writing the grid cluster rules (set-interface, set-vipconf adn set-vipaddr)
          foreach my $fRules (@clgroup) {
             my $bkRules = $fRules;
             $fRules =~ s/\?chk=.*//;
             my $setPol = $bkRules;
             $setPol =~ s/\?chk=/ chk=/;
             print FILE "\nset-$setPol";
             if ($cltype eq $fRules) {
                foreach my $aRules (@sortedId) {
                   $aRules =~ s/\n//;
                   $aRules =~ s/\\"/\"/g;
                   $aRules =~ s/\\'/\'/g;
                   print FILE "\n$aRules";
                }
             }
             else {
               foreach my $aRules (@{$clrules{"$bkRules"}}) {
                  $aRules =~ s/\n//;
                  $aRules =~ s/\\"/\"/g;
                  $aRules =~ s/\\'/\'/g;
                  print FILE "\n$aRules";
               }
             }
             print FILE "\n";
          }
          $txtvalue="OK";
          close(FILE);
       }
    }
    else {
       $msg[0] = "Aplicando as configurações do cluster!";
       $msg[1] = "Applying cluster configurations!";
       $msg2[0] = "<font size=\'2\'>Recarregando todas as regras...</font>";
       $msg2[1] = "<font size=\'2\'>Full reloading...</font>";
       $txtvalue = msgbox("info", "$msg[$FW_LANG]", "<font size=\'2\'>$msg2[$FW_LANG]</font>");
       system("$FW_DIR/fwguardian --ignore-webserver 1>&2 2>/dev/null &");
       system("$FW_DIR/fwguardian --configure-cluster 1>&2 2>/dev/null");
       sleep 1;
       system("$FW_DIR/fwguardian 1>&2 2>/dev/null");

       my $url = "/admin/clustercfg.cgi";
       $url = "/admin/clustervip.cgi" if ($cltype eq "vipconf");
       $url = "/admin/clustervipad.cgi" if ($cltype eq "vipaddr");
       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"2;URL=$url\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}


# "Make web page clustercfg.html"
sub get_clustercfg {
    my $htmlfile="$HTMLDIR/admin/dynhttp/clustercfg.html";
    my $url = shift;
    my $cltype = shift;

    my $clid = "clusterint";
    my $clget = "", $clsave = "";
    my $clsrc = "Src", $cldst = "Dst";
    my $lensrc = 120, $lendst = 120;
    my $gridlen = 120;
    if ($cltype eq "interface") {
       $clid = "clusterint";
       $clget = "/admin/getclusterinter.json";
       $clsave = "/admin/chclusterinter.cgi";
    }
    elsif ($cltype =~ /^clustervip/) {
       if ($cltype eq "clustervip") {
          $clsrc = "clVId";
          $cldst = "clPass";
          $lendst = 220;
          $clid = "clustervip";
          $clget = "/admin/getclustervip.json";
          $clsave = "/admin/chclustervip.cgi";
          $htmlfile="$HTMLDIR/admin/dynhttp/clustervip.html";
       }
       elsif ($cltype eq "clustervipad") {
          $clsrc = "clVId";
          $lendst = 360;
          $clid = "clustervipad";
          $clget = "/admin/getclustervipad.json";
          $clsave = "/admin/chclustervipad.cgi";
          $htmlfile="$HTMLDIR/admin/dynhttp/clustervipad.html";
       }
       $lensrc = 80;
       $gridlen = 80;

       $clvipid = `grep "^\\s*\\(master\\|backup\\)" $FW_DIR/cluster/cluster.conf | awk '{print \$2\":\"\$2\";\"; }' | sort | uniq | tr -d '\n'`;
       $clvipid =~ s/;$//;
    }

    read_fwcfg;
    read_cluster;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    ### Making clustercfg.html
    open FILE, ">$htmlfile";

print FILE << "javascript";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />

  <link href="/css/csstab.css" type="text/css" rel="stylesheet" />
  <link href="/css/ui.jqgrid.css" type="text/css" rel="stylesheet" />
  <link href="/css/jquery-ui.css" type="text/css" rel="stylesheet" />
  <link href="/css/multi-select.css" type="text/css" media="screen" rel="stylesheet" />
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
    .select2-search { font-size:small; }
    .select2-search input { background-color: #A4A4A4; font-size:small; }
    .select2-results { font-size:small; }

  </style>

  <script type="text/javascript" src="/js/jquery-1.7.2.min.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.core.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.widget.js"></script>
  <script type="text/javascript" src="/js/jquery.ui.button.js"></script>
  <script type="text/javascript" src="/js/jquery.multi-select.js"></script>
  <script type="text/javascript" src="/js/select2.min.js"></script>
  <script type="text/javascript" src="/js/i18n/grid.locale-en.js"></script>
  <script type="text/javascript" src="/js/i18n/grid.locale-pt-br.js"></script>
  <script type="text/javascript" src="/js/i18n/select2_locale_en.js.template"></script>
  <script type="text/javascript" src="/js/i18n/select2_locale_pt-BR.js"></script>
  <script type="text/javascript" src="/js/jquery.jqGrid.min.js"></script>
  <script type="text/javascript" src="/admin/js/gridctl.js"></script>
  <script type="text/javascript">
        jQuery.jgrid.no_legacy_api = true;
        jQuery.jgrid.useJSON = true;

        \$(function() {
           \$(".uibt" ).button();
           \$(".uibt_em" ).button();
javascript
if ($cltype eq "interface") {
print FILE << "javascript";
           \$("#btsav1").click(function() {
                 document.fCluster.savegd1.click();
                 return false;
           });
           \$("#btcan1").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btrel1").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.fiCluster1.ReloadFw.click();
                 return false;
           });

           \$("#cPrio").select2();
           \$("#cMacType").select2();

javascript
}
print FILE << "javascript";
           \$("#btsav2").click(function() {
                 document.fCluster.savegd2.click();
                 return false;
           });
           \$("#btcan2").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btrel2").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.fiCluster2.ReloadFw.click();
                 return false;
           });
           \$("#btdel").click(function() {
                 document.fCluster.delgd.click();
                 return false;
           });

           \$( "input[type=button]" ).button().css('font-size', '12px');
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
        jQuery("#fwClusterGrid1").jqGrid({
           url:'$clget',
           datatype: "json",
           height: \$(window).height() - 300,
           width: \$(window).width() - $gridlen,
javascript
if ($FW_LANG == 0) {
    if ($cltype eq "interface") {
       print FILE "           colNames:['ID', 'Politica', 'Tipo', 'Interface', 'End. origem', 'End. alvo (dst)', 'Condição', 'Descrição', 'Control' ],\n";
    }
    elsif ($cltype eq "clustervip") {
       print FILE "           colNames:['ID', 'Politica', 'Estado', 'ID Virtual', 'Interface', 'Int. anúncio', 'Prio', 'Senha', 'Condição', 'Descrição', 'Control' ],\n";
    }
    elsif ($cltype eq "clustervipad") {
       print FILE "           colNames:['ID', 'Politica', 'Interface', 'ID Virtual', 'Endereço IP', 'Condição', 'Descrição', 'Control' ],\n";
    }
}
else {
    if ($cltype eq "interface") {
       print FILE "           colNames:['ID', 'Policy', 'Type', 'Interface', 'Source Addr', 'Target addr (dst)', 'Condition', 'Description', 'Control' ],\n";
    }
    elsif ($cltype eq "clustervip") {
       print FILE "           colNames:['ID', 'Policy', 'State', 'ID Virtual', 'Interface', 'Advert int', 'Prio', 'Password', 'Condition', 'Description', 'Control' ],\n";
    }
    elsif ($cltype eq "clustervipad") {
       print FILE "           colNames:['ID', 'Policy', 'Interface', 'Virtual ID', 'IP address', 'Condition', 'Description', 'Control' ],\n";
    }
}
print FILE << "javascript";
           colModel: [
              { name:"id",    index:'id', sortable:false, width: 30, sorttype: "int", key: true },
              { name:"Group", index:'Group', hidden:true,  width:30 },
javascript
print FILE "              { name:\"clType\", index:'clType', sortable:false, editable:true, edittype:'select', editoptions:{value:\"heartbeat:heartbeat;defaultgw:defaultgw;monitor:monitor;set_maddr:set_maddr\"}, width:86 }," if ($cltype eq "interface");

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

my $edtype = "edittype:'text'";
$edtype = "edittype:'select', editoptions:{value:\"$clvipid\"}" if ($cltype eq "clustervipad" || $cltype eq "clustervip");
if ($cltype eq "clustervip") {
print FILE << "javascript";
              { name:"clState", index:'clState', sortable:false, editable:true, edittype:'select', editoptions:{value:"master:master;backup:backup"}, width:74 },
              { name:"$clsrc", index:'$clsrc', sortable:false, editable:true, $edtype, width:$lensrc },
              { name:"ifInt", index:'ifInt', sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:74 },
              { name:"clAdv", index:'clAdv', sortable:false, editable:true, width:80 },
              { name:"clPrio", index:'clPrio', sortable:false, editable:true, width:80 },
              { name:"$cldst", index:'$cldst', sortable:false, editable:true, width:$lendst },
javascript
}
else {
print FILE << "javascript";
              { name:"ifInt", index:'ifInt', sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:74 },
              { name:"$clsrc", index:'$clsrc', sortable:false, editable:true, $edtype, width:$lensrc },
              { name:"$cldst", index:'$cldst', sortable:false, editable:true, width:$lendst },
javascript
}
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
           pager: '#pfwClusterGrid1',
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
              editRow(jQuery("#fwClusterGrid1"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "$clid");
              newRow = updnewRow();
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
              rulesGrid=GridComplete(jQuery("#fwClusterGrid1"), rulesGrid, rulesCt, saveall, "$clid");

              rulesCt++;
              jQuery("#fwClusterGrid1").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
if ($cltype eq "interface") {
   $msg[0] = "Configuração de interface";
   $msg[1] = "Interface settings";
}
elsif ($cltype eq "clustervip") {
   $msg[0] = "Configuração VRRP";
   $msg[1] = "VRRP settings";
}
elsif ($cltype eq "clustervipad") {
   $msg[0] = "Configuração de endereço VIP";
   $msg[1] = "VIP address settings";
}
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#fwClusterGrid1").css('font-size', '13px');
        jQuery("#fwClusterGrid1").jqGrid('navGrid',"#pfwClusterGrid1",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#fwClusterGrid1"), rulesGrid, newRow, "$medited[$FW_LANG]", "$clid");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#fwClusterGrid1"), rulesGrid, newRow, "$medited[$FW_LANG]", "$clid");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Edit button
        \$("#fwClusterGrid1").jqGrid('navButtonAdd','#pfwClusterGrid1',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#fwClusterGrid1"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "$clid");
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
           rulesGrid = delRow(jQuery("#fwClusterGrid1"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
        });

        // Add button
        \$("#fwClusterGrid1").jqGrid('navButtonAdd','#pfwClusterGrid1',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = addRow(jQuery("#fwClusterGrid1"), rulesGrid, newRow, "$medited[$FW_LANG]", "$clid", "", "");
             newRow = updnewRow();
           }
        });

        // Saving all rows in click event
        jQuery("#savegd2").click( function() {
javascript
$msg[0] = "INFO: Definições atualizadas com sucesso!";
$msg[1] = "INFO: Settings updated successfully!";
print FILE << "javascript";
           saveall = 1;
           saveAll(jQuery("#fwClusterGrid1"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "$clid", "$clget", "$clsave");
           newRow = updnewRow();
           if (newRow.length < 1) rulesCt = 0;
        });

        // Grid resize
        \$(window).bind('resize', function() {
            \$("#jqgrid").setGridWidth(\$(window).width() - 120);
        }).trigger('resize');

    });

  </script>

<script type="text/javascript">
<!--

  function jstype(cktype, value) {
    if (cktype == "cId") this.cluster_id = value;
    else if (cktype == "cPrio") this.cluster_prio = value;
    else if (cktype == "cPass") this.member_pass = value;
    else if (cktype == "ckSelfMb") this.self_member = value;
    else if (cktype == "cglSvr") this.gluster_server = value;
    else if (cktype == "cglGpName") this.gluster_group = value;
    else if (cktype == "cMacType") this.mac_type = value;
    else if (cktype == "ckPree") this.preempt = value;
    else if (cktype == "ckSyncSt") this.sync_state = value;
    else if (cktype == "ckAct") this.active_active = value;
  }

  function saveCluster() {
    var docData = new Array();

    docData.push(new jstype('cId', encodeHtml(document.getElementById('cId').value)));
    docData.push(new jstype('cPrio', document.getElementById('cPrio').value));
    docData.push(new jstype('cPass', encodeHtml(document.getElementById('cPass').value)));
    docData.push(new jstype('ckSelfMb', document.getElementById('ckSelfMb').checked));
    docData.push(new jstype('cglSvr', encodeHtml(document.getElementById('cglSvr').value)));
    docData.push(new jstype('cglGpName', encodeHtml(document.getElementById('cglGpName').value)));
    docData.push(new jstype('cMacType', encodeHtml(document.getElementById('cMacType').value)));
    docData.push(new jstype('ckPree', document.getElementById('ckPree').checked));
    docData.push(new jstype('ckSyncSt', document.getElementById('ckSyncSt').checked));
    docData.push(new jstype('ckAct', document.getElementById('ckAct').checked));

    // POST ajax
    document.getElementById('chwait').style.display = 'block';
    jQuery.ajax({
        url         : '/admin/chclusterbase.cgi'
        ,type        : 'POST'
        ,cache       : false
        ,data        : JSON.stringify(docData)
        ,contentType : 'application/json; charset=utf-8'
        ,async: false
        ,success: function(data) {
              document.getElementById('chwait').style.display = 'none';
javascript
$msg[0] = "INFO: Definições atualizadas com sucesso!";
$msg[1] = "INFO: Settings updated successfully!";
print FILE "                 alert(\"$msg[$FW_LANG]\");\n";
print FILE << "javascript";
        }
    });
  }

//-->
</script>\n\n

javascript

    $msg[0] = "Configuração do cluster";
    $msg[1] = "Cluster configurations";
    my $mstyle = menustyle("$msg[$FW_LANG]");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' onload="document.getElementById('tab_stats').style.display='block';" $STYLE>
  <span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG]</span>

  <DIV align="center">
HTMLCODE


if ($cltype eq "interface") {
   print FILE << "HTMLCODE";
    <span id="tab_stats" style="display: none;">
      <ul id="tabs">
HTMLCODE
   $msg[0] = "Definições gerais";
   $msg[1] = "General settings";
   print FILE << "HTMLCODE";
        <li><a href="#" name="#tab1">$msg[$FW_LANG]</a></li>
HTMLCODE
   $msg[0] = "Interface";
   $msg[1] = "Interface";
   print FILE << "HTMLCODE";
        <li><a href="#" name="#tab2">$msg[$FW_LANG]</a></li>
      </ul>
HTMLCODE
}

    ## Waiting form
    print FILE "<DIV align=\"center\" valign=\"center\" id=\"chwait\">";
    $msg[0] = "Aguarde... isto pode demorar um pouco!";
    $msg[1] = "Wait... this may take a little time!";
    print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
    print FILE "</DIV>";

if ($cltype eq "interface") {
    ## Main form
    my %ctlist = ();
    print FILE "<div id='content'>";

    print FILE "<div id='tab1'>";
    print FILE "<FORM name='fiCluster1' action='/admin/chclusterbase.cgi' method='POST'>";
    print FILE "<div align='left'>";
    print FILE "<BR /><p valign='center'><span style='Font-Family: Arial, Helvetica;'>Cluster ID / Prio</span> &nbsp; ";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 150px;'>";
    print FILE "<INPUT type='text' id='cId' name='cluster_id' size='15' value=\"$clrules{'cluster_id'}\" style='Font-Family: Arial, Helvetica; height:24px; width:160px;'>";
    print FILE "<SELECT id='cPrio' name='cluster_prio' style='width:80px; font-size:small;'>";
    my $cPrio = $clrules{'cluster_prio'};
    foreach (1..10) {
       my $selip = "";
       $selip = "selected" if ($_ eq $cPrio);
       print FILE "<OPTION value=\"$_\" $selip>$_</OPTION>";
    }
    print FILE "</SELECT></span></p>";
    print FILE "<p valign='center'><span style='Font-Family: Arial, Helvetica;'> Senha</span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 150px;'>";
    print FILE "<INPUT type='password' id='cPass' name='member_pass' size='15' value=\"$clrules{'member_pass'}\" style='Font-Family: Arial, Helvetica; height:24px; width:160px;'></span></p>";
    print FILE "<BR /><hr noshade='true' size='1'><BR />";
    $msg[0] = "Tipo de MAC";
    $msg[1] = "MAC type";
    print FILE "<p valign='center'><span style='Font-Family: Arial, Helvetica;'>$msg[$FW_LANG]</span> &nbsp; ";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 150px;'>";
    print FILE "<SELECT id='cMacType' name='mac_type' style='width:120px; font-size:small;'>";
    if ($clrules{'mac_type'} eq "vmac") {
       $msg[0] = "";
       $msg[1] = "selected";
    }
    else {
       $msg[0] = "selected";
       $msg[1] = "";
    }
    print FILE "<OPTION value=\"default\" $msg[0]>default</OPTION>";
    print FILE "<OPTION value=\"vmac\" $msg[1]>vmac</OPTION>";
    print FILE "</SELECT></span>";
    $msg[0] = "Servidor Glusterfs";
    $msg[1] = "Glusterfs server";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 488px;'>$msg[$FW_LANG]</span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 630px;'>";
    print FILE "<INPUT type='text' id='cglSvr' name='gluster_server' size='15' value=\"$clrules{'gluster_server'}\" style='Font-Family: Arial, Helvetica; height:24px; width:160px;'>";
    print FILE "</span></p>";
    $msg[0] = "Preempção";
    $msg[1] = "Preemption";
    print FILE "<p valign='center'><span style='Font-Family: Arial, Helvetica;'>$msg[$FW_LANG]</span> &nbsp; ";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 150px;'>";
    $msg[0] = "";
    $msg[0] = "checked" if ($clrules{'preempt'} eq "yes");
    print FILE "<INPUT type='checkbox' id='ckPree' name='preempt' size='25' style='Font-Family: Arial, Helvetica;' $msg[0]></span>";
    $msg[0] = "Grupo gluster";
    $msg[1] = "Gluster group";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 488px;'>$msg[$FW_LANG]</span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 630px;'>";
    print FILE "<INPUT type='text' id='cglGpName' name='gluster_group' size='15' value=\"$clrules{'gluster_group'}\" style='Font-Family: Arial, Helvetica; height:24px; width:160px;'>";
    print FILE "</span></p>";
    $msg[0] = "Sync. conexão";
    $msg[1] = "Connection sync";
    print FILE "<p valign='center'><span style='Font-Family: Arial, Helvetica;'>$msg[$FW_LANG]</span> &nbsp; ";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 150px;'>";
    $msg[0] = "";
    $msg[0] = "checked" if ($clrules{'sync_state'} eq "yes");
    print FILE "<INPUT type='checkbox' id='ckSyncSt' name='sync_state' size='25' style='Font-Family: Arial, Helvetica;' $msg[0]></span>";
    print FILE "</p>";
    $msg[0] = "Ativo/Ativo";
    $msg[1] = "Active/Active";
    print FILE "<p valign='center'><span style='Font-Family: Arial, Helvetica;'>$msg[$FW_LANG]</span> &nbsp; ";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 150px;'>";
    $msg[0] = "";
    $msg[0] = "checked" if ($clrules{'active_active'} eq "yes");
    print FILE "<INPUT type='checkbox' id='ckAct' name='active_active' size='25' style='Font-Family: Arial, Helvetica;' $msg[0]></span>";
    $msg[0] = "Membro único";
    $msg[1] = "Single member";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 488px;'><strong>$msg[$FW_LANG]</strong></span>";
    print FILE "<span style='Font-Family: Arial, Helvetica; Position: Absolute; Left: 630px;'>";
    $msg[0] = "";
    $msg[0] = "checked" if ($clrules{'self_member'} eq "yes");
    print FILE "<INPUT type='checkbox' id='ckSelfMb' name='self_member' size='25' style='Font-Family: Arial, Helvetica;' $msg[0]> ";
    print FILE "</span></p>";
    print FILE "</div>";
    print FILE "<INPUT type=\"submit\" name=\"ReloadFw\" value=\"Reload firewall rules\" style=\"visibility:hidden; position:absolute;\">";
    print FILE "</FORM>";
    $msg[0] = "ALERTA: É obrigatória a configuração de uma interface heartbeat!";
    $msg[1] = "WARN: It is mandatory to setup a heartbeat interface!";
    print FILE "<BR /><BR /><BR /><BR /><FONT size='-1' color='Red'><strong> &nbsp; $msg[$FW_LANG]</strong></FONT>";
    print FILE "<BR /><BR /><BR />";
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE "<a href='#' id='btsav1' class='uibt'>$msg[$FW_LANG]</a>";
    $msg[0] = "Cancelar";
    $msg[1] = "Cancel";
    print FILE " <a href='#' id='btcan1' class='uibt_em'>$msg[$FW_LANG]</a>";
    $msg[0] = "Aplicar";
    $msg[1] = "Apply";
    print FILE " &nbsp; <a href='#' id='btrel1' class='uibt'>$msg[$FW_LANG]</a>";
    print FILE "</div>";

    print FILE "<div id='tab2'>";
}
elsif ($cltype eq "clustervip" || $cltype eq "clustervipad") {
   print FILE "<DIV align=\"left\"><i>";
   print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 20px;\">";
   if ($cltype eq "clustervip") {
      if ($FW_LANG == 0) {
         print FILE "1. Configure o estado padrão por ID virtual (master ou backup).<BR />";
         print FILE "2. É *possível* configurar um único ID virtual e distribuir os IPs em diferentes interfaces.<BR />";
      }
      else {
         print FILE "1. Set the default state for virtual ID (master or backup).<BR />";
         print FILE "2. You *can* configure only one virtual ID and distribute IPs on different interfaces.<BR />";
      }
   }
   else {
      if ($FW_LANG == 0) {
         print FILE "1. Selecione o ID virtual de acordo com a configuração VRRP.<BR />";
         print FILE "2. Para multiplos IPs em uma mesma linha utilize ',' como separador.<BR />";
      }
      else {
         print FILE "1. Select the virtual ID according to the VRRP configuration.<BR />";
         print FILE "2. For multiple IPs on the same line, use ',' as separator.<BR />";
      }
   }
   print FILE "</span></i></DIV><BR />";
}

    ## Grid rules
    print FILE "<FORM name='fiCluster2' action='$clsave' method='POST'>";
    print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
    print FILE "<tbody><TR valign=\"bottom\"><TD width=\"96%\">";
    print FILE << "HTMLCODE";
   <table id="fwClusterGrid1" width="100%" style="font-size:12px;"></table>
   <div id="pfwClusterGrid1" width="100%" style="font-size:12px;"></div>
HTMLCODE
    print FILE "</TD><TD width=\"4%\" align=\"left\">";
    print FILE "&nbsp;<a href=\"javascript: document.fCluster.gdmoveup.click();\">";
    print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "&nbsp;<a href=\"javascript: document.fCluster.gdmovedown.click();\">";
    print FILE "<img src=\"buttons/mv_down.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "</TD></TR></tbody></table>";
    print FILE "<INPUT type=\"submit\" name=\"ReloadFw\" value=\"Reload firewall rules\" style=\"visibility:hidden; position:absolute;\">";
    print FILE "</FORM><BR />";
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE "<a href='#' id='btsav2' class='uibt'>$msg[$FW_LANG]</a>";
    $msg[0] = "Cancelar";
    $msg[1] = "Cancel";
    print FILE " &nbsp; <a href='#' id='btcan2' class='uibt_em'>$msg[$FW_LANG]</a>";
    $msg[0] = "Apagar";
    $msg[1] = "Delete";
    print FILE " <a href=\"#\" id=\"btdel\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
    $msg[0] = "Aplicar";
    $msg[1] = "Apply";
    print FILE " &nbsp; <a href='#' id='btrel2' class='uibt'>$msg[$FW_LANG]</a>";

    print FILE "</div>" if ($cltype eq "interface");

print FILE << "HTML";
    <FORM name="fCluster">
    <input type="BUTTON" id="gdUp" name="gdmoveup" value="Up" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="gdDown" name="gdmovedown" value="Down" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="savegd1" name="savegd1" value="Save" onclick="return saveCluster();" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="savegd2" name="savegd2" value="Save" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="delgd" name="delgd" value="Delete" style="visibility:hidden; position:absolute;" />
    </FORM></span></DIV>

HTML
   print FILE " <script type=\"text/javascript\" src=\"/js/csstab.js\"></script>" if ($cltype eq "interface");
   print FILE " </body></html>";
   close(FILE);

   return get_file("text/html", $htmlfile);
}

return 1;

