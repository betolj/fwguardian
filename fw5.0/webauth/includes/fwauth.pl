#!/usr/bin/perl

#Rev.1 - Version 5.0

# "show users" in select box (max: 8000)
sub getauthuser {
    my $ctuser = 0;
    print FILE "<OPTION value=\"def_pos\">default posix</OPTION>";
    print FILE "<OPTION value=\"def_sql\">default sql</OPTION>";

    ### Getting SQL accounts
    if ($sqlweb{'web_user'}) {
      my $sql_ok = 1;
      my $dbh = sqladm("connect") or $sql_ok = 0;
      if ($sql_ok == 1 && $dbh != -1) {
        if ($dbh) {
           my $SQL = "select fg_username from fgaccount";
           my $sth = $dbh->prepare("$SQL");
           $sth->execute or $sql_ok = 0;

           if ($sql_ok == 1) {
              while(@row = $sth->fetchrow_array()) {
                print FILE "<OPTION value=\"$row[0]\">$row[0]</OPTION>" if ($ctuser <= 8000);
                $ctuser++;
              }
           }
        }
        $dbh->disconnect;
      }
    }

    ### Getting Posix accounts
    if ($ctuser < 8000) {
       foreach (`getent passwd | sed \'s/\:/ /g\' | sort -nk 3 | awk \'{ if (\$3 >= 500) print \$1; }\'`) {
          $_ =~ s/\n//;
          if ($_ !~ /^(nobody|fwguardian)$/) {
             print FILE "<OPTION value=\"$_\">$_</OPTION>" if ($ctuser <= 8000);
             $ctuser++;
          }
       }
    }
}

# "POST /admin/chauthmapps.cgi" -> delete or add button
sub chauthmapps {
    my $s = shift;
    my $authtype = shift;

    my $rlfw = 0;
    my $canSync = 0;
    my $saveall = 0;
    my $txtvalue = "";
    my @msg = ("", ""), @msg2 = ("", "");
    my $res = HTTP::Response->new();
    read_fwrules("route");

    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && $canch == 1) {

       # Parsing json response (sorting by ID)
       my %json = ();
       my %gpName = ();
       my %groupData = ();
       my $group = "";
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
                   if ($auxvalue && ($auxvalue ne "0" && $auxvalue ne "none")) {
                      if ($authtype eq "authmaps") {
                         if ($dvalue[0] eq "aMapType") {
                            $json{$dvalue[0]} = pack( 'A20', $auxvalue);
                         }
                         elsif ($dvalue[0] =~ /^(Src|Dst)$/) {
                            $json{$dvalue[0]} = pack( 'A35', $auxvalue);
                         }
                         else {
                            $json{$dvalue[0]} = $auxvalue;
                         }
                      }
                      else {
                         if ($dvalue[0] eq "aDir") {
                            $json{$dvalue[0]} = pack( 'A20', $auxvalue);
                         }
                         elsif ($dvalue[0] =~ /^(aIf|Dst)$/) {
                            $json{$dvalue[0]} = pack( 'A35', $auxvalue);
                         }
                         elsif ($dvalue[0] eq "ckValue") {
                            $json{$dvalue[0]} = "";
                            $json{$dvalue[0]} = "bypass" if ($dvalue[1] eq "Yes"); 
                         }
                         else {
                            $json{$dvalue[0]} = $auxvalue;
                         }
                      }
                   }
                }
             }

             if ($json{'Group'} =~ /^$authtype($|\?chk=)/ && $json{'Dst'} ne "" && ($json{'Src'} || $json{'aIf'})) {
                # FORWARD rule
                $canSync = 1;
                if ($authtype eq "authmaps") {
                   $auxentry = "$json{'aMapType'} $json{'Src'} $json{'Dst'}";
                }
                else {
                   $auxentry = "$json{'aDir'} $json{'aIf'} $json{'Dst'}";
                   $auxentry = "$auxentry $json{'ckValue'}" if ($json{'ckValue'});
                }
                $auxentry = "$auxentry \tchk=$json{'Cond'}" if ($json{'Cond'});
                $auxentry = "$auxentry desc=\"$json{'Desc'}\"" if (length($json{'Desc'}) > 1);

                # Policy rules
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
          open FILE, ">$file_cfg{'routing/fwroute.rules'}";

          # Writing FORWARDED comments
          foreach my $fRules (@routecomments) {
              $fRules =~ s/\n//;
              $fRules =~ s/\\"/\"/g;
              $fRules =~ s/\\'/\'/g;
              print FILE "$fRules\n" if ($fRules);
          }

          # Writing FORWARDED set-policy rules
          my $curPol = "";
          my $lastpolicy = "";
          foreach my $fRules (@routefw, @gpauthfw) {
              $fRules =~ s/\n//;
              $fRules =~ s/\\"/\"/g;
              $fRules =~ s/\\'/\'/g;
              my ($auxPol, $auxRules) = split(/[\s]+/, $fRules, 2);

              $curPol = $auxPol;
              print FILE "\nset-policy $auxPol\n" if ($curPol ne $lastpolicy);
              print FILE "$auxRules\n";
              $lastpolicy = $curPol;
          }

          # Writing auth rules
          foreach my $fRules (@gpset) {
             my $bkRules = $fRules;
             $fRules =~ s/\?chk=.*//;
             my $setPol = $bkRules;
             $setPol =~ s/\?chk=/ chk=/;
             $setPol = $gpName{$fRules} if ($gpName{$fRules} && $groupData{"$fRules"}[0]);
             print FILE "\nset-auth $setPol";
             if ($groupData{"$fRules"}[0]) {
                foreach my $aRules (@{$groupData{"$fRules"}}) {
                   $aRules =~ s/\n//;
                   $aRules =~ s/\\"/\"/g;
                   $aRules =~ s/\\'/\'/g;
                   print FILE "\n$aRules";
                }
             }
             else {
                foreach my $aRules (@{$gpauthrule{"$bkRules"}}) {
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

          rsyncupdate("$file_cfg{'routing/fwroute.rules'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
    }
    else {
       my $rtime = 2;
       if ($canch == 1) {
          $msg[0] = "Aplicando as regras de firewall!";
          $msg[1] = "Applying firewall rules!";
          $msg2[0] = "Com";
          $msg2[1] = "With";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "<font size=\'2\'>$msg2[$FW_LANG] --reload-rules</font>");
          system("$FW_DIR/fwguardian --reload-rules 1>&2 2>/dev/null &");

          rsyncupdate("$file_cfg{'routing/fwroute.rules'}", "rules", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       }
       else {
          $rtime = 0;
       }
       my $murl = "/admin/authmapps.cgi";
       $murl = "/admin/authnets.cgi" if ($authtype eq "networks");

       my $meta = "<META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=$murl\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">";
       $txtvalue = "<html><head>$meta</head><body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page authmapps.html"
sub get_authmapps {
    my $htmlfile="$HTMLDIR/admin/dynhttp/authmapps.html";
    read_fwrules("route");

    my @msg = ("", "");

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making fwauth.html
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
                 document.fauth.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 document.fauth.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.fiauth.ReloadFw.click();
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
        jQuery("#fwAuthGrid").jqGrid({
           url:'/admin/getauthmapps.json',
           datatype: "json",
           height: \$(window).height() - 270,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
    print FILE "           colNames:['ID', 'Politica', 'Tipo', 'Usuários/Política', 'Mapear para', 'Condição', 'Descrição', 'Control' ],\n";
}
else {
    print FILE "           colNames:['ID', 'Policy', 'Type', 'Users/Policy', 'Map to', 'Condition', 'Description', 'Control' ],\n";
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

    ### Getting auth policies
    my $cpol = 0;
    foreach (@gpauthfwtab) {
       $_ =~ s/\n//;
       $_ =~ s/^[ |\t]*set-policy[ |\t]+auth://;
       my $line = "$_:$_";
       if ($cpol gt 0) {
          $msg[0] = "$msg[0];$line";
       }
       else { $msg[0] = "$line"; }
       $cpol++;
    }

    my $aalias = $msg[0];

print FILE << "javascript";
              { name:"aMapType", index:'aMapType', sortable:false, editable:true, edittype:'select', editoptions:{value:"mapuser:mapuser;mappolicy:mappolicy;mapuserip:mapuserip"}, width:120 },
              { name:"Src",  index:'Src', sortable:false, editable:true, width:210 },
              { name:"Dst",  index:'Dst', sortable:false, editable:true, width:210 },
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
           pager: '#pfwAuthGrid',
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
             if (document.getElementById('mvPol').checked == true || document.getElementById('mvUsr').checked == true) {
                 var selcur = jQuery("#fwAuthGrid").jqGrid('getRowData', selid);
                 if (document.getElementById('mvPol').checked == true) {
                    var curPol = selcur['Group'];
                    var frPol = /\\?chk=/;
                    if (frPol.test(curPol)) curPol = curPol.replace(/.*\\?chk=/, "");
                    else curPol = "";

                    document.fchcond.idcond.value = curPol;
                    document.getElementById('chcondition').style.display = 'block';
                 }
                 else {
                    if (selid > 0 && (selcur['aMapType'] === "mapuser" || selcur['aMapType'] === "mapuserip")) document.getElementById('chusers').style.display = 'block';
javascript
$msg[0] = "A seleção de usuários não é permitida em *mappolicy*!";
$msg[1] = "The user selection is not allowed on *mappolicy*!";
print FILE << "javascript";
                    else alert("$msg[$FW_LANG]");
                 }
              }
              else {
                 editRow(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$aalias", "authmapps");
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
              rulesGrid=GridComplete(jQuery("#fwAuthGrid"), rulesGrid, rulesCt, saveall, "authmapps");

              rulesCt++;
              jQuery("#fwAuthGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Mapeamentos";
$msg[1] = "Mappings";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#fwAuthGrid").css('font-size', '13px');
        jQuery("#fwAuthGrid").jqGrid('navGrid',"#pfwAuthGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "authmapps");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "authmapps");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Edit button
        \$("#fwAuthGrid").jqGrid('navButtonAdd','#pfwAuthGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$aalias", "authmapps");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#fwAuthGrid").jqGrid('navButtonAdd','#pfwAuthGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
$msg[0] = "Por favor... selecione a linha a ser removida!";
$msg[1] = "Please... Select the line to delete!";
print FILE << "javascript";
           onClickButton:function(){
             var gridrules = jQuery("#fwAuthGrid").jqGrid('getDataIDs').length;
             if (gridrules > 0) {
                var clret = jQuery("#fwAuthGrid").jqGrid('getRowData', gridrules);
                rulesGrid = cloneRow(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "authmapps", clret['Group']);
                newRow = updnewRow();
             }
           }
        });

        // Delete row in click event
        jQuery("#delgd").click( function() {
           rulesCt = 1;
           rulesGrid = delRow(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
        });

        // Add button
        \$("#fwAuthGrid").jqGrid('navButtonAdd','#pfwAuthGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             var defGroup = "authmaps";
             var gridrules = jQuery("#fwAuthGrid").jqGrid('getDataIDs').length;
             if (gridrules > 0) {
                var clret = jQuery("#fwAuthGrid").jqGrid('getRowData', gridrules);
                defGroup = clret['Group'];
             }

             rulesGrid = addRow(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "authmapps", defGroup, "$aalias");
             newRow = updnewRow();
           }
        });

        // Change Policy condition
        jQuery("#chCond").click( function() {
           var selid = \$("#fwAuthGrid").jqGrid('getGridParam','selrow');
           chGroupCond(jQuery("#fwAuthGrid"), rulesGrid, document.fchcond.idcond.value);
        });

        // Change User
        jQuery("#chUser").click( function() {
           var selid = \$("#fwAuthGrid").jqGrid('getGridParam','selrow');
           if (selid > 0) {
              var i=0;
              var SelUser="";
              for (var j=0; j < document.getElementById('seluserid').length; j++) {
                  if (document.getElementById('seluserid')[j].selected) {
                     if (i < 1) SelUser = document.getElementById('seluserid')[j].value
                     else SelUser = SelUser + "," + document.getElementById('seluserid')[j].value;
                     i++;
                  }
              }
              if (SelUser !== "") {
                 rulesGrid[selid-1]['Src'] = SelUser;
                 refreshGroup(jQuery("#fwAuthGrid"), rulesGrid, rulesGrid.length, selid);
                 setPos(jQuery("#fwAuthGrid"), selid, 1);
              }
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
           saveAll(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "authmapps", "/admin/getauthmapps.json", "/admin/chauthmapps.cgi");
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

    $msg[0] = "Captive portal: Mapear política!";
    $msg[1] = "Captive portal: Policy Mapping!";
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
   print FILE "<DIV align=\"center\" valign=\"center\" id=\"chcondition\" class=\"chsform\">";
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

   ## User form
   print FILE "<DIV align=\"center\" valign=\"center\" id=\"chusers\" class=\"chsform\" style=\"height: 160px\">";
   print FILE "<form name=\"fchuser\">";
   $msg[0] = "Selecione um usuário";
   $msg[1] = "User select";
   print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
   print FILE "<SELECT id=\"seluserid\" name=\"seluser\" style=\"Font-Family: Arial, Helvetica; width:80%\" size=\"6\" multiple>";
   getauthuser;
   print FILE "</SELECT><BR />";
   $msg[0] = "Aplica";
   $msg[1] = "Apply";
   print FILE " <INPUT type=\"button\" id=\"chUser\" value=\"$msg[$FW_LANG]\">";
   $msg[0] = "Cancela";
   $msg[1] = "Cancel";
   print FILE "<INPUT type=\"button\" value=\"$msg[$FW_LANG]\" onclick=\"return document.getElementById('chusers').style.display = 'none';\">";
   print FILE "</form></DIV>";

   ## Grid rules
   print FILE "<FORM name=\"fiauth\" action=\"/admin/chauthmapps.cgi\" method=\"post\">";
   print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
   print FILE "<tbody><TR valign=\"bottom\"><TD width=\"96%\">";
   print FILE "<font size=\"-1\"><p>";
   $msg[0] = "Alterar";
   $msg[1] = "Change";
   print FILE "<i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"mvPol\" name=\"CkMvPol\">";
   $msg[0] = "Usuários";
   $msg[1] = "Users";
   print FILE " &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; <i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"mvUsr\" name=\"CkMvUsr\">";
   $msg[0] = "Políticas";
   $msg[1] = "Policies";
   print FILE " &nbsp; <i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"enAlias\" name=\"CkenAlias\"></FONT></p>\n";
   print FILE << "HTMLCODE";
   <table id="fwAuthGrid" width="100%" style="font-size:12px;"></table>
   <div id="pfwAuthGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
   print FILE "</TD><TD width=\"4%\" align=\"left\">";
   print FILE "&nbsp;<a href=\"javascript: document.fauth.gdmoveup.click();\">";
   print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
   print FILE "&nbsp;<a href=\"javascript: document.fauth.gdmovedown.click();\">";
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
    <form name="fauth">
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

# "Make web page authnet.html"
sub get_authnets {
    my $htmlfile="$HTMLDIR/admin/dynhttp/authnets.html";
    read_fwrules("route");

    my @msg = ("", "");

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making fwauth.html
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
                 document.fauth.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 document.fauth.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.fiauth.ReloadFw.click();
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
        jQuery("#fwAuthGrid").jqGrid({
           url:'/admin/getauthnets.json',
           datatype: "json",
           height: \$(window).height() - 290,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
    print FILE "           colNames:['ID', 'Politica', 'Direção', 'Interface', 'Rede', 'Bypass', 'Condição', 'Descrição', 'Control' ],\n";
}
else {
    print FILE "           colNames:['ID', 'Policy', 'Direction', 'Interface', 'Network', 'Bypass', 'Condition', 'Description', 'Control' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id', sortable:false, width: 25, sorttype: "int", key: true },
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
    my $aalias = $msg[0];

print FILE << "javascript";
              { name:"aDir", index:'aDir', sortable:false, editable:true, edittype:'select', editoptions:{value:"from:from;to:to"}, width:100 },
javascript

    my $cint = 0;
    foreach (@fwifs) {
       $_ =~ s/\n//;
       if ($_ !~ /^ifb/) {
          my $line = "$_:$_";
          if ($cint gt 0) {
             $msg[0] = "$msg[0];$line";
          }
          else { $msg[0] = "any:any;$line"; }
          $cint++;
       }
    }

print FILE << "javascript";
              { name:"aIf",  index:'aIf', sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:80 },
              { name:"Dst",  index:'Dst', sortable:false, editable:true, width:210 },
              { name:"ckValue",  index:'ckValue', sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, width:60 },
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
           pager: '#pfwAuthGrid',
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
                 var selcur = jQuery("#fwAuthGrid").jqGrid('getRowData', selid);
                 var curPol = selcur['Group'];
                 var frPol = /\\?chk=/;
                 if (frPol.test(curPol)) curPol = curPol.replace(/.*\\?chk=/, "");
                 else curPol = "";

                 document.fchcond.idcond.value = curPol;
                 document.getElementById('chcondition').style.display = 'block';
              }
              else {
                 editRow(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$aalias", "authnets");
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
              rulesGrid=GridComplete(jQuery("#fwAuthGrid"), rulesGrid, rulesCt, saveall, "authnets");

              rulesCt++;
              jQuery("#fwAuthGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Ajustes por rede!";
$msg[1] = "Network adjustments!";
print FILE "           caption: '$msg[$FW_LANG]'\n";
$msg[0] = "Fluxo de rede";
$msg[1] = "Network flow";
print FILE << "javascript";
        });
        jQuery("#fwAuthGrid").jqGrid('setGroupHeaders', {
             useColSpanStyle: true, 
             groupHeaders:[ {startColumnName: 'aDir', numberOfColumns: 3, titleText: '<font size="2">$msg[$FW_LANG]</font>'} ]
        });
        jQuery("#fwAuthGrid").css('font-size', '13px');
        jQuery("#fwAuthGrid").jqGrid('navGrid',"#pfwAuthGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "authnets");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "authnets");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Edit button
        \$("#fwAuthGrid").jqGrid('navButtonAdd','#pfwAuthGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$aalias", "authnets");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#fwAuthGrid").jqGrid('navButtonAdd','#pfwAuthGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
$msg[0] = "Por favor... selecione a linha a ser removida!";
$msg[1] = "Please... Select the line to delete!";
print FILE << "javascript";
           onClickButton:function(){
             var gridrules = jQuery("#fwAuthGrid").jqGrid('getDataIDs').length;
             if (gridrules > 0) {
                var clret = jQuery("#fwAuthGrid").jqGrid('getRowData', gridrules);
                rulesGrid = cloneRow(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "authnets", clret['Group']);
                newRow = updnewRow();
             }
           }
        });

        // Delete row in click event
        jQuery("#delgd").click( function() {
           rulesCt = 1;
           rulesGrid = delRow(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
        });

        // Add button
        \$("#fwAuthGrid").jqGrid('navButtonAdd','#pfwAuthGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             var defGroup = "networks";
             var gridrules = jQuery("#fwAuthGrid").jqGrid('getDataIDs').length;
             if (gridrules > 0) {
                var clret = jQuery("#fwAuthGrid").jqGrid('getRowData', gridrules);
                defGroup = clret['Group'];
             }

             rulesGrid = addRow(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "authnets", defGroup, "$aalias");
             newRow = updnewRow();
           }
        });

        // Change Policy condition
        jQuery("#chCond").click( function() {
           var selid = \$("#fwAuthGrid").jqGrid('getGridParam','selrow');
           chGroupCond(jQuery("#fwAuthGrid"), rulesGrid, document.fchcond.idcond.value);
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
           saveAll(jQuery("#fwAuthGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "authnets", "/admin/getauthnets.json", "/admin/chauthnets.cgi");
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

    $msg[0] = "Captive portal: Gerenciar redes!";
    $msg[1] = "Captive portal: Network management!";
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
   print FILE "<DIV align=\"center\" valign=\"center\" id=\"chcondition\" class=\"chsform\">";
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
   print FILE "<FORM name=\"fiauth\" action=\"/admin/chauthnets.cgi\" method=\"post\">";
   print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
   print FILE "<tbody><TR valign=\"bottom\"><TD width=\"96%\">";
   print FILE "<font size=\"-1\"><p>";
   $msg[0] = "Alterar";
   $msg[1] = "Change";
   print FILE "<i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"mvPol\" name=\"CkMvPol\">";
   $msg[0] = "Apelidos";
   $msg[1] = "Alias";
   print FILE " &nbsp; <i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"enAlias\" name=\"CkenAlias\"></FONT></p>\n";
   print FILE << "HTMLCODE";
   <table id="fwAuthGrid" width="100%" style="font-size:12px;"></table>
   <div id="pfwAuthGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
   print FILE "</TD><TD width=\"4%\" align=\"left\">";
   print FILE "&nbsp;<a href=\"javascript: document.fauth.gdmoveup.click();\">";
   print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
   print FILE "&nbsp;<a href=\"javascript: document.fauth.gdmovedown.click();\">";
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
    <form name="fauth">
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
