#!/usr/bin/perl

#Rev.1 - Version 5.0

# "POST /admin/chfwnat.cgi" -> save or reload button
sub chnatrl {
    my $s = shift;

    my $rlfw = 0;
    my $canSync = 0;
    my $saveall = 0;
    my $txtvalue = "";
    read_fwnat;

    my $res = HTTP::Response->new();

    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && $canch == 1) {

       # Parsing json response (sorting by ID)
       my %json = ();
       my %gpName = ();
       my %groupData = ();
       my $group = "";
       my $lastpolicy = "";
       my @policies = ();
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
                   if ($dvalue[0] eq "ntIf" || $dvalue[0] eq "ntIfOut") {
                      if ($dvalue[0] eq "ntIfOut" && $dvalue[1] ne "any") {
                         $json{'ntIf'} =~ s/[\s]+$//;
                         $json{'ntIf'} = "$json{'ntIf'}\->$dvalue[1]";
                         $json{'ntIf'} = pack( 'A20', str_conv($json{'ntIf'}) );
                      }
                      else {
                         $json{$dvalue[0]} = pack( 'A20', str_conv($dvalue[1]) );
                      }
                   }
                   else {
                      my $auxvalue = str_conv($dvalue[1]);
                      if ($auxvalue && $auxvalue ne "0" && $auxvalue ne "none") {
                         if ($dvalue[0] =~ /^(Src|Dst)$/) {
                            $json{$dvalue[0]} = pack( 'A35', $auxvalue);
                         }
                         elsif ($dvalue[0] =~ /^(Control|Cond|id)$/) {
                            $json{$dvalue[0]} = $dvalue[1];
                            $saveall = 1 if ($dvalue[0] eq "Control" && $dvalue[1] eq "all");
                         }
                         else {
                            $json{$dvalue[0]} = $auxvalue if ($dvalue[1] !~ /^[\s]*$/);
                         }
                      }
                   }
                }
             }

             if ($json{'Group'} ne "" && $json{'ntIf'} ne "" && $json{'Src'} ne "" && $json{'Dst'} ne "") {
                # fwroute.nat rules
                $canSync = 1;
                $json{'fwTarg'} = $json{'ntIp'} if ($json{'fwTarg'} eq "SET");
                $auxentry = "$json{'ntIf'} $json{'Src'} $json{'Dst'} $json{'fwTarg'}\t";
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

                $json{'ntOpt'} = undef if (($json{'ntOpt'} eq "only-dnat" && $json{'Group'} !~ /^DNAT($|\?chk=)/) || ($json{'ntOpt'} eq "with-masq" && $json{'Group'} =~ /^SNAT($|\?chk=)/));
                $auxentry = "$auxentry $json{'ntOpt'}" if ($json{'ntOpt'} && $json{'fwTarg'} eq $json{'ntIp'});
                $auxentry = "$auxentry chk=$json{'Cond'}" if ($json{'Cond'});
                $auxentry = "$auxentry log-desc=\"$json{'fLog'}\"" if (length($json{'fLog'}) > 1);
                $auxentry = "$auxentry desc=\"$json{'Desc'}\"" if (length($json{'Desc'}) > 1);

                # policy rules
                $group = $json{'Group'};
                $group =~ s/\?chk=.*// if ($group =~ /\?chk=/);
                push(@{$groupData{$group}}, $auxentry);
                $gpName{$group} = $json{'Group'};
                $gpName{$group} =~ s/\?chk=/ chk=/;

                # policies array
                push(@policies, $group) if ($group ne $lastpolicy);
                $lastpolicy = $group;
             }
             if ($json{'Control'} eq "set") {
                $canSync = 1;
                $saveall = 1;
             }
          }
       }

       if ($canSync == 1) {
          open FILE, ">$file_cfg{'routing/fwroute.nat'}";

          # Writing nat comments
          foreach my $fRules (@natcomments) {
              $fRules =~ s/\n//;
              $fRules =~ s/\\"/\"/g;
              $fRules =~ s/\\'/\'/g;
              print FILE "$fRules\n" if ($fRules);
          }

          # Writing nat rules
          if ($saveall == 0) {
             @policies = ();
             push(@policies, @natgroup);
          }
          foreach my $fRules (@policies) {
             my $bkRules = $fRules;
             $fRules =~ s/\?chk=.*//;
             my $setPol = $bkRules;
             $setPol =~ s/\?chk=/ chk=/;
             $setPol = $gpName{$fRules} if ($gpName{$fRules} && $groupData{"$fRules"}[0]);
             print FILE "\nset-policy $setPol";
             if ($groupData{"$fRules"}[0] || $saveall > 0) {
                foreach my $aRules (@{$groupData{"$fRules"}}) {
                   $aRules =~ s/\n//;
                   $aRules =~ s/\\"/\"/g;
                   $aRules =~ s/\\'/\'/g;
                   print FILE "\n$aRules";
                }
             }
             else {
                foreach my $aRules (@{$natrules{"$bkRules"}}) {
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

          rsyncupdate("$file_cfg{'routing/fwroute.nat'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
    }
    else {
       my $rtime = 2;
       if ($canch == 1) {
          $msg[0] = "Aplicando as regras de NAT!";
          $msg[1] = "Applying NAT rules!";
          $msg2[0] = "<font size=\'2\'>Recarregando rtnat...</font>";
          $msg2[1] = "<font size=\'2\'>rtnal reloading...</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
          system("$FW_DIR/fwguardian --reload-nat 1>&2 2>/dev/null &");

          rsyncupdate("$file_cfg{'routing/fwroute.nat'}", "nat", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       }
       else {
          $rtime = 0;
       }

       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/fwnat.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page fwnat.html"
sub get_fwnat {

    my $htmlfile="$HTMLDIR/admin/dynhttp/fwnat.html";
    read_profiles;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making fwnat.html
    my %lsnat = ();
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
                 document.fnat.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 document.fnat.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.finat.ReloadFw.click();
                 return false;
           });
           \$("#selGroup").select2();

           \$( "input[type=button]" ).button().css('font-size', '12px');
        });
  </script>

  <script type="text/javascript">
     jQuery(document).ready(function(){

        // Rules array
        var rulesCt = 0;
        var myPolicies = new Array();        // Current myDataGrid policies
        var allPolicies = new Array();       // Current rulesGrid policies
        var rulesGrid = new Array();         // Main data
        var myDataGrid = new Array();        // Selected group data
        var newRow = new Array();
        var saveall = 0;

        // Make jqgrid
        var scrollPosition = 0;
        jQuery("#ifNatGrid").jqGrid({
           url:'/admin/getnatrl.json',
           datatype: "json",
           height: \$(window).height() - 300,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
    print FILE "           colNames:['ID', 'Politica', 'Interface', 'Endereço IP', 'Interface', 'Endereço IP', 'NAT', 'IP', 'Proto', 'Porta de origem', 'Porta de destino', 'Opções', 'Condição', 'Log', 'Descrição', 'Control', 'arrId' ],\n";
}
else {
    print FILE "           colNames:['ID', 'Policy', 'Interface', 'IP Address', 'Interface', 'IP Address', 'NAT', 'IP', 'Proto', 'Source port', 'Destination port', 'Options', 'Condition', 'Log', 'Description', 'Control', 'arrId' ],\n";
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
    $msg[0] = selGridifnet("ipnet");
    my $ntalias = $msg[0];

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
              { name:"ntIf",    index:'ntIf',    sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:78 },
              { name:"Src",     index:'Src',     sortable:false, editable:true, width:140 },
              { name:"ntIfOut", index:'ntIfOut', sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:78 },
              { name:"Dst",     index:'Dst',     sortable:false, editable:true, width:140 },
              { name:"fwTarg",  index:'fwTarg',  sortable:false, editable:true, edittype:'select', editoptions:{value:"SET:SET;IGNORE:IGNORE;MASQ:MASQ;AUTO:AUTO"}, width:80 },
              { name:"ntIp",   index:'ntIp',  sortable:false, editable:true, width:140 },
              { name:"proto",  index:'proto', sortable:false, editable:true, edittype:"select", editoptions:{value:"any:any;tcp:tcp;udp:udp;icmp:icmp;gre:gre;ah:ah;esp:esp;ospf:ospf;vrrp:vrrp"}, width:70 },
              { name:"sport",  index:'sport', sortable:false, editable:true, width:162 },
              { name:"dport",  index:'dport', sortable:false, editable:true, width:162 },
              { name:"ntOpt",  index:'ntOpt', sortable:false, editable:true, edittype:"select", editoptions:{value:"none:none;with-masq:with-masq;only-dnat:only-dnat"}, width:80 },
javascript
    $msg[0] = "none:none;disabled:disabled";
    foreach (@fwchk) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       $msg[0] = "$msg[0];$line";
    }
print FILE "{ name:\"Cond\",  index:'Cond',  sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:120 },\n";
print FILE << "javascript";
              { name:"fLog",    index:'fLog', sortable:false, editable:true, dataType:'string', width:250 },
              { name:"Desc",    index:'Desc',  sortable:false, editable:true, dataType:'string', width:320 },
              { name:"Control", index:'Control', sortable:false,  editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 },
              { name:"arrId",   index:'arrId',   sortable:false, editable:true, hidden:true, editoptions:{size:"5", maxlength:"5"}, width:5 }
           ],
           pager: '#pifNatGrid',
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
                 var selcur = jQuery("#fwNatGrid").jqGrid('getRowData', selid);
                 var curPol = selcur['Group'];
                 var frPol = /\\?chk=/;
                 if (frPol.test(curPol)) curPol = curPol.replace(/.*\\?chk=/, "");
                 else curPol = "";

                 document.fchcond.idcond.value = curPol;
                 document.getElementById('chcondition').style.display = 'block';
              }
              else {
                 editRow(jQuery("#ifNatGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$ntalias", "fwnat");
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
              rulesGrid=GridComplete(jQuery("#ifNatGrid"), rulesGrid, rulesCt, saveall, "fwnat");

              rulesCt++;
              jQuery("#ifNatGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Definições de NAT";
$msg[1] = "NAT definitions";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#ifNatGrid").jqGrid('setGroupHeaders', {
             useColSpanStyle: true, 
             groupHeaders:[
javascript
$msg[0] = "Origem";
$msg[1] = "Source";
print FILE << "javascript";
               {startColumnName: 'ntIf', numberOfColumns: 2, titleText: '<font size="2">$msg[$FW_LANG]</font>'},
javascript
$msg[0] = "Destino";
$msg[1] = "Destination";
print FILE << "javascript";
               {startColumnName: 'ntIfOut', numberOfColumns: 2, titleText: '<font size="2">$msg[$FW_LANG]</font>'},
javascript
$msg[0] = "Alvo NAT";
$msg[1] = "NAT Target";
print FILE << "javascript";
               {startColumnName: 'fwTarg', numberOfColumns: 2, titleText: '<font size="2">$msg[$FW_LANG]</font>'} ]
        });
        jQuery("#ifNatGrid").css('font-size', '13px');
        jQuery("#ifNatGrid").jqGrid('navGrid',"#pifNatGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Make myDataGrid
        function mkMyDataGrid() {
           var curId = 0;
           myDataGrid.length=0;
           for (var i=0; i<myPolicies.length; i++) curId = buildMyData(myPolicies[i], rulesGrid.length, curId);
           refreshGroup(jQuery("#ifNatGrid"), myDataGrid, myDataGrid.length, curId);
        }

        // Moveup row function
        jQuery("#gdUp").click( function() {
           var it=1;
           var doId=0;
           var myRules = myDataGrid.length;
           var selid = jQuery("#ifNatGrid").jqGrid('getGridParam','selrow');
           var selcur = jQuery("#ifNatGrid").jqGrid('getRowData', selid);

           var mvPol=0;
           if (document.getElementById('mvPol').checked == true) {
              mvPol=1;
              if (myPolicies.length > 0) {
                 if (myPolicies[0] !== selcur['Group'] && myPolicies.length > 1) {
                    for (var i=0; i<myPolicies.length; i++) {
                       if (selcur['Group'] === myPolicies[i]) {
                          var auxGrp = myPolicies[i];
                          myPolicies[i] = myPolicies[i-1];
                          myPolicies[i-1] = auxGrp;
                          i=myPolicies.length;
                       }
                    }
                 }
                 else it=0;
              }
           }
           else {
              if (myRules > 0 && it > 0) {
                 var selnex = selcur;
                 if (selcur['id'] !== myDataGrid[0]['id']) {
                    selcur = myDataGrid[selcur['arrId']-1];
                    selnex = myDataGrid[selnex['arrId']];
                    it = selnex['id'];
                    it = it - selcur['id'];
                    selid = selcur['id'];
                    if (selcur['Group'] !== selnex['Group']) {
                       selid++;
                       if (it > 1) it++;
                    }
                 }
                 else it=0;
              }
           }
           if (it < 1) return 1;

           for (var i=0; i<it; i++) rulesGrid = mvUp(jQuery("#ifNatGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwnat");
           newRow = updnewRow();
           doReload = upddoReload();

           if (mvPol == 1) {
              selid=updselidGrp();
              if (myRules < 1) {
                 it=0;
                 refreshGroup(jQuery("#ifNatGrid"), rulesGrid, rulesGrid.length, selid);
              }
              doId=1;
              saveall=1;
           }
           if (myRules > 0 && it > 0) {
              doId=1;
              mkMyDataGrid();
           }
           if (doId) setPos(jQuery("#ifNatGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           var it=1;
           var doId=0;
           var myRules = myDataGrid.length;
           var selid = jQuery("#ifNatGrid").jqGrid('getGridParam','selrow');
           var selcur = jQuery("#ifNatGrid").jqGrid('getRowData', selid);

           var mvPol=0;
           if (document.getElementById('mvPol').checked == true) {
              mvPol=1;
              if (myPolicies.length > 0) {
                 if (myPolicies[myPolicies.length-1] !== selcur['Group'] && myPolicies.length > 1) {
                    for (var i=0; i<myPolicies.length; i++) {
                       if (selcur['Group'] === myPolicies[i]) {
                          var auxGrp = myPolicies[i];
                          myPolicies[i] = myPolicies[i+1];
                          myPolicies[i+1] = auxGrp;
                          i=myPolicies.length;
                       }
                    }
                 }
                 else it=0;
              }
           }
           else {
              if (myRules > 0 && it > 0) {
                 var selnex = selcur;
                 if (selcur['id'] !== myDataGrid[myDataGrid.length-1]['id']) {
                    selcur = myDataGrid[selcur['arrId']];
                    selnex = myDataGrid[parseInt(selnex['arrId'])+1];
                    it = selnex['id'];
                    it = it - selcur['id'];
                    selid = selnex['id'];
                    if (selcur['Group'] !== selnex['Group']) {
                       selid--;
                       if (it > 1) it++;
                    }
                 }
                 else it=0;
              }
           }
           if (it < 1) return 1;

           for (var i=0; i<it; i++) rulesGrid = mvDown(jQuery("#ifNatGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwnat");
           newRow = updnewRow();
           doReload = upddoReload();

           if (mvPol == 1) {
              selid=updselidGrp();
              if (myRules < 1) {
                 it=0;
                 refreshGroup(jQuery("#ifNatGrid"), rulesGrid, rulesGrid.length, selid);
              }
              doId=1;
              saveall=1;
           }
           if (myRules > 0 && it > 0) {
              doId=1;
              mkMyDataGrid();
           }
           if (doId) setPos(jQuery("#ifNatGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
        });

        // Edit button
        \$("#ifNatGrid").jqGrid('navButtonAdd','#pifNatGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#ifNatGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$ntalias", "fwnat");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#ifNatGrid").jqGrid('navButtonAdd','#pifNatGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             var selid = jQuery("#ifNatGrid").jqGrid('getGridParam','selrow');
             var selcur = jQuery("#ifNatGrid").jqGrid('getRowData', selid);

             if (selid > 0) {
                var defGroup = selcur['Group'];
                rulesGrid = cloneRow(jQuery("#ifNatGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwnat", defGroup);
                newRow = updnewRow();

                if (myDataGrid.length > 0) {
                   mkMyDataGrid();
                   selid++;
                   jQuery("#ifNatGrid").jqGrid('setRowData',selid,false,{color:'Navy'});
                   setPos(jQuery("#ifNatGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
                }
             }
           }
        });

        // Delete row in click event
        jQuery("#delgd").click( function() {
javascript
$msg[0] = "Por favor... selecione a linha a ser removida!";
$msg[1] = "Please... Select the line to delete!";
print FILE << "javascript";
           var selid = 0;
           rulesCt = 1;
           rulesGrid = delRow(jQuery("#ifNatGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();

           if (myDataGrid.length > 0) {
              mkMyDataGrid();
              selid = updselidFind();
              setPos(jQuery("#ifNatGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
           }
           allPolicies=updGrp();
        });

        // Add button
        \$("#ifNatGrid").jqGrid('navButtonAdd','#pifNatGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             var selid = jQuery("#ifNatGrid").jqGrid('getGridParam','selrow');
             var gridrules = jQuery("#ifNatGrid").jqGrid('getDataIDs').length;

             var defGroup = document.getElementById('selGroup').value;
             if (selid && gridrules > 0) {
                var clret = jQuery("#ifNatGrid").jqGrid('getRowData', selid);
                defGroup = clret['Group'];
             }

             if (defGroup !== "any") {
                rulesGrid = addRow(jQuery("#ifNatGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwnat", defGroup, "$ntalias");
                newRow = updnewRow();

                if (myDataGrid.length > 0) {
                   mkMyDataGrid();

                   selid++;
                   jQuery("#ifNatGrid").jqGrid('setRowData',selid,false,{color:'Navy'});
                   setPos(jQuery("#ifNatGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
                   jQuery("#ifNatGrid").editRow(selid, true);
                }
             }
javascript
$msg[0] = "Selecione uma política de NAT válida!";
$msg[1] = "Select a valid NAT policy!";
print FILE << "javascript";
             else alert('$msg[$FW_LANG]');
           }
        });

        // Defining MyDataGrid rows
        function buildMyData(selPolicy, rules, curId) {
           var j=curId;
           for (var i=0; i<rules; i++) {
              var curRol = rulesGrid[i];
              var curPol = curRol['Group'];
              curPol = curPol.replace(/\\?chk=.*/, "");
              if (curPol == selPolicy) {
                 myDataGrid.push(curRol);
                 myDataGrid[j]['arrId'] = j; 
                 j++;
              }
           }
           return j;
        }

        // Create a new policy
        jQuery("#newGroupPol").click(function(){
           var rules = rulesGrid.length;
           var selid = \$("#ifNatGrid").jqGrid('getGridParam','selrow');

           var edited = 0;
           var defGroup = document.getElementById('selGroup').value;
           if (newRow.length > 0) edited = chkRow(jQuery("#ifNatGrid"), 0, rulesGrid, newRow);
           rulesGrid=GridComplete(jQuery("#ifNatGrid"), rulesGrid, 1, 0, "fwnat");

           if (edited == 1 || defGroup === "any") {
javascript
$msg[0] = "ERRO: Selecione uma política de NAT válida!";
$msg[1] = "ERROR: Select a valid NAT policy!";
print FILE << "javascript";
              if (edited == 1) alert("$medited[$FW_LANG]");
              else alert("$msg[$FW_LANG]");
              return 1;
           }
           if (!selid) selid = 1;

           var find=0;
           allPolicies=updGrp();
           for (var i=0; i<allPolicies.length; i++) {
               if (allPolicies[i] === defGroup) {
                  find=1;
                  i=allPolicies.length;
               }
           }
javascript
$msg[0] = "ERRO: Este tipo de NAT já está definido!";
$msg[1] = "ERROR: This NAT type is already defined!";
print FILE << "javascript";
           if (find == 0) {
              for (var i=selid-1; i<rules; i++) {
                 if ((i < rules-1 && (rulesGrid[i]['Group'] !== rulesGrid[i+1]['Group'])) || i == rules-1) {
                    selid=i+1;
                    jQuery("#ifNatGrid").setSelection(selid, true);
                    i=rules;
                 }
              }
              rulesGrid = addRow(jQuery("#ifNatGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwnat", defGroup, "$ntalias");
              newRow = updnewRow();
              saveall=1;

              if (myDataGrid.length > 0) {
                 var auxPol = new Array();
                 for (var i=0; i<myPolicies.length; i++) {
                     auxPol.push(myPolicies[i]);
                     if (rulesGrid[selid-1]['Group'].replace(/\\?chk=.*/, "") === myPolicies[i]) auxPol.push(defGroup);
                 }
                 myPolicies = auxPol;
                 mkMyDataGrid();

                 selid++;
                 jQuery("#ifNatGrid").jqGrid('setRowData',selid,false,{color:'Navy'});
                 setPos(jQuery("#ifNatGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
                 jQuery("#ifNatGrid").editRow(selid, true);
              }
           }
           else alert("$msg[$FW_LANG]");
        });

        // Select policy
        jQuery("#selGroup").change(function(){
           var rules = rulesGrid.length;
           var gridrules = jQuery("#ifNatGrid").jqGrid('getDataIDs').length;

           var selPolicy  = \$(this).val();
           if (selPolicy == "-1") return 1;
           selPolicy = selPolicy.replace(/.*:/, "");

           // Check policy
javascript
$msg[0] = "Política inexistente...\\nPrimeiro adicione uma política de NAT ao conjunto de regras!";
$msg[1] = "Nonexistent policy...\\nFirst you need add a NAT policy into rule set!";
print FILE << "javascript";
           var find=0;
           rulesGrid=GridComplete(jQuery("#ifNatGrid"), rulesGrid, 1, 0, "fwnat");
           if (gridrules < 1) allPolicies.length = 0;
           else allPolicies=updGrp();
           for (var i=0; i<allPolicies.length; i++) {
              if (selPolicy === allPolicies[i] || selPolicy === "any") {
                 find=1;
                 break;
              }
           }

           if (selPolicy && find == 1) {
              if (newRow.length > 0) {
                 if (chkRow(jQuery("#ifNatGrid"), 0, rulesGrid, newRow) == 1) {
                    alert("$medited[$FW_LANG]");
                    return 1;
                 }
                 newRow = updnewRow();
                 saveall = 1;
              }
           }
           else {
              if (find == 0) alert('$msg[$FW_LANG]');
              return 1;
           }

           if (selPolicy !== "any") {
              myRules = 0;
              myDataGrid.length = 0;
              myPolicies.length = 0;

              var curId = buildMyData(selPolicy, rules, myRules);
              myPolicies.push(selPolicy);

              if (myDataGrid[myDataGrid.length-1]) {
                 curId = myDataGrid[myDataGrid.length-1]['id'];
                 \$("#ifNatGrid").setGridParam({ rowNum:curId });
              }
              else cudId=0;
              refreshGroup(jQuery("#ifNatGrid"), myDataGrid, myDataGrid.length, curId);
              jQuery("#ifNatGrid").setSelection(curId, true);
javascript
$msg[0] = "Tipo selecionado: ";
$msg[1] = "Selected type: ";
print FILE "              alert(\"$msg[$FW_LANG]\"+selPolicy);\n";
print FILE << "javascript";
           }
           else {
              myDataGrid.length=0;
              myPolicies.length=0;
              refreshGroup(jQuery("#ifNatGrid"), rulesGrid, rules, 1);
              jQuery("#ifNatGrid").setSelection(1, true);
           }
        });

        // Change Policy condition
        jQuery("#chCond").click( function() {
           var selid = \$("#ifNatGrid").jqGrid('getGridParam','selrow');
           chGroupCond(jQuery("#ifNatGrid"), rulesGrid, document.fchcond.idcond.value);
           if (myDataGrid.length > 0) {
              mkMyDataGrid();
              setPos(jQuery("#ifNatGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
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
           var gridData = rulesGrid;
           var edited = 0;
           var nlen = newRow.length;
           var selid = \$("#ifNatGrid").jqGrid('getGridParam','selrow');
           if (nlen > 0) edited = chkRow(jQuery("#ifNatGrid"), 0, rulesGrid, newRow);
           if (edited == 0) {
              if (myDataGrid.length > 0 && saveall < 1) {
                 if (nlen > 0) mkMyDataGrid();
                 gridData = myDataGrid;
              }
              else if (gridData.length > 0) gridData[0]['Control']="all";

              saveAll(jQuery("#ifNatGrid"), gridData, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "fwnat", "/admin/getnatrl.json", "/admin/chnatrl.cgi");
              newRow = updnewRow();

              if (newRow.length < 1 && myDataGrid.length < 1) {
                 rulesCt = 0;
                 refreshGroup(jQuery("#ifNatGrid"), gridData, gridData.length, selid);
              }
           }
        });

        \$("#ifNatGrid").jqGrid('navButtonAdd','#pifNatGrid',{
           caption:"&nbsp; Info",
           onClickButton:function(){
             var selid = jQuery("#ifNatGrid").jqGrid('getGridParam','selrow');
             var clret = jQuery("#ifNatGrid").jqGrid('getRowData', selid);
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

    $msg[0] = "Configuração de NAT!";
    $msg[1] = "NAT configuration!";
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
   print FILE "<FORM name=\"finat\" action=\"/admin/chnatrl.cgi\" method=\"post\">";
   print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
   print FILE "<tbody><TR valign=\"bottom\"><TD width=\"96%\">";
   print FILE "<font size=\"-1\"><p>";
   print FILE "<select size='1' id='selGroup' name='lsDefGroup' style='width:180px; font-size:small;'>";
   my @lsnat = ( "any", "DNAT", "SNAT", "NETMAP" );
   foreach my $group (@lsnat) {
      print FILE "<OPTION value=\"$group\">$group</OPTION>";
   }
   print FILE "</select>";
   $msg[0] = "Adiciona";
   $msg[1] = "Add";
   print FILE "&nbsp; <INPUT type=\"button\" id=\"newGroupPol\" name=\"CtGP\" value=\"$msg[$FW_LANG]\" style=\"Font-Family: Arial, Helvetica;\">";
   print FILE " &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; ";
   $msg[0] = "Alterar";
   $msg[1] = "Change";
   print FILE "<i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"mvPol\" name=\"CkMvPol\">";
   $msg[0] = "Apelidos";
   $msg[1] = "Alias";
   print FILE " &nbsp; <i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"enAlias\" name=\"CkenAlias\"></FONT></p>\n";
   print FILE << "HTMLCODE";
   <table id="ifNatGrid" width="100%" style="font-size:12px;"></table>
   <div id="pifNatGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
   print FILE "</TD><TD width=\"4%\" align=\"left\">";
   print FILE "&nbsp;<a href=\"javascript: document.fnat.gdmoveup.click();\">";
   print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
   print FILE "&nbsp;<a href=\"javascript: document.fnat.gdmovedown.click();\">";
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
    <form name="fnat">
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
