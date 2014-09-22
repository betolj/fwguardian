#!/usr/bin/perl

#Rev.1 - Version 5.0

# "POST /admin/chprofile.cgi" -> "save" button
sub chprofile {
    my $s = shift;

    my $saveall = 0;
    my $txtvalue = "";
    my $rlfw = 0;
    my @msg = ("", ""), @msg2 = ("", "");
    my $res = HTTP::Response->new();
    read_profiles;
    
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
                   my $auxvalue = str_conv($dvalue[1]);
                   if ($auxvalue && $auxvalue ne "0" && $auxvalue ne "none") {
                      if ($dvalue[0] =~ /^(pflInt|pflIn2)$/) {
                         $json{$dvalue[0]} = pack( 'A4', $auxvalue);
                      }
                      elsif ($dvalue[0] =~ /^(pfIf|proto)$/) {
                         $json{$dvalue[0]} = pack( 'A9', $auxvalue);
                      }
                      elsif ($dvalue[0] eq "fwTarg") {
                         $auxvalue = "RETURN" if ($dvalue[0] eq "fwTarg" && $dvalue[1] eq "IGNORE");
                         $json{$dvalue[0]} = pack( 'A18', $auxvalue);
                      }
                      elsif ($dvalue[0] eq "pdata") {
                         $auxvalue =~ s/(\s)+$//;
                         if (length($auxvalue) > 62) {
                            $json{$dvalue[0]} = $auxvalue;
                         }
                         else {
                            $json{$dvalue[0]} = pack( 'A62', $auxvalue);
                         }
                      }
                      elsif ($dvalue[0] =~ /^(Control|Cond|id)$/) {
                         $json{$dvalue[0]} = $dvalue[1];
                         $saveall = 1 if ($dvalue[0] eq "Control" && $dvalue[1] eq "all");
                      }
                      else {
                         $auxvalue =~ s/>/:/ if ($dvalue[0] eq "Group" && $dvalue[1] =~ /^(vpn|mangle|limit)>/);
                         $json{$dvalue[0]} = $auxvalue if ($dvalue[1] !~ /^[\s]*$/);
                      }
                   }
                }
             }

             $json{'pdata'} = pack( 'A62', "any") if (($json{'pdata'} && $json{'pdata'} eq "") || not $json{'pdata'});
             if ($json{'Group'} ne "" && $json{'proto'} ne "" && $json{'fwTarg'} ne "") {
                # profile/profile.def rules
                $canSync = 1;
                $auxentry = "$json{'pflInt'} $json{'pfIf'} $json{'proto'} $json{'pdata'} $json{'fwTarg'} $json{'pflIn2'} $json{'pfIp'}\t";

                if ($json{'pRate'} && $json{'pRate'} ne "any") {
                   $auxentry = "$auxentry $json{'pRate'}";
                   $auxentry = "$auxentry flow=$json{'pHash'}" if ($json{'pHash'} && $json{'pHash'} ne "any" && $json{'fwTarg'} =~ /^PKTLIMIT[\s]*$/);
                }
                $auxentry = "$auxentry new" if ($json{'fNew'} eq "Yes");
                $auxentry = "$auxentry string=\"$json{'pStr'}\"" if ($json{'pStr'});
                $auxentry = "$auxentry chk=$json{'Cond'}" if ($json{'Cond'});
                $auxentry = "$auxentry log" if ($json{'hLog'} eq "Yes");
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
          open FILE, ">$file_cfg{'profile/profile.def'}";

          # Writing profile comments
          foreach my $fRules (@profcomments) {
              $fRules =~ s/\n//;
              $fRules =~ s/\\"/\"/g;
              $fRules =~ s/\\'/\'/g;
              print FILE "$fRules\n" if ($fRules);
          }

          # Writing profile rules
          if ($saveall == 0) {
             @policies = ();
             push(@policies, @fwltprof);
             push(@policies, @fwprof);
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
                foreach my $aRules (@{$profline{"$bkRules"}}) {
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

          rsyncupdate("$file_cfg{'profile/profile.def'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
    }
    else {
       my $rtime = 2;
       if ($canch == 1) {
          my $reloadpol = $s;
          $reloadpol =~ s/.*\&pgroup=//;
          $reloadpol = "profile" if ($reloadpol eq "");
          if ($reloadpol ne "profile") {
             $reloadpol = str_conv($reloadpol);
             $reloadpol =~ s/^limit>/limit:/ if ($reloadpol =~ /^limit>/);
             $reloadpol =~ s/^mangle>/mangle:/ if ($reloadpol =~ /^mangle>/);
          }
          $msg[0] = "Aplicando as regras de firewall!";
          $msg[1] = "Applying firewall rules!";
          $msg2[0] = "Com";
          $msg2[1] = "With";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "<font size=\'2\'>$msg2[$FW_LANG] --reload-profile $reloadpol</font>");
          system("$FW_DIR/fwguardian --reload-profile $reloadpol 1>&2 2>/dev/null &");

          rsyncupdate("$reloadpol", "profile", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       }
       else {
          $rtime = 0;
       }
       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/profiles.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page profiles.html"
sub get_profile {
    my $htmlfile="$HTMLDIR/admin/dynhttp/profiles.html";
    read_profiles;

    my @msg = ("", "");
    my @policy = ("", "");
    $policy[0] = "Politica";
    $policy[1] = "Policy";
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making profiles.html
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
                 document.fprof.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 document.fprof.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.fiprof.ReloadFw.click();
                 return false;
           });
           \$("#selGroup").select2();
           \$("#selGroupType").select2();

           \$( "input[type=button]" ).button().css('font-size', '12px');
        });
  </script>

<script type="text/javascript">

     jQuery(document).ready(function(){

        // Rules array
        var saveall = 0;
        var rulesCt = 0;
        var myPolicies = new Array();        // Current myDataGrid policies
        var allPolicies = new Array();       // Current rulesGrid policies
        var rulesGrid = new Array();         // Main data
        var myDataGrid = new Array();        // Selected group data
        var newRow = new Array();

        // Make jqgrid
        var scrollPosition = 0;
        jQuery("#ifProfGrid").jqGrid({
           url:'/admin/getprofile.json',
           datatype: "json",
           height: \$(window).height() - 300,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
    print FILE "           colNames:['ID', 'Politica', 'Dir', 'Interface', 'Protocolo', 'Dados do protocolo (portas)', 'Alvo', 'Dir', 'Endereço', 'Taxa', 'Fluxo hash', 'Novo', 'Texto', 'Condição', 'Log', 'Descrição', 'Control', 'arrId' ],\n";
}
else {
    print FILE "           colNames:['ID', 'Policy', 'Dir', 'Interface', 'Protocol', 'Protocol data (ports)', 'Target', 'Dir', 'Address', 'Rate', 'Hash flow', 'New', 'String', 'Condition', 'Log', 'Description', 'Control', 'arrId' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id', sortable:false, width: 30, sorttype: "int", key: true },
              { name:"Group",   index:'Group', hidden:true,  width:30,
                 formatter: function (cellval, opts, rowObject, action) {
                     var groupIdPrefix = opts.gid + "ghead_",
                         groupIdPrefixLength = groupIdPrefix.length;

                     var fwtrigger = /(^(limit\>|((rsquid|vpop3)\$))|\\?chk=)/;
                     if (opts.rowId.substr(0, groupIdPrefixLength) === groupIdPrefix && typeof action === "undefined") {
                        return (fwtrigger.test(cellval) ? ('<span class="ui-icon ui-icon-alert" style="float: left;"></span>' + '<span style="color:#800000; margin-left: 5px;">') : "<span>") + cellval + '</span>';
                     }
                     return cellval;
                 }
              },
javascript
    $msg[0] = selGridifnet("net");

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
              { name:"pflInt", index:'pflInt',  sortable:false, editable:true, edittype:'select', editoptions:{value:"to:to;from:from"}, hidden:true, width:54 },
              { name:"pfIf",   index:'pfIf',    sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, hidden:true, width:78 },
              { name:"proto",  index:'proto',   sortable:false, editable:true, edittype:"select", editoptions:{value:"any:any;src_addr:src_addr;dst_addr:dst_addr;src_geoip:src_geoip;dst_geoip:dst_geoip;tcp:tcp;udp:udp;icmp:icmp;gre:gre;ah:ah;esp:esp;ospf:ospf;vrrp:vrrp"}, width:80 },
              { name:"pdata",  index:'pdata',   sortable:false, editable:true, width:480 },
javascript
$msg[0] = "ACCEPT:ACCEPT;DROP:DROP;REJECT:REJECT;IGNORE:IGNORE;PKTLIMIT:PKTLIMIT;CONNLIMIT:CONNLIMIT";
foreach (@fwprof,@fwltprof) {
   $_ =~ s/\n//;
   if ($_ !~ /^[\s]*mangle:/) {
      my $auxdesc = $_;
      if ($_ !~ /chk=disabled$/) {
         $auxdesc =~ s/.*://;
         my $line = "$auxdesc:$auxdesc";
         $msg[0] = "$msg[0];$line";
      }
   }
}
print FILE << "javascript";
              { name:"fwTarg", index:'fwTarg', sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:120 },
              { name:"pflIn2", index:'pflIn2', sortable:false, editable:true, edittype:'select', editoptions:{value:"to:to;from:from"}, hidden:true, width:54 },
              { name:"pfIp",   index:'pfIp',   sortable:false, editable:true, hidden:true, width:140 },
              { name:"pRate",  index:'pRate',  sortable:false, editable:true, hidden:true, width:80 },
              { name:"pHash",  index:'pHash',  sortable:false, editable:true, hidden:true, width:140 },
              { name:"fNew",   index:'fNew',   sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, width:60 },
              { name:"pStr",   index:'pStr',   sortable:false, editable:true, width:150 },
javascript
    $msg[0] = "none:none;disabled:disabled";
    foreach (@fwchk) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       $msg[0] = "$msg[0];$line";
    }
print FILE "{ name:\"Cond\",  index:'Cond',  sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:120 },\n";
print FILE << "javascript";
              { name:"hLog",    index:'hLog', sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, width:60 },
              { name:"Desc",    index:'Desc', sortable:false, editable:true, dataType:'string', width:320 },
              { name:"Control", index:'Control', sortable:false,  editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 },
              { name:"arrId",   index:'arrId',   sortable:false, editable:true, hidden:true, editoptions:{size:"5", maxlength:"5"}, width:5 }
           ],
           pager: '#pifProfGrid',
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
                 var selcur = jQuery("#fwProfGrid").jqGrid('getRowData', selid);
                 var curPol = selcur['Group'];
                 var frPol = /\\?chk=/;
                 if (frPol.test(curPol)) curPol = curPol.replace(/.*\\?chk=/, "");
                 else curPol = "";

                 document.fchcond.idcond.value = curPol;
                 document.getElementById('chcondition').style.display = 'block';
              }
              else {
                 editRow(jQuery("#ifProfGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "profile");
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
              rulesGrid=GridComplete(jQuery("#ifProfGrid"), rulesGrid, rulesCt, saveall, "profile");

              rulesCt++;
              jQuery("#ifProfGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Definições de perfil";
$msg[1] = "Profile definitions";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#ifProfGrid").jqGrid('setGroupHeaders', {
             useColSpanStyle: true, 
             groupHeaders:[
javascript
$msg[0] = "Fluxo / Interface";
$msg[1] = "Interface flow";
print FILE << "javascript";
               {startColumnName: 'pflInt', numberOfColumns: 2, titleText: '<font size="2">$msg[$FW_LANG]</font>'},
javascript
$msg[0] = "Fluxo / Endereço";
$msg[1] = "Address flow";
print FILE << "javascript";
               {startColumnName: 'pflIn2', numberOfColumns: 2, titleText: '<font size="2">$msg[$FW_LANG]</font>'},
javascript
$msg[0] = "Limitadores";
$msg[1] = "Limiters";
print FILE << "javascript";
               {startColumnName: 'pRate', numberOfColumns: 2, titleText: '<font size="2">$msg[$FW_LANG]</font>'} ]
        });
        jQuery("#ifProfGrid").css('font-size', '13px');
        jQuery("#ifProfGrid").jqGrid('navGrid',"#pifProfGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Search function
        function searchGrid() {
           var gridid = jQuery("#ifProfGrid");
           var selid = gridid.jqGrid('getGridParam','selrow');
           var dataGrid = rulesGrid;
           var myDataLen = myDataGrid.length;
           if (!selid) {
              if (myDataLen > 0) selid=myDataGrid[0]['id'];
              else selid=1;
              gridid.setSelection(selid, true);
           }
           var selcur = gridid.jqGrid('getRowData', selid);
           var canAdd = document.getElementById('GroupAdd').checked;
           var st_search = document.getElementById('newGroupValue').value;
           var st_field = new Array("Group","proto","pdata","fwTarg","pStr","Desc");

           // Getting policies
           var selpos = selid-1;
           var startid = selid;
           if (myDataLen > 0) {
              dataGrid = myDataGrid;
              selpos = selcur['arrId'];
           }
           var auxPol = search_Grid(dataGrid, selpos, st_search, canAdd, st_field);
           if (auxPol.length > 0) {
              myPolicies.length = 0;
              myPolicies = auxPol;
           }

           // Find search ID - FindId
javascript
$msg[0] = "INFO: Nada encontrado!\\nBusca iniciada em ";
$msg[1] = "INFO: Nothing found!\\nSearch started at ";
print FILE << "javascript";
           selid = updselidFind();
           if (selid < 1) {
              alert("$msg[$FW_LANG]"+startid+"!");
              gridid.setSelection(dataGrid[0]['id'], true);
              gridid.closest(".ui-jqgrid-bdiv").scrollTop(dataGrid[0]['id']);
              return 1;
           }
javascript
$msg[0] = "INFO: Desmarque 'Unir' para pesquisa linha a linha!";
$msg[1] = "INFO: Uncheck 'Join' for fine search!";
print FILE << "javascript";
           // Rebuild grid if myDataGrid was greater then 0
           if (canAdd) {
              if (myPolicies.length > 0) {
                 mkMyDataGrid();
                 alert("$msg[$FW_LANG]");
              }
              else {
javascript
$msg[0] = "INFO: Nenhuma política encontrada!\\nIniciado em ";
$msg[1] = "INFO: No policy found!\\nStarting at ";
print FILE << "javascript";
                 alert("$msg[$FW_LANG]");
                 selid=1;
              }
           }

           // Set selid
           gridid.setSelection(selid, true);
           setPos(gridid, selid, getGroups(dataGrid[selid-1], myPolicies));
        }

        // Make myDataGrid
        function mkMyDataGrid() {
           var curId = 0;
           myDataGrid.length=0;
           for (var i=0; i<myPolicies.length; i++) curId = buildMyData(myPolicies[i], rulesGrid.length, curId);
           refreshGroup(jQuery("#ifProfGrid"), myDataGrid, myDataGrid.length, curId);
        }

        // Moveup row function
        jQuery("#gdUp").click( function() {
           var it=1;
           var doId=0;
           var myRules = myDataGrid.length;
           var selid = jQuery("#ifProfGrid").jqGrid('getGridParam','selrow');
           var selcur = jQuery("#ifProfGrid").jqGrid('getRowData', selid);

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

           rulesGrid = mvUp(jQuery("#ifProfGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "profile", it);
           newRow = updnewRow();
           doReload = upddoReload();

           if (mvPol == 1) {
              selid=updselidGrp();
              if (myRules < 1) {
                 it=0;
                 refreshGroup(jQuery("#ifProfGrid"), rulesGrid, rulesGrid.length, selid);
              }
              doId=1;
              saveall=1;
           }
           if (myRules > 0 && it > 0) {
              doId=1;
              mkMyDataGrid();
           }
           if (doId) setPos(jQuery("#ifProfGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           var it=1;
           var doId=0;
           var myRules = myDataGrid.length;
           var selid = jQuery("#ifProfGrid").jqGrid('getGridParam','selrow');
           var selcur = jQuery("#ifProfGrid").jqGrid('getRowData', selid);

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

           rulesGrid = mvDown(jQuery("#ifProfGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "profile", it);
           newRow = updnewRow();
           doReload = upddoReload();

           if (mvPol == 1) {
              selid=updselidGrp();
              if (myRules < 1) {
                 it=0;
                 refreshGroup(jQuery("#ifProfGrid"), rulesGrid, rulesGrid.length, selid);
              }
              doId=1;
              saveall=1;
           }
           if (myRules > 0 && it > 0) {
              doId=1;
              mkMyDataGrid();
           }
           if (doId) setPos(jQuery("#ifProfGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
        });

        // Advanced
        \$("#ifProfGrid").jqGrid('navButtonAdd','#pifProfGrid',{
javascript
$msg[0] = "*Avançado ";
$msg[1] = "*Advanced ";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
               \$("#ifProfGrid").showCol("pflInt");
               \$("#ifProfGrid").showCol("pfIf");
               \$("#ifProfGrid").showCol("pflIn2");
               \$("#ifProfGrid").showCol("pfIp");
               \$("#ifProfGrid").showCol("pRate");
               \$("#ifProfGrid").showCol("pHash");
           }
        });

        // Edit button
        \$("#ifProfGrid").jqGrid('navButtonAdd','#pifProfGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#ifProfGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "profile");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#ifProfGrid").jqGrid('navButtonAdd','#pifProfGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             var selid = jQuery("#ifProfGrid").jqGrid('getGridParam','selrow');
             var selcur = jQuery("#ifProfGrid").jqGrid('getRowData', selid);

             if (selid > 0) {
                var defGroup = selcur['Group'];
                rulesGrid = cloneRow(jQuery("#ifProfGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "profile", defGroup);
                newRow = updnewRow();

                if (myDataGrid.length > 0) {
                   mkMyDataGrid();
                   selid++;
                   jQuery("#ifProfGrid").jqGrid('setRowData',selid,false,{color:'Navy'});
                   setPos(jQuery("#ifProfGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
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
           rulesGrid = delRow(jQuery("#ifProfGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();

           if (myDataGrid.length > 0) {
              mkMyDataGrid();
              selid = updselidFind();
              setPos(jQuery("#ifProfGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
           }

           var find=0;
           var selgroup = document.getElementById('selGroup');
           allPolicies=updGrp();
           for (var i=2; i<selgroup.length && allPolicies.length > 0; i++) {
              find=0;
              for (j=0;j<allPolicies.length && find==0; j++) if (selgroup.options[i].value === allPolicies[j] && rulesGrid.length > 0) find=1;
              if (find == 0) {
                 selgroup.remove(i);
                 saveall=1;
                 break;
              }
           }
        });

        \$("#ifProfGrid").jqGrid('navButtonAdd','#pifProfGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             var selid = jQuery("#ifProfGrid").jqGrid('getGridParam','selrow');
             var gridrules = jQuery("#ifProfGrid").jqGrid('getDataIDs').length;

             var defGroup = document.getElementById('selGroup').value;
             if (selid && gridrules > 0) {
                var clret = jQuery("#ifProfGrid").jqGrid('getRowData', selid);
                defGroup = clret['Group'];
             }

             if (defGroup !== "any") {
                rulesGrid = addRow(jQuery("#ifProfGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "profile", defGroup, "");
                newRow = updnewRow();

                if (myDataGrid.length > 0) {
                   mkMyDataGrid();

                   selid++;
                   jQuery("#ifProfGrid").jqGrid('setRowData',selid,false,{color:'Navy'});
                   setPos(jQuery("#ifProfGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
                   jQuery("#ifProfGrid").editRow(selid, true);
                }
             }
javascript
$msg[0] = "Selecione um perfil válido!";
$msg[1] = "Select a valid profile!";
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
           var selid = \$("#ifProfGrid").jqGrid('getGridParam','selrow');
           var edited = 0;
           var defGroup = "default";

           if (newRow.length > 0) edited = chkRow(jQuery("#ifProfGrid"), 0, rulesGrid, newRow);
           if (edited == 1) {
              alert("$medited[$FW_LANG]");
              return 1;
           }
           if (!selid) selid = 1;
           rulesGrid=GridComplete(jQuery("#ifProfGrid"), rulesGrid, 1, 0, "profile");
           if (document.getElementById('chkSearch').checked == true) searchGrid();
           else {
              var find=0;
              if (!selid) selid = 1;
              defGroup = document.getElementById('selGroupType').value;
              if (document.getElementById('selGroupType').value != "default") defGroup = defGroup+">"+document.getElementById('newGroupValue').value;
              else defGroup = document.getElementById('newGroupValue').value;
              if (rulesGrid.length < 1) allPolicies.length = 0;
              else allPolicies=updGrp();
              for (var i=0; i<allPolicies.length; i++) {
                  if (allPolicies[i].replace(/((limit|vpn|mangle)>|\\?chk=.*)/, "") == defGroup) {
                     find=1;
                     i=allPolicies.length;
                  }
              }
javascript
$msg[0] = "ERRO: Esta política já existe!";
$msg[1] = "ERROR: This policy already exists!";
print FILE << "javascript";
               if (find == 0 && defGroup !== "") {
                  document.fiprof.pgroupls.options[document.fiprof.pgroupls.length] = new Option(defGroup, defGroup, false, false);
                  for (var i=selid-1; i<rules; i++) {
                     if ((i < rules-1 && (rulesGrid[i]['Group'] !== rulesGrid[i+1]['Group'])) || i == rules-1) {
                        selid=i+1;
                        jQuery("#ifProfGrid").setSelection(selid, true);
                        i=rules;
                     }
                  }
                  rulesGrid = addRow(jQuery("#ifProfGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "profile", defGroup, "");
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
                     jQuery("#ifProfGrid").jqGrid('setRowData',selid,false,{color:'Navy'});
                     setPos(jQuery("#ifProfGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
                     jQuery("#ifProfGrid").editRow(selid, true);
                  }
               }
               else alert("$msg[$FW_LANG]");
            }
        });

        // Select policy
        jQuery("#selGroup").change(function(){
           var rules = rulesGrid.length;
           var gridrules = jQuery("#ifProfGrid").jqGrid('getDataIDs').length;
           var canAdd = document.getElementById('GroupAdd').checked;

           var selPolicy  = \$(this).val();
           if (selPolicy == "-1") return 1;
           selPolicy = selPolicy.replace(/[\\s]+chk=.*/, "");
           document.getElementById('polValue').value = selPolicy;

           if (selPolicy) {
              if (newRow.length > 0) {
                 if (chkRow(jQuery("#ifProfGrid"), 0, rulesGrid, newRow) == 1) {
                    alert("$medited[$FW_LANG]");
                    return 1;
                 }
                 newRow = updnewRow();
                 saveall = 1;
              }
           }
           else return 1;

           if (selPolicy !== "any") {
              var fdPol = 0;

              myRules = myDataGrid.length;
              if (canAdd !== true) {
                 myRules = 0;
                 myDataGrid.length = 0;
                 myPolicies.length = 0;
              }
              else {
                 allPolicies=updGrp();
                 for (var i=0; i<allPolicies.length && myDataGrid.length > 0; i++) {
                     if (allPolicies[i].replace(/[\\s]+chk=.*/, "") === selPolicy) {
                        fdPol = 1;
                        i = allPolicies.length;
                     }
                     else if (allPolicies[i].replace(/[\\s]+chk=.*/, "") === myDataGrid[myDataGrid.length-1]['Group'].replace(/[\\s]+chk=.*/, "")) i = allPolicies.length;
                 }

                 for (var i=0; i<myRules && fdPol == 0; i++) {
                    var curRol = myDataGrid[i];
                    var curPol = curRol['Group'];
                    curPol = curPol.replace(/\\?chk=.*/, "");
                    if (curPol == selPolicy) {
                       fdPol = 1;
                       i = myRules;
                    }
                 }
              }

              if (!fdPol) {
                 var curId = buildMyData(selPolicy, rules, myRules);
                 myPolicies.push(selPolicy);

                 if (myDataGrid[myDataGrid.length-1]) {
                    curId = myDataGrid[myDataGrid.length-1]['id'];
                    if (canAdd !== true) \$('#ifProfGrid').jqGrid('clearGridData');
                    \$("#ifProfGrid").setGridParam({ rowNum:curId });

                    refreshGroup(jQuery("#ifProfGrid"), myDataGrid, myDataGrid.length, curId);
                    jQuery("#ifProfGrid").setSelection(curId, true);
javascript
$msg[0] = "Política selecionada: ";
$msg[1] = "Selected policy: ";
print FILE << "javascript";
                    alert("$msg[$FW_LANG]"+selPolicy);
javascript
$msg[0] = "Política não encontrada: ";
$msg[1] = "Policy not found: ";
print FILE << "javascript";
                 }
                 else alert("$msg[$FW_LANG]"+selPolicy);
              }
           }
           else {
              myDataGrid.length=0;
              myPolicies.length=0;
              refreshGroup(jQuery("#ifProfGrid"), rulesGrid, rules, 1);
              jQuery("#ifProfGrid").setSelection(1, true);
           }
        });

        // Change Policy condition
        jQuery("#chCond").click( function() {
           var selid = \$("#ifProfGrid").jqGrid('getGridParam','selrow');
           chGroupCond(jQuery("#ifProfGrid"), rulesGrid, document.fchcond.idcond.value);
           if (myDataGrid.length > 0) {
              mkMyDataGrid();
              setPos(jQuery("#ifProfGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
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
           var selid = \$("#ifProfGrid").jqGrid('getGridParam','selrow');
           if (nlen > 0) edited = chkRow(jQuery("#ifProfGrid"), 0, rulesGrid, newRow);
           if (edited == 0) {
              if (myDataGrid.length > 0 && saveall < 1) {
                 if (nlen > 0) mkMyDataGrid();
                 gridData = myDataGrid;
              }
              else if (gridData.length > 0) gridData[0]['Control']="all";

              saveAll(jQuery("#ifProfGrid"), gridData, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "profile", "/admin/getprofile.json", "/admin/chprofile.cgi");
              newRow = updnewRow();

              if (newRow.length < 1 && myDataGrid.length < 1) {
                 rulesCt = 0;
                 refreshGroup(jQuery("#ifProfGrid"), gridData, gridData.length, selid);
              }
           }
           else alert("$medited[$FW_LANG]");
        });

        // Grid resize
        \$(window).bind('resize', function() {
            \$("#jqgrid").setGridWidth(\$(window).width() - 120);
        }).trigger('resize');

    });
  </script>

<script type="text/javascript">
<!--

function chkpol() {
    if (document.getElementById('chkSearch').checked == true) {
javascript
$msg[0] = "Pesquisar";
$msg[1] = "Search";
print FILE "       document.fiprof.CtGP.value = \"$msg[$FW_LANG]\";\n";
print FILE << "javascript";
       document.fiprof.pgroupls.disabled = true;
    }
    else {
javascript
$msg[0] = "Criar";
$msg[1] = "Create";
print FILE "      document.fiprof.CtGP.value = \"$msg[$FW_LANG]\";\n";
print FILE << "javascript";
      document.fiprof.pgroupls.disabled = false;
    }
}

//-->
</script>\n\n
javascript

    my $srcfs = "";
    if ($canch == 0) {
       $msg[0] = "Somente leitura (nó escravo)!";
       $msg[1] = "Read-only (slave node)!";
       $srcfs = "<h5><FONT color=\"Red\"><strong>$msg[$FW_LANG]</strong></FONT></h5>";
    }

    $msg[0] = "Funções globais: Configura&ccedil;&otilde;es de perfil";
    $msg[1] = "Global functions: Profile settings";
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
   print FILE "<FORM name=\"fiprof\" action=\"/admin/chprofile.cgi\" method=\"post\">";
   print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
   print FILE "<tbody><TR valign=\"bottom\"><TD width=\"96%\">";
   print FILE "<FONT size=\"-1\"><p>";
   print FILE "<SELECT id='selGroup' name='pgroupls' style='width:180px; font-size:small;'>";
   ## read policies...
   print FILE "<OPTION value=\"-1\" selected>--- $policy[$FW_LANG] ---</OPTION>";
   print FILE "<OPTION value=\"any\">any</OPTION>";
   foreach (@fwltprof,@fwprof) {
     $_ =~ s/:/>/;
     $_ =~ s/\?chk=.*//;
     if ($_ !~ /^(rsquid|vpop3)$/) {
        my $auxdesc = $_;
        $auxdesc =~ s/[ |\t]+chk=.*/\xC2\xA0\xC2\xA0 ?/;
        print FILE "<OPTION value=\"$_\">$auxdesc</OPTION>" if ($_ ne "any");
     }
   }
   print FILE "<OPTION value=\"rsquid\">rsquid</OPTION>";
   print FILE "<OPTION value=\"vpop3\">vpop3</OPTION>";
   print FILE "</SELECT>";
   print FILE "&nbsp; <SELECT id='selGroupType' style='width:140px; font-size:small;'>";
   print FILE "<OPTION value=\"default\">default</OPTION>";
   print FILE "<OPTION value=\"mangle\">vpn|mangle</OPTION>";
   print FILE "<OPTION value=\"limit\">limit</OPTION>";
   print FILE "</SELECT>";
   print FILE " &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; ";
   $msg[0] = "Criar";
   $msg[1] = "Create";
   print FILE "<INPUT type=\"button\" id=\"newGroupPol\" name=\"CtGP\" value=\"$msg[$FW_LANG]\" style=\"Font-Family: Arial, Helvetica;\"> ";
   print FILE "<INPUT type=\"text\" id=\"newGroupValue\" name=\"polgroup\" size=\"15\" style=\"background-color: #bec2c8; Font-Family: Arial, Helvetica; height:24px;\" onkeydown=\"if (event.keyCode == 13) { document.fiprof.CtGP.click(); return false; }\">";
   print FILE " &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; ";
   $msg[0] = "Unir";
   $msg[1] = "Join";
   print FILE "<i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"GroupAdd\" name=\"CkPolAdd\">";
   print FILE " &nbsp; &nbsp; ";
   $msg[0] = "Pesquisar";
   $msg[1] = "Search";
   print FILE "<i>$msg[$FW_LANG]</i>";
   print FILE "<INPUT type=\"checkbox\" id=\"chkSearch\" name=\"CkSearch\" onclick=\"return chkpol();\">";
   $msg[0] = "Alterar";
   $msg[1] = "Change";
   print FILE " &nbsp; &nbsp; <i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"mvPol\" name=\"CkMvPol\">";
   print FILE "</FONT></p>\n";
   print FILE << "HTMLCODE";
   <table id="ifProfGrid" width="100%" style="font-size:12px;"></table>
   <div id="pifProfGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
   print FILE "</TD><TD width=\"4%\" align=\"left\">";
   print FILE "&nbsp;<a href=\"javascript: document.fprof.gdmoveup.click();\">";
   print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
   print FILE "&nbsp;<a href=\"javascript: document.fprof.gdmovedown.click();\">";
   print FILE "<img src=\"buttons/mv_down.png\" style=\"border: 0px solid ;\"></a><BR />";
   print FILE "</TD></TR></tbody></table>";
   print FILE "<INPUT type=\"submit\" name=\"ReloadFw\" value=\"Reload firewall rules\" style=\"visibility:hidden; position:absolute;\">";
   print FILE "<INPUT type=\"text\" id=\"polValue\" name=\"pgroup\" size=\"15\" style=\"visibility:hidden; position:absolute;\">";
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
    <form name="fprof">
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
