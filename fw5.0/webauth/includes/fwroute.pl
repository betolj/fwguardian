#!/usr/bin/perl

#Rev.1 - Version 5.0

# "POST /admin/chroute.cgi" -> delete or add button
sub chroute {
    my $s = shift;

    my $rlfw = 0;
    my $canSync = 0;
    my $saveall = 0;
    my @policies = ();
    my $txtvalue = "";
    my @msg = ("", ""), @msg2 = ("", "");
    my $res = HTTP::Response->new();
    read_fwrules("route");

    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && $canch == 1) {

       # Parsing json response
       my %json = ();
       my %polData = ();
       my %polName = ();
       my $curPol = "";
       my $lastpolicy = "";
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
                if ($dvalue[1] && $dvalue[1] ne "none") {
                   if ($dvalue[0] eq "fwTarg" || $dvalue[0] eq "rtIf" || $dvalue[0] eq "rtIfOut") {
                      if ($dvalue[0] eq "rtIfOut" && $dvalue[1] ne "any") {
                         $json{'rtIf'} =~ s/[\s]+$//;
                         $json{'rtIf'} = "$json{'rtIf'}\->$dvalue[1]";
                         $json{'rtIf'} = pack( 'A20', str_conv($json{'rtIf'}) );
                      }
                      else {
                         $dvalue[1] = "RETURN" if ($dvalue[0] eq "fwTarg" && $dvalue[1] eq "IGNORE");
                         $json{$dvalue[0]} = pack( 'A20', str_conv($dvalue[1]) );
                      }
                   }
                   else {
                      if ($dvalue[0] eq "Cond") {
                         $json{'Cond'} = "chk=$dvalue[1]";
                      }
                      elsif ($dvalue[0] eq "fNew") {
                         $json{'fNew'} = "new" if ($dvalue[1] eq "Yes");
                         $json{'fNew'} = "nonew" if ($dvalue[1] eq "No");
                      }
                      elsif ($dvalue[0] =~ /^rt(Guaran|State|Track)$/ || $dvalue[0] eq "NatType") {
                         $json{$dvalue[0]} = "";
                         if ($dvalue[0] eq "rtGuaran") { $json{$dvalue[0]} = "guaranteed" if ($dvalue[1] eq "Yes"); }
                         elsif ($dvalue[0] eq "rtState") { $json{$dvalue[0]} = "stateless" if ($dvalue[1] eq "Yes"); }
                         elsif ($dvalue[0] eq "rtTrack") { $json{$dvalue[0]} = "notrack" if ($dvalue[1] eq "No"); }
                         elsif ($dvalue[0] eq "NatType") { $json{$dvalue[0]} = $dvalue[1]; }
                      }
                      elsif ($dvalue[0] =~ /^(proto|sport|dport|Group|Desc)$/) {
                         $dvalue[1] =~ s/>/:/ if ($dvalue[0] eq "Group" && $dvalue[1] =~ /^(filter|auth|rtsec)>/);
                         $json{$dvalue[0]} = str_conv($dvalue[1]);
                      }
                      elsif ($dvalue[0] eq "Control") {
                         $saveall = 1 if ($dvalue[1] eq "all");
                         $saveall = 2 if ($dvalue[1] eq "set");
                      }
                      else {
                         $json{$dvalue[0]} = pack( 'A35', str_conv($dvalue[1]) ) if ($dvalue[1] !~ /^[\s]*$/);
                      }
                   }
                }
             }
             if (($json{'Group'} ne "" && $json{'rtIf'} ne "" && $json{'Src'} ne "" && $json{'Dst'} ne "") || $saveall == 2) {
                # FORWARD rule
                $canSync = 1;
                my $auxentry = "$json{'rtIf'} $json{'Src'} $json{'Dst'}";
                  $auxentry = "$auxentry $json{'fwTarg'}"  if ($json{'fwTarg'});
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
                  $auxentry = "$auxentry $json{'fNew'}" if ($json{'fNew'});
                  $auxentry = "$auxentry $json{'rtGuaran'}" if ($json{'rtGuaran'});
                  $auxentry = "$auxentry $json{'rtState'}" if ($json{'rtState'});
                  if ($json{'NatType'}) { 
                     $json{'NatType'} = "autosnat" if ($json{'NatType'} eq "AUTO");
                     $json{'NatType'} = "masq" if ($json{'NatType'} eq "MASQ");
                     $auxentry = "$auxentry $json{'NatType'}";
                  }
                  else { $auxentry = "$auxentry $json{'rtTrack'}" if ($json{'rtTrack'}); }
                  $auxentry = "$auxentry $json{'Cond'}" if ($json{'Cond'});
                  $auxentry = "$auxentry log-desc=\"$json{'fLog'}\"" if (length($json{'fLog'}) gt 1);
                  $auxentry = "$auxentry desc=\"$json{'Desc'}\"" if (length($json{'Desc'}) > 1);

                # policy rules
                $curPol = $json{'Group'};
                $curPol =~ s/\?chk=.*// if ($curPol =~ /\?chk=/);
                push(@{$polData{$curPol}}, $auxentry);
                $polName{$curPol} = $json{'Group'};
                $polName{$curPol} =~ s/\?chk=/ chk=/;

                # policies array
                $curPol = $json{'Group'};
                push(@policies, $json{'Group'}) if ($curPol ne $lastpolicy);
                $lastpolicy = $curPol;
             }
          }
       }

       if ($canSync == 1) {
          # Open fwroute.rules in write mode
          # - Remove set-alias
          # - You must use webalias for firewall aliases
          open FILE, ">$file_cfg{'routing/fwroute.rules'}";

          # Writing FORWARDED comments
          foreach my $rtRules (@routecomments) {
              $rtRules =~ s/\n//;
              $rtRules =~ s/\\"/\"/g;
              $rtRules =~ s/\\'/\'/g;
              print FILE "$rtRules\n" if ($rtRules);
          }

          # Writing FORWARDED set-policy rules
          $curPol = "";
          $lastpolicy = "";
          if ($saveall == 0) {
             @policies = @routefw;
             push(@policies, @gpauthfw);
          }
          foreach my $rtRules (@policies) {
              $rtRules =~ s/\n//;
              $rtRules =~ s/\\"/\"/g;
              $rtRules =~ s/\\'/\'/g;
              my ($ruPol, undef) = split(/[\s]+/, $rtRules, 2);
              my $auxpol = $ruPol;
              $ruPol =~ s/\?/\\?/;
              $rtRules =~ s/^(\s)*$ruPol(\s)+//;

              $curPol = $auxpol;
              $curPol =~ s/\?chk=.*//;
              $auxpol =~ s/\?chk=/ chk=/;
              if ($polData{$curPol}[0] || $saveall > 0) {
                 if ($curPol ne $lastpolicy && $auxpol ne "any") {
                    print FILE "\nset-policy $polName{$curPol}\n";
                    foreach my $auxentry (@{$polData{"$curPol"}}) {
                       print FILE "$auxentry\n";
                    }
                 }
              }
              else {
                 print FILE "\nset-policy $auxpol\n" if ($curPol ne $lastpolicy);
                 print FILE "$rtRules\n";
              }
              $lastpolicy = $curPol;
          }

          # Writing set-auth defs
          foreach my $rtRules (@gpset) {
             my $auxpol = $rtRules;
             $auxpol =~ s/\?chk=/ chk=/;
             print FILE "\nset-auth $auxpol";
             foreach my $aRules (@{$gpauthrule{"$rtRules"}}) {
                $aRules =~ s/\n//;
                $aRules =~ s/\\"/\"/g;
                $aRules =~ s/\\'/\'/g;
                print FILE "\n$aRules";
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
       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/fwroute.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}


# "Make web page fwroute.html"
sub get_fwroute {
    my $htmlfile="$HTMLDIR/admin/dynhttp/fwroute.html";
    read_profiles;
    read_fwrules("route");

    my @msg = ("", "");
    my @policy = ("", "");
    $policy[0] = "Politica";
    $policy[1] = "Policy";
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making fwroute.html
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
                 fRouteGrid.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.froute.pgroupls.disabled = false;
                 document.froute.pgroupls.options[0].selected = true;
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 fRouteGrid.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.froute.ReloadFw.click();
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
        var rulesCt = 0;
        var myPolicies = new Array();        // Current myDataGrid policies
        var allPolicies = new Array();       // Current rulesGrid policies
        var rulesGrid = new Array();         // Main data
        var myDataGrid = new Array();        // Selected group data
        var newRow = new Array();
        var saveall = 0;

        // Make jqgrid
        var scrollPosition = 0;
        jQuery("#fwRouteGrid").jqGrid({
           url:'/admin/getroute.json',
           datatype: "json",
           height: \$(window).height() - 270,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'Politica', 'Int (Ori)', 'Origem', 'Int (Dest)', 'Destino', 'Alvo', 'Proto', 'Porta de origem', 'Porta de destino', 'Novo', 'Garantido', 'Stateless', 'Tracking', 'Condição', 'SNAT', 'log', 'Descrição', 'Control', 'arrId' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'Policy', 'Int (Src)', 'Source', 'Int (Dst)', 'Destination', 'Target', 'Proto', 'Source port', 'Destination port', 'New', 'Guaranteed', 'Stateless', 'Tracking', 'Condition', 'SNAT', 'log', 'Description', 'Control', 'arrId' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id', sortable:false, sorttype: "int", key: true, width:30 },
              { name:"Group",   index:'Group',   hidden:true,  width:30,
                 formatter: function (cellval, opts, rowObject, action) {
                     var groupIdPrefix = opts.gid + "ghead_",
                         groupIdPrefixLength = groupIdPrefix.length;

                     var fwtrigger = /(^(filter|auth)\>|\\?chk=)/;
                     if (opts.rowId.substr(0, groupIdPrefixLength) === groupIdPrefix && typeof action === "undefined") {
                        return (fwtrigger.test(cellval) ? ('<span class="ui-icon ui-icon-alert" style="float: left;"></span>' + '<span style="color:#800000; margin-left: 5px;">') : "<span>") + cellval + '</span>';
                     }
                     return cellval;
                 }
              },
javascript
$msg[0] = selGridifnet("net");
my $rtalias = $msg[0];
$msg[0] = selGridifnet("if");
print FILE "              { name:\"rtIf\",    index:'rtIf',  sortable:false, editable:true, edittype:\"select\", editoptions:{value:\"$msg[0]\"}, width:78 },\n";
print FILE "              { name:\"Src\",     index:'Src',   sortable:false, editable:true, width:140 },\n";
print FILE "              { name:\"rtIfOut\", index:'rtIfOut', sortable:false, editable:true, edittype:\"select\", editoptions:{value:\"$msg[0]\"}, width:78 },\n";
print FILE "              { name:\"Dst\",     index:'Dst',     sortable:false, editable:true, width:140 },\n";
    $msg[0] = "%A:ACCEPT;%D:DROP;%R:REJECT;FILTER:FILTER;IGNORE:IGNORE";
    foreach (@fwprof,@fwltprof) {
       $_ =~ s/\n//;
       $_ =~ s/.*://;
       if ($_ !~ /chk=disabled$/) {
          $_ =~ s/\?chk=.*//;
          my $line = "$_:$_";
          $msg[0] = "$msg[0];$line" if ($_ !~ /^[\s]*(mangle:|rsquid|vpop3)/);
       }
    }
    $msg[0] = "$msg[0];SYNPROXY:SYNPROXY" if (-e "/usr/share/fwguardian/sproxy.forward.ctl");
    $msg[0] = "$msg[0];IPS:IPS" if (-e "/etc/suricata/suricata.yaml" || -e "/etc/suricata/suricata-debian.yaml");
print FILE "{ name:\"fwTarg\",  index:'fwTarg', sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:120 },\n";
print FILE << "javascript";
              { name:"proto",  index:'proto', sortable:false, editable:true, edittype:"select", editoptions:{value:"any:any;tcp:tcp;udp:udp;icmp:icmp;gre:gre;ah:ah;esp:esp;ospf:ospf;vrrp:vrrp;ipp2p:ipp2p"}, width:70 },
              { name:"sport",    index:'sport',  sortable:false, editable:true, hidden:true, width:162 },
              { name:"dport",    index:'dport',  sortable:false, editable:true, width:162 },
              { name:"fNew",     index:'fNew',    sortable:false, editable:true, edittype:"select", editoptions:{value:"none:none;Yes:Yes;No:No"}, width:60 },
              { name:"rtGuaran", index:'rtGuaran', sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, width:68 },
              { name:"rtState",  index:'rtState',  sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, hidden:true, width:68 },
              { name:"rtTrack",  index:'rtTrack',  sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, hidden:true, width:68 },
javascript
    $msg[0] = "none:none;disabled:disabled";
    foreach (@fwchk) {
       $_ =~ s/\n//;
       my $line = "$_:$_";
       $msg[0] = "$msg[0];$line";
    }
print FILE "{ name:\"Cond\",   index:'Cond',  sortable:false, editable:true, edittype:'select', editoptions:{value:\"$msg[0]\"}, width:120 },\n";
print FILE << "javascript";
              { name:"NatType", index:'NatType', sortable:false, editable:true, edittype:'select', editoptions:{value:"none:none;MASQ:MASQ;AUTO:AUTO"}, hidden:true, width:70 },
              { name:"fLog",   index:'fLog',  sortable:false, editable:true, dataType:'string', width:250 },
              { name:"Desc",   index:'Desc',  sortable:false, editable:true, dataType:'string', width:320 },
              { name:"Control", index:'Control', sortable:false, editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 },
              { name:"arrId",  index:'arrId', sortable:false, editable:true, hidden:true, editoptions:{size:"5", maxlength:"5"}, width:5 }
           ],
           pager: '#pfwRouteGrid',
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
                 var selcur = jQuery("#fwRouteGrid").jqGrid('getRowData', selid);
                 var curPol = selcur['Group'];
                 var frPol = /\\?chk=/;
                 if (frPol.test(curPol)) curPol = curPol.replace(/.*\\?chk=/, "");
                 else curPol = "";

                 document.fchcond.idcond.value = curPol;
                 document.getElementById('chcondition').style.display = 'block';
              }
              else {
                 editRow(jQuery("#fwRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$rtalias", "fwroute");
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
              rulesGrid=GridComplete(jQuery("#fwRouteGrid"), rulesGrid, rulesCt, saveall, "fwroute");

              rulesCt++;
              jQuery("#fwRouteGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Trafego encaminhado pelo Firewall (FORWARD)";
$msg[1] = "Traffic forwarded by Firewall (FORWARD)";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#fwRouteGrid").css('font-size', '13px');
        jQuery("#fwRouteGrid").jqGrid('navGrid',"#pfwRouteGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Search function
        function searchGrid() {
           var gridid = jQuery("#fwRouteGrid");
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
           var st_field = new Array("Src","Dst","dport","Desc");

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
           setPos(gridid, selid, getGroups(dataGrid[selid-1], myPolicies));
        }

        // Make myDataGrid
        function mkMyDataGrid() {
           var curId = 0;
           myDataGrid.length=0;
           for (var i=0; i<myPolicies.length; i++) curId = buildMyData(myPolicies[i], rulesGrid.length, curId);
           refreshGroup(jQuery("#fwRouteGrid"), myDataGrid, myDataGrid.length, curId);
        }

        // Moveup row function
        jQuery("#gdUp").click( function() {
           var it=1;
           var doId=0;
           var myRules = myDataGrid.length;
           var selid = jQuery("#fwRouteGrid").jqGrid('getGridParam','selrow');
           var selcur = jQuery("#fwRouteGrid").jqGrid('getRowData', selid);

           var mvPol=0;
           if (document.getElementById('mvPol').checked == true) {
              mvPol=1;
              var auxcur = selcur['Group'];
              auxcur = auxcur.replace(/\\?chk=.*/, "");
              if (myPolicies.length > 0) {
                 if (myPolicies[0] !== auxcur && myPolicies.length > 1) {
                    for (var i=0; i<myPolicies.length; i++) {
                       if (auxcur === myPolicies[i]) {
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

           rulesGrid = mvUp(jQuery("#fwRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwroute", it);
           newRow = updnewRow();
           doReload = upddoReload();

           if (mvPol == 1) {
              selid=updselidGrp();
              if (myRules < 1) {
                 it=0;
                 refreshGroup(jQuery("#fwRouteGrid"), rulesGrid, rulesGrid.length, selid);
              }
              doId=1;
              saveall=1;
           }
           if (myRules > 0 && it > 0) {
              doId=1;
              mkMyDataGrid();
           }
           if (doId) setPos(jQuery("#fwRouteGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           var it=1;
           var doId=0;
           var myRules = myDataGrid.length;
           var selid = jQuery("#fwRouteGrid").jqGrid('getGridParam','selrow');
           var selcur = jQuery("#fwRouteGrid").jqGrid('getRowData', selid);

           var mvPol=0;
           if (document.getElementById('mvPol').checked == true) {
              mvPol=1;
              var auxcur = selcur['Group'];
              auxcur = auxcur.replace(/\\?chk=.*/, "");
              if (myPolicies.length > 0) {
                 if (myPolicies[myPolicies.length-1] !== auxcur && myPolicies.length > 1) {
                    for (var i=0; i<myPolicies.length; i++) {
                       if (auxcur === myPolicies[i]) {
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

           rulesGrid = mvDown(jQuery("#fwRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwroute", it);
           newRow = updnewRow();
           doReload = upddoReload();

           if (mvPol == 1) {
              selid = updselidGrp();
              if (myRules < 1) {
                 it=0;
                 refreshGroup(jQuery("#fwRouteGrid"), rulesGrid, rulesGrid.length, selid);
              }
              doId=1;
              saveall=1;
           }
           if (myRules > 0 && it > 0) {
              doId=1;
              mkMyDataGrid();
           }
           if (doId) setPos(jQuery("#fwRouteGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
        });

        // Advanced
        \$("#fwRouteGrid").jqGrid('navButtonAdd','#pfwRouteGrid',{
javascript
$msg[0] = "*Avançado ";
$msg[1] = "*Advanced ";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
               \$("#fwRouteGrid").showCol("sport");
               \$("#fwRouteGrid").showCol("rtState");
               \$("#fwRouteGrid").showCol("rtTrack");
               \$("#fwRouteGrid").showCol("NatType");
           }
        });

        // Edit button
        \$("#fwRouteGrid").jqGrid('navButtonAdd','#pfwRouteGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#fwRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$rtalias", "fwroute");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#fwRouteGrid").jqGrid('navButtonAdd','#pfwRouteGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             var selid = jQuery("#fwRouteGrid").jqGrid('getGridParam','selrow');
             var selcur = jQuery("#fwRouteGrid").jqGrid('getRowData', selid);

             rulesGrid = cloneRow(jQuery("#fwRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwroute", selcur['Group']);
             newRow = updnewRow();

             if (myDataGrid.length > 0) {
                mkMyDataGrid();
                selid++;
                jQuery("#fwRouteGrid").jqGrid('setRowData',selid,false,{color:'Navy'});
                setPos(jQuery("#fwRouteGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
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
           rulesGrid = delRow(jQuery("#fwRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();

           if (myDataGrid.length > 0) {
              mkMyDataGrid();
              selid = updselidFind();
              setPos(jQuery("#fwRouteGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
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

        \$("#fwRouteGrid").jqGrid('navButtonAdd','#pfwRouteGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             var selid = jQuery("#fwRouteGrid").jqGrid('getGridParam','selrow');
             var gridrules = jQuery("#fwRouteGrid").jqGrid('getDataIDs').length;

             var defGroup = "default";
             if (!selid) selid = 1;
             if (selid && gridrules > 0) {
                var clret = jQuery("#fwRouteGrid").jqGrid('getRowData', selid);
                defGroup = clret['Group'];
             }

             rulesGrid = addRow(jQuery("#fwRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwroute", defGroup, "$rtalias");
             newRow = updnewRow();

             if (myDataGrid.length > 0) {
                mkMyDataGrid();

                selid++;
                jQuery("#fwRouteGrid").jqGrid('setRowData',selid,false,{color:'Navy'});
                setPos(jQuery("#fwRouteGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
                jQuery("#fwRouteGrid").editRow(selid, true);
             }
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
            var selid = \$("#fwRouteGrid").jqGrid('getGridParam','selrow');
            var edited = 0;
            var defGroup = "";

            if (newRow.length > 0) edited = chkRow(jQuery("#fwRouteGrid"), 0, rulesGrid, newRow);
            if (edited == 1) {
               alert("$medited[$FW_LANG]");
               return 1;
            }
            if (!selid) selid = 1;
            rulesGrid=GridComplete(jQuery("#fwRouteGrid"), rulesGrid, 1, 0, "fwroute");
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
                   if (allPolicies[i].replace(/\\?chk=.*/, "") == defGroup) {
                      find=1;
                      i=allPolicies.length;
                   }
               }
javascript
$msg[0] = "ERRO: Esta política já existe!";
$msg[1] = "ERROR: This policy already exists!";
print FILE << "javascript";
               if (find == 0 && defGroup !== "") {
                  document.froute.pgroupls.options[document.froute.pgroupls.length] = new Option(defGroup, defGroup, false, false);
                  for (var i=selid-1; i<rules; i++) {
                     if ((i < rules-1 && (rulesGrid[i]['Group'] !== rulesGrid[i+1]['Group'])) || i == rules-1) {
                        selid=i+1;
                        jQuery("#fwRouteGrid").setSelection(selid, true);
                        i=rules;
                     }
                  }
                  rulesGrid = addRow(jQuery("#fwRouteGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwroute", defGroup);
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
                     jQuery("#fwRouteGrid").jqGrid('setRowData',selid,false,{color:'Navy'});
                     setPos(jQuery("#fwRouteGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
                     jQuery("#fwRouteGrid").editRow(selid, true);
                  }
               }
               else alert("$msg[$FW_LANG]");
            }
        });

        // Select policy
        jQuery("#selGroup").change(function(){
           var rules = rulesGrid.length;
           var gridrules = jQuery("#fwRouteGrid").jqGrid('getDataIDs').length;
           var canAdd = document.getElementById('GroupAdd').checked;

           var selPolicy  = \$(this).val();
           if (selPolicy == "-1") return 1;
           selPolicy = selPolicy.replace(/[\\s]+chk=.*/, "");

           if (selPolicy) {
              if (newRow.length > 0) {
                 if (chkRow(jQuery("#fwRouteGrid"), 0, rulesGrid, newRow) == 1) {
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
                     if (allPolicies[i].replace(/\\?chk=.*/, "") === selPolicy) {
                        fdPol = 1;
                        i = allPolicies.length;
                     }
                     else if (allPolicies[i].replace(/\\?chk=.*/, "") === myDataGrid[myDataGrid.length-1]['Group'].replace(/\\?chk=.*/, "")) i = allPolicies.length;
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

                 curId = myDataGrid[myDataGrid.length-1]['id'];
                 if (canAdd !== true) \$('#fwRouteGrid').jqGrid('clearGridData');
                 \$("#fwRouteGrid").setGridParam({ rowNum:curId });

                 refreshGroup(jQuery("#fwRouteGrid"), myDataGrid, myDataGrid.length, curId);
                 jQuery("#fwRouteGrid").setSelection(curId, true);
javascript
$msg[0] = "Política selecionada: ";
$msg[1] = "Selected policy: ";
print FILE "                 alert(\"$msg[$FW_LANG]\"+selPolicy);\n";
print FILE << "javascript";
              }
           }
           else {
              myDataGrid.length=0;
              myPolicies.length=0;
              refreshGroup(jQuery("#fwRouteGrid"), rulesGrid, rules, 1);
              jQuery("#fwRouteGrid").setSelection(1, true);
           }
        });

        // Change Policy condition
        jQuery("#chCond").click( function() {
           var selid = \$("#fwRouteGrid").jqGrid('getGridParam','selrow');
           chGroupCond(jQuery("#fwRouteGrid"), rulesGrid, document.fchcond.idcond.value);
           if (myDataGrid.length > 0) {
              mkMyDataGrid();
              setPos(jQuery("#fwRouteGrid"), selid, getGroups(rulesGrid[selid-1], myPolicies));
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
           var selid = \$("#fwRouteGrid").jqGrid('getGridParam','selrow');
           if (nlen > 0) edited = chkRow(jQuery("#fwRouteGrid"), 0, rulesGrid, newRow);
           if (edited == 0) {
              if (myDataGrid.length > 0 && saveall < 1) {
                 if (nlen > 0) mkMyDataGrid();
                 gridData = myDataGrid;
              }
              else if (gridData.length > 0) gridData[0]['Control']="all";

              saveAll(jQuery("#fwRouteGrid"), gridData, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "fwroute", "/admin/getroute.json", "/admin/chroute.cgi");
              newRow = updnewRow();

              if (newRow.length < 1 && myDataGrid.length < 1) {
                 rulesCt = 0;
                 refreshGroup(jQuery("#fwRouteGrid"), gridData, gridData.length, selid);
              }
           }
           else alert("$medited[$FW_LANG]");
        });

        \$("#fwRouteGrid").jqGrid('navButtonAdd','#pfwRouteGrid',{
           caption:"&nbsp; Info",
           onClickButton:function(){
             var selid = jQuery("#fwRouteGrid").jqGrid('getGridParam','selrow');
             var clret = jQuery("#fwRouteGrid").jqGrid('getRowData', selid);
             if (clret['Desc'] !== "") alert(clret['Desc']);
           }
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
print FILE "       document.froute.CtGP.value = \"$msg[$FW_LANG]\";\n";
print FILE << "javascript";
       document.froute.pgroupls.disabled = true;
    }
    else {
javascript
$msg[0] = "Criar";
$msg[1] = "Create";
print FILE "      document.froute.CtGP.value = \"$msg[$FW_LANG]\";\n";
print FILE << "javascript";
      document.froute.pgroupls.disabled = false;
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

    my $auxdesc;
    $msg[0] = "Filtro de pacotes: Traf. Encaminhado (FORWARD)";
    $msg[1] = "Packet filter: Routing access (FORWARD)";
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

    # Grid rules
    print FILE "<FORM name=\"froute\" action=\"/admin/chroute.cgi\" method=\"POST\">";
    print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
    print FILE "<tbody><TR valign=\"bottom\"><TD width=\"96%\">";
    print FILE "<font size=\"-1\"><p>";
    print FILE "<SELECT id='selGroup' name='pgroupls' style='width:180px; font-size:small;'>";
    ## read policies...
    print FILE "<OPTION value=\"-1\" selected>--- $policy[$FW_LANG] ---</OPTION>";
    print FILE "<OPTION value=\"any\">any</OPTION>";
    foreach (@routefwtab, @gpauthfwtab) {
      $_ =~ s/:/>/;
      $_ =~ s/(set-policy[ |\t]|\n)//g if ($_ =~ /(set-policy|\n)/);
      my $auxdesc = $_;
      $auxdesc =~ s/[ |\t]+chk=.*/\xC2\xA0\xC2\xA0 ?/;
      print FILE "<OPTION value=\"$_\">$auxdesc</OPTION>" if ($_ ne "any");
    }
    print FILE "</SELECT>";
    print FILE "&nbsp; <SELECT id='selGroupType' style='width:80px; font-size:small;'>";
    print FILE "<OPTION value=\"default\">default</OPTION>";
    print FILE "<OPTION value=\"filter\">filter</OPTION>";
    print FILE "<OPTION value=\"rtsec\">rtsec</OPTION>";
    print FILE "<OPTION value=\"auth\">auth</OPTION>";
    print FILE "</SELECT>";
    print FILE " &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; ";
    $msg[0] = "Criar";
    $msg[1] = "Create";
    print FILE "<INPUT type=\"button\" id=\"newGroupPol\" name=\"CtGP\" value=\"$msg[$FW_LANG]\" style=\"Font-Family: Arial, Helvetica;\"> ";
    print FILE "<INPUT type=\"text\" id=\"newGroupValue\" name=\"polgroup\" size=\"15\" style=\"background-color: #bec2c8; Font-Family: Arial, Helvetica; height:24px;\" onkeydown=\"if (event.keyCode == 13) { document.froute.CtGP.click(); return false; }\">";
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
    print FILE " &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; ";
    $msg[0] = "Apelidos";
    $msg[1] = "Alias";
print FILE " <i>$msg[$FW_LANG]</i><INPUT type=\"checkbox\" id=\"enAlias\" name=\"CkenAlias\"></FONT></p>\n";
print FILE << "HTMLCODE";
    <table id="fwRouteGrid" width="100%" style="font-size:12px;"></table>
    <div id="pfwRouteGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
    print FILE "</TD><TD width=\"4%\">";
    print FILE "&nbsp;<a href=\"javascript: document.fRouteGrid.gdmoveup.click();\">";
    print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "&nbsp;<a href=\"javascript: document.fRouteGrid.gdmovedown.click();\">";
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
    <form name="fRouteGrid">
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
