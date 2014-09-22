#!/usr/bin/perl

#Rev.1 - Version 5.0

# "POST /admin/chmsncheck.cgi" -> save button (check options)
sub chmsncheck {
    my $s = shift;
    my $txtvalue = "";

    my $res = HTTP::Response->new();
    read_fwmsn;

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($canch == 1) {
       # Parsing json response
       my %json = ();
       my @auxname = ();
       my $isaddr = 0;
       my $scanSync = 0;
       $txtvalue = "NO";

       foreach my $auxjson (split /{/, $s) {
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
                if ($dvalue[1] && ($dvalue[0] eq "addr" || $dvalue[0] eq "proxy")) {
                   $isaddr = 1 if ($dvalue[0] eq "addr");
                   $json{$dvalue[0]} = str_conv($dvalue[1]) if ($dvalue[1] !~ /^[\s]*$/);
                }
             }
             if (($json{'addr'} ne "" && $isaddr == 1) || ($json{'proxy'} ne "" && $isaddr == 0)) {
                $canSync = 1;
                if ($isaddr == 1) {
                   push(@auxname, "$json{'addr'}") if ($json{'addr'} ne "_ignore_");
                }
                else {
                   push(@auxname, "$json{'proxy'}") if ($json{'proxy'} ne "_ignore_");
                }
             }
          }
       }

       if ($canSync == 1) {
          open FILE, ">$file_cfg{'fwmsn'}";
          if ($isaddr == 1) {
             @fwmsncheckaddr = @auxname;
          }
          else {
             @fwmsncheckproxy = @auxname;
          }

          # Writing fwmsn comments
          foreach my $msnRules (@fwmsncomments) {
              $msnRules =~ s/\n//;
              $msnRules =~ s/\\"/\"/g;
              $msnRules =~ s/\\'/\'/g;
              print FILE "$msnRules\n" if ($msnRules);
          }

          # Writing fwmsn check definitions
          print FILE "\n";
          foreach my $msnRules (@fwmsncheckaddr) {
              $msnRules =~ s/\n//;
              $msnRules =~ s/\\"/\"/g;
              print FILE "check.address $msnRules\n" if ($msnRules);
          }
          foreach my $msnRules (@fwmsncheckproxy) {
              $msnRules =~ s/\n//;
              $msnRules =~ s/\\"/\"/g;
              print FILE "check.proxy $msnRules\n" if ($msnRules);
          }

          # Writing fwmsn rules
          print FILE "\n";
          foreach my $msnRules (@fwmsnrules) {
              $msnRules =~ s/\n//;
              $msnRules =~ s/\\"/\"/g;
              print FILE "allow.login $msnRules\n" if ($msnRules);
          }

          close(FILE);
          $txtvalue="OK";

          rsyncupdate("$file_cfg{'fwmsn'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "POST /admin/chfwmsn.cgi" -> save button (grid rules)
sub chfwmsn {
    my $s = shift;

    my $rlfw = 0;
    my $canSync = 0;
    my $txtvalue = "";
    my @msg = ("", ""), @msg2 = ("", "");
    my $res = HTTP::Response->new();
    read_fwmsn;

    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && $canch == 1) {

       # Parsing json response (sorting by ID)
       my %json = ();
       my @unsortId = ();
       my %unsortData = ();
       $textvalue = "NO";

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
                    if ($dvalue[0] eq "Src") {
                       $json{$dvalue[0]} = pack( 'A18', str_conv($dvalue[1]) ) if ($dvalue[1] !~ /^[\s]*$/);
                    }
                    elsif ($dvalue[0] eq "mEmail") {
                       $json{$dvalue[0]} = pack( 'A50', str_conv($dvalue[1]) ) if ($dvalue[1] !~ /^[\s]*$/);
                    }
                    elsif ($dvalue[0] eq "mForce") {
                       $json{'mForce'} = "";
                       $json{'mForce'} = "force" if ($dvalue[1] eq "Yes");
                    }
                    elsif ($dvalue[0] eq "Disa") {
                       $json{'Disa'} = "";
                       $json{'Disa'} = "disabled" if ($dvalue[1] eq "Yes");
                    }
                    elsif ($dvalue[0] =~ /^(Control|id)$/) {
                       $json{$dvalue[0]} = $dvalue[1];
                    }
                    elsif ($dvalue[0] eq "Desc" || $dvalue[0] eq "id") {
                       $json{$dvalue[0]} = str_conv($dvalue[1]);
                    }
                    elsif ($dvalue[0] eq "Control") {
                       $json{'Control'} = $dvalue[1];
                    }
                 }
              }

              if (($json{'Src'} ne "" && $json{'mEmail'} ne "") && $json{'Control'} ne "set") {
                 $canSync = 1;
                 if ($json{'Control'} ne "del") {
                    my $auxentry = "allow.login $json{'Src'} $json{'mEmail'}";
                    $auxentry = "$auxentry $json{'mForce'}" if ($json{'mForce'});
                    $auxentry = "$auxentry $json{'Disa'}" if ($json{'Disa'});
                    $auxentry = "$auxentry desc=\"$json{'Desc'}\"" if (length($json{'Desc'}) gt 1);
                    push(@unsortId, $json{'id'});
                    push(@{$unsortData{$json{'id'}}}, $auxentry);
                 }
              }
              $canSync = 1 if ($json{'Control'} eq "set");
          }
       }

       if ($canSync == 1) {
          open FILE, ">$file_cfg{'fwmsn'}";

          # Writing fwmsn comments
          foreach my $msnRules (@fwmsncomments) {
              $msnRules =~ s/\n//;
              $msnRules =~ s/\\"/\"/g;
              $msnRules =~ s/\\'/\'/g;
              print FILE "$msnRules\n" if ($msnRules);
          }

          # Writing fwmsn check definitions
          print FILE "\n";
          foreach my $msnRules (@fwmsncheckaddr) {
              $msnRules =~ s/\n//;
              $msnRules =~ s/\\"/\"/g;
              print FILE "check.address $msnRules\n" if ($msnRules);
          }
          foreach my $msnRules (@fwmsncheckproxy) {
              $msnRules =~ s/\n//;
              $msnRules =~ s/\\"/\"/g;
              print FILE "check.proxy $msnRules\n" if ($msnRules);
          }

          # Writing fwmsn rules
          print FILE "\n";
          my @sortedId = sort { $a <=> $b } @unsortId;
          foreach (@sortedId) {
             foreach my $msnRules (@{$unsortData{"$_"}}) {
                print FILE "$msnRules\n";
             }
          }
          close(FILE);
          $txtvalue="OK";

          rsyncupdate("$file_cfg{'fwmsn'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
    }
    else {
       my $rtime = 2;
       if ($canch == 1) {
          $msg[0] = "Aplicando as regras de firewall!";
          $msg[1] = "Applying firewall rules!";
          $msg2[0] = "<font size=\'2\'>Recarregando as regras de MSN...</font>";
          $msg2[1] = "<font size=\'2\'>Reloading the MSN rules...</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
          system("$FW_DIR/fwguardian --reload-msn 1>&2 2>/dev/null &");

          rsyncupdate("$file_cfg{'fwmsn'}", "msn", "reload") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
       }
       else {
          $rtime = 0;
       }
       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/fwmsn.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page fwmsn.html"
sub get_fwmsn {
    my $htmlfile="$HTMLDIR/admin/dynhttp/fwmsn.html";
    read_fwmsn;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $defmSrc = `ip route ls scope link | grep 'proto kernel' | head -1 | sed 's/\\s.*//'`;
    $defmSrc =~ s/\n//;

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making fwmsn.html
    splitalias;
    open FILE, ">$htmlfile";

print FILE << "javascript";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />

  <link href="/css/csstab.css" type="text/css" rel="stylesheet" />
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
                 fMsnGrid.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 fMsnGrid.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.flsFwMsn.ReloadFw.click();
                 return false;
           });

           \$("#btcan2").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btrel2").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.flsFwMsn.ReloadFw.click();
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
        var newRow = new Array();
        var rulesGrid = new Array();         // Main data

        // Make jqgrid
        var scrollPosition = 0;
        jQuery("#fwMsnGrid").jqGrid({
           url:'/admin/getfwmsn.json',
           datatype: "json",
           height: \$(window).height() - 270,
           width: \$(window).width() - 120,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'IP de origem', 'Email', 'Forçar', 'Desabilitado', 'Descrição', 'Control' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'Source IP', 'Email', 'Force', 'Disabled', 'Description', 'Control' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id', sortable:true, sorttype: "int", key: true, width:30 },
              { name:"Src",     index:'Src', sortable:true, editable:true, width:140 },
              { name:"mEmail",  index:'mEmail', sortable:false, editable:true, dataType:'string', width:320 },
              { name:"mForce",  index:'mForce', sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, width:64 },
              { name:"Disa",    index:'Disa', sortable:false, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, width:78 },
              { name:"Desc",    index:'Desc', sortable:false, editable:true, dataType:'string', width:360 },
              { name:"Control", index:'Control', sortable:false, editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 }
           ],
           pager: '#pfwMsnGrid',
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
              editRow(jQuery("#fwMsnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "fwmsn");
              newRow = updnewRow();
           },
           gridComplete: function(data, response) {
              rulesGrid=GridComplete(jQuery("#fwMsnGrid"), rulesGrid, rulesCt, saveall, "fwmsn");

              rulesCt++;
              saveall = 0;
              jQuery("#fwMsnGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Contas autorizadas";
$msg[1] = "Authorized accounts";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#fwMsnGrid").css('font-size', '13px');
        jQuery("#fwMsnGrid").jqGrid('navGrid',"#pfwMsnGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#fwMsnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwmsn");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#fwMsnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwmsn");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Edit grid row
        \$("#fwMsnGrid").jqGrid('navButtonAdd','#pfwMsnGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#fwMsnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "fwmsn");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#fwMsnGrid").jqGrid('navButtonAdd','#pfwMsnGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
$msg[0] = "Por favor... selecione a linha a ser removida!";
$msg[1] = "Please... Select the line to delete!";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = cloneRow(jQuery("#fwMsnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwmsn", "$defmSrc");
             newRow = updnewRow();
           }
        });

        // Delete row in click event
        jQuery("#delgd").click( function() {
           rulesCt = 1;
           rulesGrid = delRow(jQuery("#fwMsnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
        });

        \$("#fwMsnGrid").jqGrid('navButtonAdd','#pfwMsnGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = addRow(jQuery("#fwMsnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "fwmsn", "$defmSrc", "");
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
           saveAll(jQuery("#fwMsnGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "fwmsn", "/admin/getfwmsn.json", "/admin/chfwmsn.cgi");
           newRow = updnewRow();
           if (newRow.length < 1) rulesCt = 0;
        });

        // Grid resize
        \$(window).bind('resize', function() {
            \$("#jqgrid").setGridWidth(\$(window).width() - 120);
        }).trigger('resize');

     });

function EnterKey(e, dtype)
{
   var key;
   if(window.event) key = window.event.keyCode;  //IE
   else key = e.which;  //firefox

   if(key == 13) {
     if (dtype == "proxy") return selectall('proxy');
     else return selectall('addr');
   }
   else return;
}

function newcheck(cktype) {
  var selid = 1;
  var canadd = 1;
  var ninput="";
  var seldoc = document.fmsnaddr.lsVrfAddr;
  if (cktype == "proxy") {
     seldoc = document.fmsnproxy.lsVrfProxy;
javascript
$msg[0] = "Por favor identifique o servidor proxy!";
$msg[1] = "Please identify the proxy server!";
  print FILE << "javascript";
     ninput=prompt("$msg[$FW_LANG]","127.0.0.1:8080");
  }
  else {
javascript
$msg[0] = "Por favor entre com o endereço IP!";
$msg[1] = "Please enter the IP address!";
  print FILE << "javascript";
     ninput=prompt("$msg[$FW_LANG]","127.0.0.1");
  }

  var rules = seldoc.length;
  for (var i = 0; i < seldoc.length ; i++) if (seldoc[i].value == ninput) {
     canadd = 0;
     i = seldoc.length;
  }
  
  if (ninput !== null) {
     if (canadd) seldoc.options[rules] = new Option(ninput, ninput, true, true);
javascript
$msg[0] = "Este registro já existe!";
$msg[1] = "This record exist!";
print FILE "       else alert(\"$msg[$FW_LANG]\");\n";
print FILE << "javascript";
  }
}

function delcheck(cktype) {
  var seldoc = document.fmsnaddr.lsVrfAddr;
  if (cktype == "proxy") seldoc = document.fmsnproxy.lsVrfProxy;

  var rules = seldoc.length;
  var ruleid = seldoc.selectedIndex;
  if (ruleid > -1) {
    var selval = seldoc[ruleid].value;
    var testval = /^--- /;
    if (selval && !testval.test(selval)) {
       seldoc[ruleid] = null;
       if (ruleid < rules - 1) {
         if (seldoc[ruleid].value) seldoc[ruleid].selected = true;
         else seldoc[ruleid-1].selected = true;
       }      
       else seldoc[ruleid-1].selected = true;
    }
javascript
$msg[0] = "ALERTA... \\nRemoção inválida!";
$msg[1] = "WARNING...\\nInvalid delete!";
print FILE "    else alert(\"$msg[$FW_LANG]\");\n";
print FILE "  }\n";
$msg[0] = "ALERTA... \\nNada para remover!";
$msg[1] = "WARNING...\\nNothing to delete!";
print FILE "  else alert(\"$msg[$FW_LANG]\");\n";
print FILE << "javascript";
}

function jstype(cktype, value){
  if (cktype == "proxy") this.proxy = value;
  else this.addr = value;
}

function selectall(cktype) {
  var cl_lock=$cl_lock;

  if (!cl_lock) {
     var seldoc = document.fmsnaddr.lsVrfAddr;
     if (cktype == "proxy") seldoc = document.fmsnproxy.lsVrfProxy;

     var docData = new Array();
     var rules = seldoc.length;
     for ( var i=0; i<rules; i++ ) {
        if (i == 0) seldoc[i].value = "_ignore_";

        if (cktype == "proxy") docData.push(new jstype('proxy', encodeHtml(seldoc[i].value)));
        else docData.push(new jstype('addr', seldoc[i].value));
     }

     // POST ajax
     jQuery.ajax({
         url         : '/admin/chmsncheck.cgi'
         ,type        : 'POST'
         ,cache       : false
         ,data        : JSON.stringify(docData)
         ,contentType : 'application/json; charset=utf-8'
         ,async: false
         ,success: function(data) {
               document.getElementById('chwait').style.display = 'none';
javascript
$msg[0] = "INFO: Regras atualizadas com sucesso!";
$msg[1] = "INFO: Rules updated successfully!";
print FILE "                    alert(\"$msg[$FW_LANG]\");\n";
print FILE << "javascript";
         }
     });
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

    $msg[0] = "Filtro de pacotes: Controlar MSN";
    $msg[1] = "Packet filter: MSN Control";
    my $mstyle = menustyle("$msg[$FW_LANG]");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' onload="document.getElementById('tab_msn').style.display='block';" $STYLE>
  <span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG] ($srcfile)</span>

  <DIV align="center">
HTMLCODE

    ## Waiting form
    print FILE "<DIV align=\"center\" valign=\"center\" id=\"chwait\">";
    $msg[0] = "Aguarde... isto pode demorar um pouco!";
    $msg[1] = "Wait... this may take a little time!";
    print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
    print FILE "</DIV>";

   print FILE << "HTMLCODE";
    <span id="tab_msn" style="display: none;">
      <ul id="tabs">
HTMLCODE
   $msg[0] = "Contas do MSN";
   $msg[1] = "MSN accounts";
   print FILE << "HTMLCODE";
        <li><a href="#" name="#tab1">$msg[$FW_LANG]</a></li>
HTMLCODE
   $msg[0] = "Oções avançadas";
   $msg[1] = "Advanced Options";
   print FILE << "HTMLCODE";
        <li><a href="#" name="#tab2">$msg[$FW_LANG]</a></li>
      </ul>
HTMLCODE

    print FILE "<div id=\"content\">";

    ### Grid rules
    print FILE "<div id=\"tab1\">";
    print FILE "<FORM name=\"flsFwMsn\" action=\"/admin/chfwmsn.cgi\" method=\"post\">";
    print FILE "<table border='0' cellspacing='0' cellpadding='0'>";
    print FILE "<tbody><TR valign=\"bottom\" align=\"left\"><TD width=\"96%\">";
print FILE << "HTMLCODE";
    <table id="fwMsnGrid" width="100%" style="font-size:12px;"></table>
    <div id="pfwMsnGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
    print FILE "</TD><TD width=\"4%\">";
    print FILE "&nbsp;<a href=\"javascript: document.fMsnGrid.gdmoveup.click();\">";
    print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "&nbsp;<a href=\"javascript: document.fMsnGrid.gdmovedown.click();\">";
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
    print FILE "</div>";

    ### Adv options
    print FILE "<div id=\"tab2\">";
    print FILE "<DIV align='left' valign='top' style='Font-Family: Arial, Helvetica;' heigth='15%'><i>";
    print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 12px;\">";
    if ($FW_LANG == 0) {
       print FILE "1. Configure quais redes (microsoft) serão inspecionadas em *Verificar destino*<BR />\n";
       print FILE "2. Identifique seu proxy MSN em *Verificar proxy* (se existir)<BR />\n";
       print FILE "3. Este modulo pode não funcionar para muitos clientes e <strong>tende a ser removido</strong>";
    }
    else {
       print FILE "1. Set which networks (microsoft) will be inspected in *Destination verify*<BR />\n";
       print FILE "2. Identify your MSN proxy in *Proxy verify* (if exist)<BR />\n";
       print FILE "3. This module may not work for many clients and <strong>tends to be removed</strong>\n";
    }
    print FILE "</span></i></DIV><BR /><BR />";

    print FILE "<p><table border='0' cellspacing='0' cellpadding='0' width='50%' height='45%'></tbody><tr align='center'>";
    print FILE "<form name=\"fmsnaddr\"><TD align='left' valign='center' width='50%'>";
    $msg[0] = "Verificar destino";
    $msg[1] = "Destination verify";
    print FILE "<DIV class='custom-header' style='background-color:#A4A4A4; border:0px; color:white; text-align:center; font-size:13px; width:180px'>$msg[$FW_LANG]</DIV>";
    print FILE "<SELECT size='14' name='lsVrfAddr' STYLE='background-color:#eeeeee; width:180px; Font-Family: Arial, Helvetica; border:1px solid #A4A4A4; color: #555; font-size: 14px;'>";
    $msg[0] = "Destino";
    $msg[1] = "Destination";
    print FILE "<OPTION style=\"color:#1C4059;text-align:center;\">--- $msg[$FW_LANG] ---</OPTION>";
    foreach (@fwmsncheckaddr) {
       $_ =~ s/\n//;
       print FILE "<OPTION value=\"$_\">$_</OPTION>";
    }
    print FILE "</select><BR />";
    print FILE "<INPUT type=\"button\" value=\"+\" onclick=\"return newcheck('addr');\" style=\"Font-Family: Arial, Helvetica;\">";
    print FILE "<INPUT type=\"button\" value=\"-\" onclick=\"return delcheck('addr');\" style=\"Font-Family: Arial, Helvetica;\">&nbsp;";
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE "<INPUT type=\"button\" value=\"$msg[$FW_LANG]\" onclick=\"return selectall('addr')\" style=\"Font-Family: Arial, Helvetica;\">";
    print FILE "</TD>";
    print FILE "</form>";

    print FILE "<form name='fmsnproxy'><TD align='left' valign='center' width='50%'>";
    $msg[0] = "Verificar proxy";
    $msg[1] = "Proxy verify";
    print FILE "<div class='custom-header' style='background-color:#A4A4A4; border:0px; color:white; text-align:center; font-size:13px; width:180px'>$msg[$FW_LANG]</div>";
    print FILE "<SELECT size='14' name='lsVrfProxy' STYLE='background-color:#eeeeee; width:180px; Font-Family: Arial, Helvetica; border:1px solid #A4A4A4; color: #555; font-size: 14px;'>";
    print FILE "<OPTION style=\"color:#1C4059;text-align:center;\">--- proxy:port ---</OPTION>";
    foreach (@fwmsncheckproxy) {
       $_ =~ s/\n//;
       print FILE "<OPTION value=\"$_\">$_</OPTION>";
    }
    print FILE "</select><BR />";
    print FILE "<INPUT type=\"button\" value=\"+\" onclick=\"return newcheck(\'proxy\');\" style=\"Font-Family: Arial, Helvetica;\">";
    print FILE "<INPUT type=\"button\" value=\"-\" onclick=\"return delcheck(\'proxy\');\" style=\"Font-Family: Arial, Helvetica;\">&nbsp;";
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE "<INPUT type=\"button\" value=\"$msg[$FW_LANG]\" onclick=\"return selectall('proxy')\" style=\"Font-Family: Arial, Helvetica;\">";
    print FILE "</TD>";
    print FILE "</form><BR />";
    print FILE "</tr></tbody></table></p>";
    print FILE "$srcfs<BR />";
    print FILE "<BR />" if ($srcfs eq "");
    $msg[0] = "Cancelar";
    $msg[1] = "Cancel";
    print FILE " &nbsp; <a href=\"#\" id=\"btcan2\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
    $msg[0] = "Aplicar";
    $msg[1] = "Apply";
    print FILE " &nbsp; <a href=\"#\" id=\"btrel2\" class=\"uibt\">$msg[$FW_LANG]</a>";
    print FILE "</div>";

print FILE << "HTML";
    <form name="fMsnGrid">
    <input type="BUTTON" id="gdUp" name="gdmoveup" value="Up" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="gdDown" name="gdmovedown" value="Down" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="savegd" name="savegd" value="Save" style="visibility:hidden; position:absolute;" />
    <input type="BUTTON" id="delgd" name="delgd" value="Delete" style="visibility:hidden; position:absolute;" />
    </form></DIV>

    <script type="text/javascript" src="/js/csstab.js"></script>
    </body></HTML>
HTML
    close(FILE);

    return get_file("text/html", $htmlfile);
}

return 1;

