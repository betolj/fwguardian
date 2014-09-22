#!/usr/bin/perl

#Rev.1 - Version 5.0

# "POST /admin/chalias.cgi" -> save button
sub chalias {
    my $s = shift;
    my $txtvalue = "NO";

    my $res = HTTP::Response->new();
    read_fwcfg;

    my $rlfw = 0;
    $rlfw = 1 if ($s =~ /ReloadFw/);

    my $canSync = 0;
    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($rlfw == 0 && $canch == 1) {

        # Parsing json response (sorting by ID)
        my %json = ();
        my @unsortId = ();
        my %unsortData = ();

        my @dvalue = ();
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
                 $json{$dvalue[0]} = str_conv($dvalue[1]);
                 $json{'Control'} = $dvalue[1] if ($dvalue[0] eq "Control");
              }
              if ($json{'aName'} ne "" && $json{'aValue'} ne "" && $json{'Control'} ne "set") {
                 $canSync = 1;
                 my $auxentry = "alias $json{'aName'} $json{'aValue'} $json{'Desc'}  webalias";
                 push(@unsortId, $json{'id'});
                 push(@{$unsortData{$json{'id'}}}, $auxentry);
              }
              $canSync = 1 if ($json{'Control'} eq "set");
           }
        }

        if ($canSync == 1) {
           open FILE, ">$file_cfg{'alias'}";
           print FILE "; Dont change manually... this is managed only by webserver\n";
           my @sortedId = sort { $a <=> $b } @unsortId;
           foreach (@sortedId) {
              foreach my $line (@{$unsortData{"$_"}}) {
                 print FILE "$line\n";
              }
           }
           close(FILE);
           $txtvalue="OK";

           rsyncupdate("$file_cfg{'alias'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
        }
    }
    else {
       my $rtime = 2;
       if ($canch == 1) {
          $msg[0] = "Aplicando as regras de firewall!";
          $msg[1] = "Applying firewall rules!";
          $msg2[0] = "<font size=\'2\'>Recarregando todas as regras...</font>";
          $msg2[1] = "<font size=\'2\'>Full reloading...</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "<font size=\'2\'>$msg2[$FW_LANG]</font>");

          system("$FW_DIR/fwguardian --ignore-cluster 1>&2 2>/dev/null &") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl");
          system("$FW_DIR/fwguardian --ignore-webserver 1>&2 2>/dev/null &");
          system("$FW_DIR/fwguardian 1>&2 2>/dev/null &");
       }
       else {
          $rtime = 0;
       }
       my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"$rtime;URL=/admin/alias.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
       $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    }

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page alias.html" 
sub get_alias {
    my $htmlfile="$HTMLDIR/admin/dynhttp/alias.html";
    read_fwcfg;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making alias.html
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
       font-size: 14px;
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
                 document.faliasGrid.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 document.faliasGrid.delgd.click();
                 return false;
           });
           \$("#btrel").click(function() {
                 document.getElementById('chwait').style.display = 'block';
                 document.falias.ReloadFw.click();
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
        jQuery("#aliasGrid").jqGrid({
           url:'/admin/getalias.json',
           datatype: "json",
           height: \$(window).height() - 250,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'Nome', 'Valor', 'Descrição', 'Control' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'Name', 'Value', 'Description', 'Control' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",       index:'id', width: 6, sorttype: "int", key: true },
              { name:"aName",    index:'aName',  sortable:true, editable:true, width:20 },
              { name:"aValue",   index:'aValue', sortable:true, editable:true, width:20 },
              { name:"Desc" ,    index:'Desc',   sortable:false, editable:true, width:50 },
              { name:"Control",  index:'Control', sortable:false,  editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 }
           ],
           pager: '#paliasGrid',
           editurl: 'clientArray',
           rowNum: '',
           rowList: [],
           pgbuttons: false,
           pgtext: null,
           gridview: true,
           viewrecords: false,
           sortable: true,
           ondblClickRow: function (selid, iRow,iCol) {
              editRow(jQuery("#aliasGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "alias");
              newRow = updnewRow();
           },
           gridComplete: function(data, response) {
              rulesGrid=GridComplete(jQuery("#aliasGrid"), rulesGrid, rulesCt, saveall, "alias");

              rulesCt++;
              saveall = 0;
              jQuery("#aliasGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Definição de apelidos de rede";
$msg[1] = "Network alias definitions";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#aliasGrid").css('font-size', '13px');
        jQuery("#aliasGrid").jqGrid('navGrid',"#paliasGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#aliasGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "alias");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#aliasGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "alias");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Edit button
        \$("#aliasGrid").jqGrid('navButtonAdd','#paliasGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery("#aliasGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "alias");
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
           rulesGrid = delRow(jQuery("#aliasGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
        });

        // Add button
        \$("#aliasGrid").jqGrid('navButtonAdd','#paliasGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = addRow(jQuery("#aliasGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "alias", "", "");
             newRow = updnewRow();
           }
        });

        // Saving all rows in click event
        jQuery("#savegd").click( function() {
javascript
my $cl_lock=0;
$cl_lock=1 if ($canch ==0);
$msg[0] = "INFO: Regras atualizadas com sucesso!";
$msg[1] = "INFO: Rules updated successfully!";
print FILE << "javascript";
           var cl_lock=$cl_lock;
           if (cl_lock) return false;
           saveall = 1;
           saveAll(jQuery("#aliasGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "alias", "/admin/getalias.json", "/admin/chalias.cgi");
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

    $msg[0] = "Funções globais: Apelidos";
    $msg[1] = "Global functions: Aliases";
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
    print FILE "</DIV><BR />";

    print FILE "<table border=\"0\" cellspacing=\"0\" cellpadding=\"0\"><tbody><TR valign=\"bottom\" align=\"center\">";
    print FILE "<TD width=\"96%\">";
print FILE << "HTMLCODE";
    <table id="aliasGrid" width="100%" style="font-size:12px;"></table>
    <div id="paliasGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
    print FILE "<BR />" if ($srcfs eq ""); 
    print FILE "</TD><TD width=\"4%\" align=\"left\">";
    print FILE "&nbsp;<a href=\"javascript: document.faliasGrid.gdmoveup.click();\">";
    print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "&nbsp;<a href=\"javascript: document.faliasGrid.gdmovedown.click();\">";
    print FILE "<img src=\"buttons/mv_down.png\" style=\"border: 0px solid ;\"></a><BR /><BR />";
    print FILE "</TD></TR></tbody></table>";
    print FILE "<FORM name='falias' action='/admin/chalias.cgi' method='POST'>";
    print FILE "<INPUT type=\"submit\" name=\"ReloadFw\" value=\"Reload firewall rules\" style=\"visibility:hidden; position:absolute;\">";
    print FILE "</FORM>";
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
    <form name="faliasGrid">
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
