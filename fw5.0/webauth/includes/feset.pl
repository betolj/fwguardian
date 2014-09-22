#!/usr/bin/perl

#Rev.1 - Version 5.0

# File Editor

# "POST /admin/chfeset.cgi" -> save button
sub chfeset {
    my $s = shift;
    my @dvalue = ();
    my @msg = ("", "");
    my $txtvalue = "NO";

    my $res = HTTP::Response->new();
    read_fwcfg;

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    if ($canch == 1) {
       # Parsing json response
       my %json = ();
       my $scanSync = 0;

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
                    if ($dvalue[0] eq "feName" || $dvalue[0] eq "Desc") {
                       if ($dvalue[0] eq "Desc") {
                          $dvalue[1] =~ s/ /_/g;
                          $dvalue[1] =~ s/%20/_/g;
                       }
                       $json{$dvalue[0]} = pack( 'A45', str_conv($dvalue[1]) ) if ($dvalue[1] !~ /^[\s]*$/);
                    }
                    elsif ($dvalue[0] eq "Disa") {
                       $json{'Disa'} = "";
                       $json{'Disa'} = "_ignore_" if ($dvalue[1] eq "Yes");
                    }
                    elsif ($dvalue[0] eq "feType") {
                       $json{'feType'} = "textbox";
                       $json{'feType'} = "$dvalue[1]" if ($dvalue[1] eq "selectbox");
                       $json{'feType'} = pack( 'A12', str_conv($json{'feType'}) );
                    }
                    elsif ($dvalue[0] eq "feCmd") {
                       $json{'feCmd'} = "none";
                       $json{'feCmd'} = "$dvalue[1]" if ($dvalue[1] ne "none" && $dvalue[1] ne "null");
                    }
                    elsif ($dvalue[0] =~ /^(Control|id)/) {
                       $json{$dvalue[0]} = $dvalue[1];
                    }
                 }
              }
              if ($json{'feName'} ne "" && $json{'Desc'} ne "" && $json{'Control'} ne "set") {
                 $canSync = 1;

                 # filedit.conf definitions
                 $json{'feType'} = "textbox" if (!$json{'feType'});
                 $json{'feCmd'} = "none" if (!$json{'feCmd'});
                 my $auxentry = "$json{'feName'} $json{'Desc'} $json{'feType'} $json{'Disa'} $json{'feCmd'}";

                 push(@unsortId, $json{'id'});
                 push(@{$unsortData{$json{'id'}}}, $auxentry);
             }
             $canSync = 1 if ($json{'Control'} eq "set");
          }
       }

       if ($canSync == 1) {
          open FILE, ">$file_cfg{'webauth/filedit.conf'}";

          # Writing filedit definitions
          $msg[0] = "; Não modifique manualmente... gerenciado apenas pelo webserver";
          $msg[1] = "; Dont change manually... this is managed only by webserver";
          print FILE "$msg[$FW_LANG]\n";
          print FILE "\n";
          my @sortedId = sort { $a <=> $b } @unsortId;
          foreach (@sortedId) {
             foreach my $line (@{$unsortData{"$_"}}) {
                print FILE "$line\n";
             }
          }
          close(FILE);
          $txtvalue="OK";
          system("rm -f /tmp/sessions/cgisess_$read_cookie.app.fe");

          rsyncupdate("$file_cfg{'webauth/filedit.conf'}", "", "change") if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && ($srcfile eq "default" || $srcfile =~ /^rsync_/));
       }
   }

   $res->content_type("text/html");
   $res->content($txtvalue);
   return $res;
}

# "Make web page feset.html"
sub get_feset {
    my $htmlfile="$HTMLDIR/admin/dynhttp/feset.html";
    read_fwcfg;

    my @msg = ("", "");
    my @medited = ("", "");
    $medited[0] = "ERRO: Há linhas em modo de edição!";
    $medited[1] = "ERROR: There are rows in edit mode!";

    my $canch = 1;
    $canch = 0 if (-e "/usr/share/fwguardian/modules/clusterfw.ctl" && (($srcfile !~ /^(default$|rsync_)/ && not -e "/usr/share/fwguardian/cluster/glusterfs.done") || not -e "/var/tmp/cluster.manager"));

    ### Making feset.html
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
                 ffeSetGrid.savegd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 ffeSetGrid.delgd.click();
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
        jQuery("#fesetGrid").jqGrid({
           url:'/admin/getfeset.json',
           datatype: "json",
           height: \$(window).height() - 270,
           width: \$(window).width() - 80,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'Nome do arquivo', 'Descrição', 'Desabilitado', 'Tipo', 'Comando', 'Control' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'File name', 'Description', 'Disabled', 'Type', 'Command', 'Control' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id', sortable:true, sorttype: "int", key: true, width:30 },
              { name:"feName",  index:'feName', sortable:true, editable:true, width:220 },
              { name:"Desc",    index:'Desc', sortable:false, editable:true, dataType:'string', width:320 },
              { name:"Disa",    index:'Disa', sortable:true, editable:true, edittype:"checkbox", editoptions:{value:"Yes:No"}, width:86 },
              { name:"feType",  index:'feType', sortable:true, editable:true, edittype:"select", editoptions:{value:"textbox:textbox;selectbox:selectbox"}, width:90 },
              { name:"feCmd",   index:'feCmd',  sortable:false, editable:true, dataType:'string', width:220 },
              { name:"Control", index:'Control', sortable:false, editable:true, hidden:true, editoptions:{size:"2", maxlength:"2"}, width:2 }
           ],
           pager: '#pfesetGrid',
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
              editRow(jQuery("#fesetGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "", "feset");
              newRow = updnewRow();
           },
           gridComplete: function(data, response) {
              rulesGrid=GridComplete(jQuery("#fesetGrid"), rulesGrid, rulesCt, saveall, "feset");

              rulesCt++;
              saveall = 0;
              jQuery("#fesetGrid").closest(".ui-jqgrid-bdiv").scrollTop(scrollPosition);
           },
javascript
$msg[0] = "Gerência de arquivos";
$msg[1] = "File management";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#fesetGrid").css('font-size', '13px');
        jQuery("#fesetGrid").jqGrid('navGrid',"#pfesetGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Moveup row function
        jQuery("#gdUp").click( function() {
           rulesGrid = mvUp(jQuery("#fesetGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "feset");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Movedown row function
        jQuery("#gdDown").click( function() {
           rulesGrid = mvDown(jQuery("#fesetGrid"), rulesGrid, newRow, "$medited[$FW_LANG]", "feset");
           newRow = updnewRow();
           doReload = upddoReload();
        });

        // Edit button
        \$("#fesetGrid").jqGrid('navButtonAdd','#pfesetGrid',{
javascript
$msg[0] = "Editar";
$msg[1] = "Edit";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
              editRow(jQuery('#fesetGrid'), rulesGrid, newRow, "$medited[$FW_LANG]", "", "feset");
              newRow = updnewRow();
           }
        });

        // Clone row in click event
        \$("#fesetGrid").jqGrid('navButtonAdd','#pfesetGrid',{
javascript
$msg[0] = "Clonar";
$msg[1] = "Clone";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = cloneRow(jQuery('#fesetGrid'), rulesGrid, newRow, "$medited[$FW_LANG]", "feset", "");
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
           rulesGrid = delRow(jQuery('#fesetGrid'), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]");
           newRow = updnewRow();
        });

        // Add button
        \$("#fesetGrid").jqGrid('navButtonAdd','#pfesetGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
           onClickButton:function(){
             rulesGrid = addRow(jQuery('#fesetGrid'), rulesGrid, newRow, "$medited[$FW_LANG]", "feset", "", "");
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
           saveAll(jQuery('#fesetGrid'), rulesGrid, newRow, "$medited[$FW_LANG]", "$msg[$FW_LANG]", "feset", "/admin/getfeset.json", "/admin/chfeset.cgi");
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

    $msg[0] = "FE: Configura&ccedil;&otilde;es do Editor";
    $msg[1] = "FE: Editor settings";
    my $mstyle = menustyle("$msg[$FW_LANG]");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE>
  <p><span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG] ($srcfile)</span></p>

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
       print FILE "1. Pode ser utilizado para modificar arquivos com definição de ACL<BR />";
       print FILE "2. Permite execução de scripts para releitura de arquivos modificados (atualizações de sistema)<BR />";
    }
    else {
       print FILE "1. Can be used to change proxy ACL files<BR />";
       print FILE "2. Allows execution of scripts for reading of modified files (system updates)<BR />";
    }
    print FILE "</span></i></DIV><BR />";

    print FILE "<FORM name=\"flsFlEdit\">";
    print FILE "<table style=\"font-size: 0.92em;\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">";
    print FILE "<tbody><TR valign=\"bottom\"><TD width=\"96%\">";
print FILE << "HTMLCODE";
    <table id="fesetGrid" width="100%" style="font-size:12px;"></table>
    <div id="pfesetGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE
    print FILE "</TD><TD width=\"4%\">";
    print FILE "&nbsp;<a href=\"javascript: document.ffeSetGrid.gdmoveup.click();\">";
    print FILE "<img src=\"buttons/mv_up.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "&nbsp;<a href=\"javascript: document.ffeSetGrid.gdmovedown.click();\">";
    print FILE "<img src=\"buttons/mv_down.png\" style=\"border: 0px solid ;\"></a><BR />";
    print FILE "</TD></TR></tbody></table>";
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

print FILE << "HTML";
    <form name="ffeSetGrid">
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


# "POST /admin/chfeman.cgi" -> save button
sub chfeman {
    my $s = shift;
    my $chfile = "";
    my $chvalue = "";
    my $chtype = "textbox";
    my @dvalue = ();
    my $feapply = 0;
    my @msg = ("", ""), @msg2 = ("", "");
    my $txtvalue = "";

    my $res = HTTP::Response->new();
    $feapply = 1 if ($s =~ /Reload=RELOAD$/);

    if ($feapply == 0) {
       foreach my $lines (split /&/, $s) {
          # Unix format ($dvalue[1] =~ s/\r\n$/\n/g;  # convert CR LF to LF)
          $lines =~ s/\+/ /g if ($lines =~ /\+/);
          $lines = str_conv($lines);

          # Identify the filename
          if ($lines =~ /chfilename=/) {
             @dvalue = split /chfilename=/, $lines;
             $chfile = $dvalue[1];
             $chfile =~ s/ /\\ /g;
             if ($s =~ /lsSelectBox=/) {
                $chtype = "selectbox";
                open FILE, ">$chfile";
             }
          }

          # Changing a textarea or select file
          if ($lines =~ /^(FeText|lsSelect)Box=/) {
             if ($lines =~ /^FeTextBox=/) {
                @dvalue = split /^FeTextBox=/, $lines;
                $dvalue[1] =~ tr/\015//d;
                $chvalue = str_conv($dvalue[1]);
             }
             else {
               @dvalue = split /^lsSelectBox=/, $lines;
               if ($dvalue[1]) {
                  $dvalue[1] =~ tr/\015//d;
                  $chvalue = str_conv($dvalue[1]);
                  print FILE "$chvalue\n";
               }
               else {
                  print FILE "\n";
               }
             }
          }
       }
       close (FILE) if ($chtype eq "selectbox");

       if ($chvalue) {
          if ($chtype eq "textbox") {
             open FILE, ">$chfile";
             print FILE $chvalue;
             close (FILE);
          }
          $msg[0] = "O arquivo $chfile foi modificado!";
          $msg[1] = "The $chfile file has been modified!";
          $msg2[0] = "Você pode utilizar o botão <strong><i>Aplicar</i></strong>!";
          $msg2[1] = "You can use <strong><i>Apply</i></strong> button!";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
       }
       else {
          $msg[0] = "ALERTA: Nada a ser feito!";
          $msg[1] = "WARNING: Nothing to do!";
          $msg2[0] = "<font color=\'Red\'>Dados inv&aacute;lidos</font>";
          $msg2[1] = "<font color=\'Red\'>Invalid data</font>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
       }
    }
    else {
       $chfile = `cat /tmp/sessions/cgisess_$read_cookie.app.fe | tr -d \'\n\'` if ( -e "/tmp/sessions/cgisess_$read_cookie.app.fe" );
       $chvalue = `grep \"^$chfile\[ \\|\\t\]" $WEB_DIR/filedit.conf | sed \'s/\.\*\\(select\\|text\\)box\[ \\|\\t\]\\+//\' | tr -d \'\\n\'`;
       if ($chvalue !~ /^(null|none)$/ && $chvalue ne "") {
          system "$chvalue &";
          $msg[0] = "Comando ou script executado!";
          $msg[1] = "Running a command or script!";
          $msg2[0] = "Comando: <strong><i>$chvalue</i></strong>";
          $msg2[1] = "Command: <strong><i>$chvalue</i></strong>";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
          log_error("feman apply: $chvalue");
       }
       else {
          $msg[0] = "ALERTA: Nada a ser feito!";
          $msg[1] = "WARNING: Nothing to do!";
          $msg2[0] = "Nenhum comando encontrado!";
          $msg2[1] = "None scheduled command found!";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "<font color=\'Red\'>$msg2[$FW_LANG]</font>");
          log_error("feman apply: $msg2[$FW_LANG] ($chfile)");
       }
    }

    my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"3;URL=/admin/feman.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
    $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";

    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Select an file to edit"
sub chfecfg {
    my $s = shift;
    my $txtvalue = "";
    my @msg = ("", ""), @msg2 = ("", "");

    my $dvalue = $s;
    my $res = HTTP::Response->new();

    $msg[0] = "---Selecione---";
    $msg[1] = "---Select---";
    if ($s !~ /$msg[$FW_LANG]/) {
       $dvalue =~ s/^lsFileEdit=//;
       $dvalue =~ s/\+/ /g if ($dvalue =~ /\+/);
       $dvalue = str_conv($dvalue);

      ### Set selected file to the user session
      system("echo \"$dvalue\" > /tmp/sessions/cgisess_$read_cookie.app.fe");
      $msg[0] = "Mudando para <font color=\'Navy\'>$dvalue</font>";
      $msg[1] = "Changing to <font color=\'Navy\'>$dvalue</font>";
      $txtvalue = msgbox("info", "$msg[$FW_LANG]", "");
    }
    else {
      $msg[0] = "Nada a ser feito!";
      $msg[1] = "Nothing to do!";
      $msg2[0] = "<FONT color=\"Red\">Selecione um arquivo v&aacute;lido</FONT>";
      $msg2[1] = "<FONT color=\"Red\">Select a valid file</FONT>";
      $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]", "");
    }

    my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"2;URL=/admin/feman.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
    $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page feman.html"
sub get_feman {
    my $htmlfile="$HTMLDIR/admin/dynhttp/feman.html";
    my @auxopt = ();
    my $chfile = "";
    my $chtype = "";
    my $tfind = 1;
    my $invistbox = "visibility:hidden; position:absolute;";
    my $invissbox = "visibility:hidden; position:absolute;";
    my $invisctbox = "visibility:hidden; position:absolute;";

    read_fwcfg;

    ### Visibility Box
    if ( -e "/tmp/sessions/cgisess_$read_cookie.app.fe" ) {
       $chfile = `cat /tmp/sessions/cgisess_$read_cookie.app.fe | tr -d \'\n\' `;
       $chtype = `grep \"^$chfile\[ \\|\\t\]\\+\" $WEB_DIR/filedit.conf | awk \'{print \$3}\' | tr -d \'\n\'`;
       if ( -e "$chfile" ) {
         if ( $chtype eq "selectbox" ) {
            $invissbox = "visibility:visible; position:static;";
            $invisctbox = "visibility:hidden; position:absolute;";
         }
         $invistbox = "visibility:visible; position:static;" if ( $chtype eq "textbox" );
       } 
       else {
         $invistbox = "visibility:visible; position:static;";
         $tfind = 0;
       }
       $invissel = "visibility:hidden; position:absolute;";
       $invisctbox = "visibility:visible; position:static;";
    }
    else {
       $invissel = "visibility:visible; position:static;";
    }

    my @msg = ("", ""), @msg2 = ("", "");
 
    ### Making feman.html
    open FILE, ">$htmlfile";

    print FILE "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">";
    print FILE "<html><head>";
    print FILE "<META HTTP-EQUIV=\"Refresh\" CONTENT=\"2;URL=/admin/feman.cgi?cancel\">" if ( !-e "$chfile" && $tfind == 0 );

print FILE << "javascript";

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  <link href="/css/jquery-ui.css" type="text/css" rel="stylesheet" />
  <link href="/css/select2.css" type="text/css" media="screen" rel="stylesheet" />

  <style type="text/css">
    html, body {
       margin: 0;
       padding: 0;
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

  <script type="text/javascript">
        \$(function() {
           \$(".uibt" ).button();
           \$(".uibt_em" ).button();
           \$("#btsav").click(function() {
                 selectall();
                 return false;
           });
           \$("#btcan").click(function() {
                 parent.Pages.location.href = '/admin/feman.cgi?cancel';
                 return false;
           });
           \$("#btrel").click(function() {
                 document.fchfeman.Reload.click();
                 return false;
           });

           \$("#btaddr").click(function() {
                 newtxt('-1');
                 return false;
           });
           \$("#btchr").click(function() {
                 change('change');
                 return false;
           });
           \$("#btsavr").click(function() {
                 selectall();
                 return false;
           });
           \$("#btcanr").click(function() {
                 parent.Pages.location.href = '/admin/feman.cgi?cancel'
                 return false;
           });
           \$("#btdelr").click(function() {
                 deltxt('delete');
                 return false;
           });
           \$("#btrelr").click(function() {
                 document.fchfeman.Reload.click();
                 return false;
           });

           \$( "input[type=submit]" ).button().css('font-size', '12px');
           \$( "input[type=button]" ).button().css('font-size', '12px');
           \$("#lsfileed").select2();
        });
  </script>

<script type="text/javascript">
<!--

// Encode text string to HTML
function encodeHtml(encstr) {
   encstr = encstr.replace(/\"/g,"%22");
   encstr = encstr.replace(/\'/g,"%27");
   var encoded = escape(encstr);
   encoded = encoded.replace(/\\//g,"%2F");
   encoded = encoded.replace(/\\?/g,"%3F");
   encoded = encoded.replace(/=/g,"%3D");
   encoded = encoded.replace(/,/g,"%2C");
   encoded = encoded.replace(/&/g,"%26");
   encoded = encoded.replace(/@/g,"%40");
   return encoded;
}

function choptions(ruleid) {
  document.fchfeman.lsSelectBox[ruleid].style.fontFamily = \'Monospace\';
}


// UP and Down button
function moveup() {
  var rules = document.fchfeman.lsSelectBox.length;
  var ruleid = document.fchfeman.lsSelectBox.selectedIndex;
  var selcur = document.fchfeman.lsSelectBox[ruleid].value;

  if (ruleid > 0 && selcur) {
    var selnex = document.fchfeman.lsSelectBox[ruleid-1].value;
    document.fchfeman.lsSelectBox.options[ruleid] = new Option(selnex, selnex, false, false);
    document.fchfeman.lsSelectBox.options[ruleid-1] = new Option(selcur, selcur, true, true);
    choptions(ruleid); choptions(ruleid-1);
  }
}

function movedown() {
  var rules = document.fchfeman.lsSelectBox.length;
  var ruleid = document.fchfeman.lsSelectBox.selectedIndex;

  if (ruleid + 1 < rules) {
    var selnex = document.fchfeman.lsSelectBox[ruleid+1].value;
    var selcur = document.fchfeman.lsSelectBox[ruleid].value;
    if (ruleid < rules && ruleid >= 0 && selcur) {
      document.fchfeman.lsSelectBox.options[ruleid] = new Option(selnex, selnex, false, false);
      document.fchfeman.lsSelectBox.options[ruleid+1] = new Option(selcur, selcur, true, true);
      choptions(ruleid); choptions(ruleid+1);
    }
  }
}

// Textarea searching - Find button
function findtb()
{
  var fstring = document.fchfeman.feField;
  var seldoc = document.fchfeman.FeTextBox;

  var str1 = fstring.value;
  var str2 = seldoc.value;
  var idstr = parseInt(str2.indexOf(str1));

  var pixunit = parseInt(seldoc.clientHeight / 30);

  var fdstr = str2.split(str1);
  var idstr2 = parseInt(document.fchfeman.feFieldCt.value);
  var idstraux = 0;

  seldoc.focus();

  if (idstr >= 0) {

     for (var i = 0; i < fdstr.length; i++) {
       idstraux += fdstr[i].length;
       if ( i >= idstr2 ) {
          idstr = idstraux + (str1.length * i);
          document.fchfeman.feFieldCt.value = i + 1;
          i = fdstr.length;
       }
     }

     if ( idstr2 >= fdstr.length - 1 ) {
        idstr2 = 0;
        document.fchfeman.feFieldCt.value = 0;
javascript
$msg[0] = "Sem mais ocorrências!";
$msg[1] = "No more match found!";
print FILE "        alert(\"$msg[$FW_LANG]\");\n";
print FILE << "javascript";
        seldoc.scrollTop;
     }
     else {
        var auxdoc = seldoc.value.substring(0, idstr);
        var alines = auxdoc.split("\\n").length;
        var nlines = (alines * pixunit) - pixunit;

        if(seldoc.setSelectionRange){
          seldoc.setSelectionRange(idstr, (idstr + str1.length));
        }
        else {
          var range = seldoc.createTextRange();
          range.collapse(true);

          range.moveStart('character', ((idstr - (alines + 1)) + 2));
          range.moveEnd('character', str1.length);
          range.select();
          range.focus();
        }      
        seldoc.scrollTop = nlines;
     }
  }
javascript
$msg[0] = "Nenhuma ocorrência encontrada!";
$msg[1] = "No match found!";
print FILE "  else alert(\"$msg[$FW_LANG]\");\n";
print FILE << "javascript";
}

// Selectbox searching - Find button
function findsb() {
  var fstring = document.fchfeman.feField.value;
  var seldoc = document.fchfeman.lsSelectBox;
  var nlines = seldoc.length;
  var idstr2 = parseInt(document.fchfeman.feFieldCt.value);
  var sfind = 0;
 
  for (var i = idstr2; i < nlines; i++) {
     if (seldoc[i].value.indexOf(fstring) >= 0) {
        seldoc[i].selected = true;
        document.fchfeman.feFieldCt.value = i + 1;
        i = nlines;
        sfind = 1;
     }
  }

  if ( sfind == 0 ) {
     document.fchfeman.feFieldCt.value = 0;
javascript
$msg[0] = "Nenhuma ocorrência encontrada!";
$msg[1] = "No match found!";
print FILE "     if (idstr2 == 0) alert(\"$msg[$FW_LANG]\");\n";
$msg[0] = "Sem mais ocorrências!";
$msg[1] = "No more match found!";
print FILE "     else alert(\"$msg[$FW_LANG]\");\n";
print FILE << "javascript";
  }
}

// Find button
function Findtxt() {
  if (document.fchfeman.FeTextBox) findtb();
  else { 
     findsb();
     document.fchfeman.feField.focus();
  }
  return false;
}

// Change button or selectbox double-click
function change(cmd) {
  var ruleid = document.fchfeman.lsSelectBox.selectedIndex;
  if (ruleid >= 0) {
     var valopt = document.fchfeman.lsSelectBox[ruleid].value;
  }
  else ruleid = 0;
  if ((cmd == "select") && ruleid >= 0) document.fchfeman.feField.value = valopt;
  else {
    if ((ruleid >= 0) && valopt) {
      deltxt();
      newtxt(ruleid);
    }
  }
}

// ADD button
function newtxt(pos) {
  var rules = document.fchfeman.lsSelectBox.length;
  var ruleid = document.fchfeman.lsSelectBox.selectedIndex;
  var trules = rules;
  var cont = 0;

  if (ruleid >= 0) {
    for ( var i = rules; i > ruleid; i-- ) {
       valopt = document.fchfeman.lsSelectBox[i-1].value;
       txtopt = valopt;
       txtopt = txtopt.replace(/\t/g, "\x09");
       txtopt = txtopt.replace(/ |&nbsp;/g, "\xC2\xA0");
       valopt = txtopt;
       document.fchfeman.lsSelectBox.options[i] = new Option(txtopt, valopt, false, false);
       choptions(i);
    }
    trules = ruleid + 1;
  }
  if (pos >= 0) trules = pos;

  addrule = document.fchfeman.feField.value;
  addrule = addrule.replace(/\t/g, "\x09");
  addrule = addrule.replace(/ |&nbsp;/g, "\xC2\xA0");
  document.fchfeman.lsSelectBox.options[trules] = new Option(addrule, addrule, true, true);
  choptions(trules);
}

// Delete button
function deltxt(cmd) {
  var rules = document.fchfeman.lsSelectBox.length;
  var ruleid = document.fchfeman.lsSelectBox.selectedIndex;
  if (ruleid >= 0) {
    document.fchfeman.lsSelectBox[ruleid] = null;
    if (cmd == "delete" && ruleid < rules - 1) {
       if (document.fchfeman.lsSelectBox[ruleid].value) document.fchfeman.lsSelectBox[ruleid].selected = "true";
       else document.fchfeman.lsSelectBox[ruleid-1].seleted = "true";
    }
    else {
       if (ruleid > 0) document.fchfeman.lsSelectBox[ruleid-1].selected = "true";
       else document.fchfeman.lsSelectBox[ruleid].selected = "true";
    }
  }
javascript
$msg[0] = "ALERTA... \\nNada para remover!";
$msg[1] = "WARNING...\\nNothing to delete!";
print FILE "  else alert(\"$msg[$FW_LANG]\");\n";
print FILE << "javascript";
}

// Save button
function selectall() {
  var rules = 0;
  document.fchfeman.chfilename.value = "$chfile";
  if (document.fchfeman.FeTextBox) {
    var seldoc = document.fchfeman.FeTextBox;
  }
  else { 
    var seldoc = document.fchfeman.lsSelectBox;
    seldoc.multiple = "true";
    rules = seldoc.length;
  }

  document.getElementById('chwait').style.display = 'block';
  seldoc.focus();
  for ( var i=0; i<rules; i++ ) {
     if (document.fchfeman.lsSelectBox) { 
       seldoc.options[i].selected = "true";
       var auxvar = seldoc.options[i].value.replace(/\x09/g, "\t");
       auxvar = auxvar.replace(/(\xC2\xA0| )/g, " ");
       seldoc.options[i].value = encodeHtml(auxvar);
     }
  }
  document.fchfeman.submit();
}

//-->
</script>\n\n
javascript

    $msg[0] = "FE: Editar agora";
    $msg[1] = "FE: Edit now";
    my $mstyle = menustyle("$msg[$FW_LANG]");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE>
  <p><span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG]</span></p>

  <DIV align="center">
HTMLCODE

    ## Waiting form
    print FILE "<DIV align=\"center\" valign=\"center\" id=\"chwait\">";
    $msg[0] = "Aguarde... isto pode demorar um pouco!";
    $msg[1] = "Wait... this may take a little time!";
    print FILE "<p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>";
    print FILE "</DIV>";

    print FILE "<DIV align=\"left\" style=\"$invissel\"><i>";
    print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 20px;\">";
    if ($FW_LANG == 0) {
print FILE << "HTMLSource"
1. Identifique o arquivo em *Editar:*<BR />
2. Clique no bot&atildeo *Selecionar* para editar o arquivo<BR />
3. Clicando em *Reload* &eacute; poss&iacute;vel executar comandos ou scripts ap&oacute;s ter feito alguma altera&ccedil;&atilde;o<BR /><BR />
HTMLSource
    }
    else {
print FILE << "HTMLSource"
1. Identify the target file into *Edit:*<BR />
2. Click in *Select* button to edit the file<BR />
3. A command or scripts can be run after changes with *Reload* button<BR /><BR />
HTMLSource
    }
    print FILE "</span></i><BR /></DIV>";

    print FILE "<FORM name='fiFileSel' action='/admin/chfecfg.cgi' method='POST' style=\"$invissel\"><DIV align='left'>";
    print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 20px;\">";
    print FILE "<select id='lsfileed' name='lsFileEdit' style='width:280px; font-size:small;'>";
    $msg[0] = "Selecione";
    $msg[1] = "Select";
    $msg2[0] = "Selecione um arquivo";
    $msg2[1] = "Select an file";
    print FILE "<OPTION value=\"---$msg[$FW_LANG]---\">--- $msg2[$FW_LANG] ---</OPTION>";
    if (-e "$file_cfg{'webauth/filedit.conf'}") {
      open FEFILE, "<$file_cfg{'webauth/filedit.conf'}";
      while (<FEFILE>) {
        if ($_ !~ /(^[ |\t]*(#|;|$)|_ignore_[\s])/) { 
           $_ =~ s/\n//;
           @auxopt = split /[ |\t]+/, $_;
           $auxopt[1] =~ s/_/ /g;
           print FILE "<OPTION value=\"$auxopt[0]\">$auxopt[1]</OPTION>";
        }
      }
      close (FEFILE);
    }
    print FILE "</select></span>";
    $msg[0] = "Selecionar";
    $msg[1] = "Select";
    print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 40px;\">";
    print FILE "<input value=\"$msg[$FW_LANG]\" type='submit'></span>";
    print FILE "</DIV></FORM>";

    ### TextBox or Select Box form
    print FILE "<form name='fchfeman' style=\"$invisctbox\" action='/admin/chfeman.cgi' method='POST'>";
    print FILE "<input name=\"chfilename\" style=\"visibility:hidden; position:absolute;\" type=\"textbox\">";
    print FILE "<input type=\"textbox\" value=\"0\" name=\"feFieldCt\" style=\"visibility:hidden; position:absolute;\">";

    print FILE "<DIV align='left'><i>";
    print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 20px;\">";
    print FILE "<input style=\"background-color: #bec2c8; height:24px;\" size=\"80\" name=\"feField\" onchange=\"document.fchfeman.feFieldCt.value = 0;\" onkeypress=\"javascript: if (event.keyCode == 13) return Findtxt();\"> &nbsp; ";
    $msg[0] = "Encontrar";
    $msg[1] = "Find";
    print FILE "<INPUT type=\"button\" value=\"$msg[$FW_LANG]\" name=\"fibuttom\" onclick=\"return Findtxt();\">";
    print FILE "</span></i></DIV><BR />";

    if ($chtype eq "textbox") { 
      ### TextBox
      if ( -e "$chfile" ) {
        print FILE "<div id='idtbox' style='font-size: 0.92em; text-align: center; $invistbox'>";
        print FILE "<textarea style='background-color:#eeeeee; font-size: 1em; width: 96%; height: 72%; font-family: Monospace; $invistbox' rows='30' cols='110' name='FeTextBox'>";

        open FEFILE, "<$chfile";
        while (<FEFILE>) {
          print FILE "$_";
        }
        close(FEFILE);
        print FILE "</textarea></div>";
      }
    }
    else {
      ### SelectBox
      if ( -e "$chfile" ) {
        print FILE "<div id='idsbox' style='text-align: center; $invissbox'>";
        print FILE "<table style='font-size: 0.92em; width:96%; height:72%;' border='0' cellspacing='0' cellpadding='0' align='center'><tbody>";
        print FILE "<TR valign='bottom'><TD width='96%'>";
        print FILE "<select size='30' name='lsSelectBox' style='background-color:#eeeeee; font-size: 1em; width: 100%; height: 100%; font-family: Monospace; $invissbox' ondblclick='return change(\'select\');'>";

        open FEFILE, "<$chfile";
        while (<FEFILE>) {
          $_ =~ s/\n//;
          $_ =~ s/\t/\x09/g;
          $_ =~ s/\s|&nbsp;/\xC2\xA0/g;
          print FILE "<OPTION value=\"$_\">$_</OPTION>";
        }
        close(FEFILE);
        print FILE "</select></TD><TD width='4%'>";
        print FILE "&nbsp;<a href='javascript: moveup();'>";
        print FILE "<img src='buttons/mv_up.png' style='border: 0px solid ;'></a><BR />";
        print FILE "&nbsp;<a href='javascript: movedown();'>";
        print FILE "<img src='buttons/mv_down.png' style='border: 0px solid ;'></a><BR />";
        print FILE "</TD></TR></tbody></table>";
        print FILE "</div>";
      }
    }
    print FILE "<INPUT type=\"submit\" name=\"Reload\" onclick=\"return selectall();\" value=\"RELOAD\" style=\"visibility:hidden; position:absolute;\">";
    print FILE "</form>";

    print FILE "<div id=\"chbox\" style=\"text-align: center; $invistbox\">";
    if ( -e "$chfile" ) {
      $msg[0] = "Salvar";
      $msg[1] = "Save";
      print FILE "<a href=\"#\" id=\"btsav\" class=\"uibt\">$msg[$FW_LANG]</a>";
      $msg[0] = "Cancelar";
      $msg[1] = "Cancel";
      print FILE " &nbsp; <a href=\"#\" id=\"btcan\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
      $msg[0] = "Aplicar";
      $msg[1] = "Apply";
      print FILE " &nbsp; <a href=\"#\" id=\"btrel\" class=\"uibt\">$msg[$FW_LANG]</a>";
    }
    else {
      $msg[0] = "ERRO: Arquivo n&atilde;o encontrado!";
      $msg[1] = "ERROR: File not found!";
      print FILE "<hr noshade='true' size='1'>";
      print FILE "<BR /><h2><FONT color=\"Red\">$msg[$FW_LANG]</FONT><BR /><BR /><BR /></h2>";
    }
    print FILE "</div>";

    print FILE "<div style=\"$invissbox\">";
    $msg[0] = "Adicionar";
    $msg[1] = "Add";
    print FILE "<a href=\"#\" id=\"btaddr\" class=\"uibt\">$msg[$FW_LANG]</a>";
    $msg[0] = "Salvar";
    $msg[1] = "Save";
    print FILE " <a href=\"#\" id=\"btsavr\" class=\"uibt\">$msg[$FW_LANG]</a>";
    $msg[0] = "Alterar";
    $msg[1] = "Change";
    print FILE " &nbsp; <a href=\"#\" id=\"btchr\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
    $msg[0] = "Cancelar";
    $msg[1] = "Cancel";
    print FILE " <a href=\"#\" id=\"btcanr\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
    $msg[0] = "Apagar";
    $msg[1] = "Delete";
    print FILE " <a href=\"#\" id=\"btdelr\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
    $msg[0] = "Aplicar";
    $msg[1] = "Apply";
    print FILE " &nbsp; <a href=\"#\" id=\"btrelr\" class=\"uibt\">$msg[$FW_LANG]</a>";
    print FILE "</div>";

    print FILE "</DIV></body>";

    print FILE "</HTML>";
    close (FILE);

    return get_file("text/html", $htmlfile);
}

return 1;
