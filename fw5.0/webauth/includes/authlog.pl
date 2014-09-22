#!/usr/bin/perl -w

#Rev.0 - Version 5.0

# Account stats

# Disconnect webauth account
sub authleave {
    my $s = shift;
    my $res = HTTP::Response->new();
    my @msg = ("", ""), @msg2 = ("", "");

    my ($cmd, $txtvalue) = split /\=/, $s;
    if ($cmd eq "userLeave") {
       (undef, $txtvalue) = split /\+/, $txtvalue;
       $msg[0] = "Endere&ccedil;o alvo: <font color=\'Navy\'>$txtvalue</font>!";
       $msg[1] = "Target address: <font color=\'Navy\'>$txtvalue</font>!";

       if (system("/usr/share/fwguardian/webauth/webctl.sh", "leave", $txtvalue, "null") > -1) {
          $msg2[0] = "Desconectado...";
          $msg2[1] = "Disconnected...";
          $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
       }
       else {
          $msg2[0] = "Não foi possível desconectar<br>Tente novamente...";
          $msg2[1] = "I cant disconnect this address<br>Try again...";
          $txtvalue = msgbox("error", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
       }
    }
    else {
       $msg[0] = "Dados inv&aacute;lidos!";
       $msg[1] = "Invalid data!";
       $msg2[0] = "Tente novamente.";
       $msg2[1] = "Try again.";
       $txtvalue = msgbox("info", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
    }

    my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"2;URL=/admin/authlog.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
    $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
    $res->content_type("text/html");
    $res->content($txtvalue);
    return $res;
}

# "Make web page authlog.html"
sub get_authlog {
    my $htmlfile="$HTMLDIR/admin/dynhttp/authlog.html";

    my @msg = ("", "");

    ### Making lease.html
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
  <script type="text/javascript">
        jQuery.jgrid.no_legacy_api = true;
        jQuery.jgrid.useJSON = true;

        \$(function() {
           \$(".uibt" ).button();
           \$(".uibt_em" ).button();

           \$( "input[type=button]" ).button().css('font-size', '12px');
        });
  </script>

  <script type="text/javascript">

    function do_submit() {
       if (document.getElementById('UserGrid').value) {
         document.getElementById('UserGrid').disabled = false;
         document.fchcond.submit();
       }
    }

    jQuery(document).ready(function(){

        // Filters array
        var searchColumn1 = new Array();
        var searchColumn2 = new Array();

        jQuery("#authGrid").jqGrid({
           url:'/admin/authlog.json',
           datatype: "json",
           height: \$(window).height() - 220,
           width: \$(window).width() - 300,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'Login', 'Tipo de conta', 'Fonte', 'Endereço', 'Horário' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'Login', 'Account type', 'Source', 'Address', 'Time' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",       index:'id', width: 4, sorttype: "int", key: true, hidden:true },
              { name:"alLogin",    index:'alLogin',  sortable:true, editable:true, width:30 },
              { name:"alAccount",  index:'alAccount', sortable:true, editable:true, width:25 },
              { name:"alFrom" ,    index:'alFrom',  sortable:false, editable:true, width:20 },
              { name:"alAddress" , index:'alAddress',  sortable:true, editable:true, width:20 },
              { name:"alTime" , index:'alTime',  sortable:true, editable:true, width:30 }
           ],
           pager: '#pauthGrid',
           editurl: 'clientArray',
           rowNum: '',
           rowList: [],
           pgbuttons: false,
           pgtext: null,
           gridview: true,
           viewrecords: false,
           sortable: true,
           gridComplete: function() {
              searchColumn1[0] = jQuery("#authGrid").jqGrid('getCol','alLogin',true);
              searchColumn1[1] = jQuery("#authGrid").jqGrid('getCol','alAccount',true);
              searchColumn1[2] = jQuery("#authGrid").jqGrid('getCol','alAddress',true);
              searchColumn1[3] = jQuery("#authGrid").jqGrid('getCol','alTime',true);
           },
javascript
$msg[0] = "Eventos, <input type=\"search\" id=\"gridsearch1\" placeholder=\"Search\" results=\"0\" class=\"gridsearch\" />";
$msg[1] = "Events, <input type=\"search\" id=\"gridsearch1\" placeholder=\"Search\" results=\"0\" class=\"gridsearch\" />";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#authGrid").css('font-size', '13px');
        jQuery("#authGrid").jqGrid('navGrid',"#pauthGrid",{refresh:false,search:false,edit:false,add:false,del:false});

        jQuery("#auth2Grid").jqGrid({
           url: "/admin/authuserlog.json",
           datatype: "json",
           height: \$(window).height() - 220,
           width:250,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'Login', 'Endereço' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'Login', 'Address' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",       index:'id', width: 4, sorttype: "int", key: true, hidden:true },
              { name:"alLogin",   index:'alLogin',  sortable:true, editable:true, width:45 },
              { name:"alAddress", index:'alAddress',  sortable:false, editable:true, width:45 }
           ],
           pager: '#pauth2Grid',
           editurl: 'clientArray',
           rowNum: '',
           rowList: [],
           pgbuttons: false,
           pgtext: null,
           gridview: true,
           viewrecords: false,
           sortable: true,
           ondblClickRow: function (selid, iRow,iCol) {
              var selcur = jQuery("#auth2Grid").jqGrid('getRowData', selid);
              var authleave = selcur['alLogin'];
              authleave += " "+selcur['alAddress'];
              authleave = authleave.replace(/\\<strong\\>|\\<\\/strong\\>/g, "");
              document.getElementById('chcondition').style.display = 'block';
              document.getElementById('UserGrid').style.color = 'Red';
              document.getElementById('UserGrid').value = authleave;
              document.getElementById('UserGrid').size = authleave.lenght + 12;
              document.getElementById('UserGrid').disabled = true;
           },
           gridComplete: function() {
              searchColumn2[0] = jQuery("#auth2Grid").jqGrid('getCol','alLogin',true);
              searchColumn2[1] = jQuery("#auth2Grid").jqGrid('getCol','alAddress',true);
           },
javascript
$msg[0] = "Endereços, <input type=\"search\" id=\"gridsearch2\" placeholder=\"Search\" results=\"0\" class=\"gridsearch\" style=\"width:120;\" />";
$msg[1] = "Address, <input type=\"search\" id=\"gridsearch2\" placeholder=\"Search\" results=\"0\" class=\"gridsearch\" style=\"width:120;\" />";
print FILE "           caption: '$msg[$FW_LANG]'\n";
print FILE << "javascript";
        });
        jQuery("#auth2Grid").css('font-size', '13px');
        jQuery("#auth2Grid").jqGrid('navGrid',"#pauth2Grid",{refresh:false,search:false,edit:false,add:false,del:false});

        // Grid filters
        jQuery('#gridsearch1').keyup(function () {
           var find = new Array();
           var searchString = jQuery(this).val().toLowerCase();
           for (var i=0; i<4; i++) {
              jQuery.each(searchColumn1[i],function() {
                  if (!find[parseInt(this.id)-1]) {
                     if(this.value.toLowerCase().indexOf(searchString) == -1) {
                       jQuery('#'+this.id).hide();
                     } else {
                       jQuery('#'+this.id).show();
                       find[parseInt(this.id)-1] = 1;
                     }
                  }
              });
           }
        });
        jQuery('#gridsearch2').keyup(function () {
           var find = new Array();
           var searchString = jQuery(this).val().toLowerCase();
           for (var i=0; i<2; i++) {
              jQuery.each(searchColumn2[i],function() {
                  if (!find[parseInt(this.id)-1]) {
                     if(this.value.toLowerCase().indexOf(searchString) == -1) {
                       jQuery('#'+this.id, "#auth2Grid").hide();
                     } else {
                       jQuery('#'+this.id, "#auth2Grid").show();
                       find[parseInt(this.id)-1] = 1;
                     }
                  }
              });
           }
        });

    });

  </script>
javascript
    $msg[0] = "Eventos de autentica&ccedil;&atilde;o";
    $msg[1] = "Auth events";
    my $mstyle = menustyle("$msg[$FW_LANG]");
    print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE>
  <span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG]</span>

  <DIV align="center">
HTMLCODE

$msg[0] = "<i><strong>Eventos</strong>: Exibe o log dos eventos de autentica&ccedil;&atilde;o!</i>";
$msg[1] = "<i><strong>Events</strong>: Display the log auth events!</i>";
print FILE << "javascript";
    <table><tbody><tr>
    <td>
      <center>$msg[$FW_LANG]</center>
      <table id="authGrid" width="100%" style="font-size:12px;"></table>
      <div id="pauthGrid" width="100%" style="font-size:12px;"></div><BR />
    </td>
    <td>
javascript
$msg[0] = "<i><strong>Usu&aacute;rios online</strong></i>";
$msg[1] = "<i><strong>Online users</strong></i>";
print FILE "      <center>$msg[$FW_LANG]</center>\n";
print FILE << "javascript";
      <table id="auth2Grid" width="100%" style="font-size:12px;"></table>
      <div id="pauth2Grid" width="100%" style="font-size:12px;"></div><BR />
      <DIV align="center" valign="center" id="chcondition">
        <form name="fchcond" action="/admin/authleave.cgi" method="post">
javascript
$msg[0] = "Desconectar o endereço?";
$msg[1] = "Disconnect address?";
print FILE "        <p style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></p>\n";
print FILE "        <INPUT id='UserGrid' name=\"userLeave\" type=\"textbox\" size=\"20\" style=\"background-color: #bec2c8; font-weight: bold; Font-Family: Arial, Helvetica; height:24px; width:160px;\">\n";
$msg[0] = "sim";
$msg[1] = "yes";
print FILE "        <INPUT type=\"button\" value=\"$msg[$FW_LANG]\" onclick=\"return do_submit();\">\n";
$msg[0] = "n&atilde;o";
$msg[1] = "no";
print FILE "        <INPUT type=\"button\" value=\"$msg[$FW_LANG]\" onclick=\"return document.getElementById('chcondition').style.display= 'none';\">\n";
print FILE << "javascript";
      </form></DIV>
    </td>
    </tr></tbody></table>
    </body></html>
javascript

  close(FILE);
  return get_file("text/html", $htmlfile);
}

return 1;
