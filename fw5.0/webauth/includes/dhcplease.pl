#!/usr/bin/perl -w

#Rev.0 - Version 5.0

# "Make web page lease.html"
sub get_lease {
    my $htmlfile="$HTMLDIR/admin/dynhttp/lease.html";

    my @msg = ("", "");

    ### Making lease.html
    open FILE, ">$htmlfile";

print FILE << "javascript";
  <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
  <html><head>

  <meta http-equiv="content-type" content="text/html;charset=utf-8" />
  <script type="text/javascript" src="/js/mootools-core-1.3.2-full-compat-yc.js"></script>
  <script type="text/javascript" src="/js/mootools-more-1.3.2.1.js"></script>

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

  </style>

  <script type="text/javascript" src="/js/jquery-1.7.2.min.js"></script>
  <script type="text/javascript" src="/js/i18n/grid.locale-en.js"></script>
  <script type="text/javascript" src="/js/i18n/grid.locale-pt-br.js"></script>
  <script type="text/javascript" src="/js/jquery.jqGrid.min.js"></script>
  <script type="text/javascript">
        jQuery.jgrid.no_legacy_api = true;
        jQuery.jgrid.useJSON = true;
  </script>

  <script type="text/javascript">
     document.addEvent('domready', function(){

        // Make jqgrid
        jQuery("#dhcpLease").jqGrid({
           url:'/admin/lease.js',
           datatype: "json",
           height: \$(window).height() - 240,
           width: \$(window).width() - 40,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'Endereço IP', 'Hostname', 'Início', 'Termino', 'Endereço MAC', 'ETher/Token' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'IP Address', 'Hostname', 'Lease start', 'Lease End', 'MAC Address', 'ETher/Token' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",      index:'id', width: 4, sorttype: "int", key: true },
              { name:"ipL",     index:'ipL',     sortable:true,  width:20 },
              { name:"clientL", index:'clientL', sortable:true,  width:20 },
              { name:"sLease",  index:'sLease',  sortable:true,  width:18 },
              { name:"eLease",  index:'eLease',  sortable:true, width:18 },
              { name:"macL",    index:'macL',    sortable:false, width:20 },
              { name:"macType", index:'macType', sortable:false, width:15 }
           ],
           pager: '#pdhcpLease',
           rowNum: '',
           rowList: [],
           pgbuttons: false,
           pgtext: null,
           sortable: true,
           gridview: true,
           viewrecords: false,
           caption: "DHCP Leasing"
        });
        jQuery("#dhcpLease").css('font-size', '13px');
        jQuery("#dhcpLease").jqGrid('navGrid',"#pdhcpLease",{refresh:false,search:false,edit:false,add:false,del:false});

        // Grid resize
        \$(window).bind('resize', function() {
            \$("#jqgrid").setGridWidth(\$(window).width() - 120);
        }).trigger('resize');

    });

  </script>\n\n

javascript
   my $mstyle = menustyle("DHCP lease ");
   print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE>
  <span id="text" style="Position: Relative; font-weight:bold;">&nbsp; DHCP lease</span><BR />

  <DIV align="center">
HTMLCODE

$msg[0] = "<i><strong>DHCP leases</strong>: exibe apenas mapeamentos ativos!</i>";
$msg[1] = "<i><strong>DHCP leases</strong>: displays only active mappings!</i>";
print FILE "<div align='left'><span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 20px;\">$msg[$FW_LANG]</span></div><BR />\n";
my $lease = dhcpConf();
if (-e "$lease") {
   print FILE "    <table id=\"dhcpLease\" style=\"font-size:12px;\"></table>\n";
   print FILE "    <div id=\"pdhcpLease\" style=\"font-size:12px;\"></div>\n";
}
else {
   $msg[0] = "ERRO: Serviço DHCP não encontrado!<BR />$lease";
   $msg[1] = "ERROR: DHCP service not found!<BR />$lease";
   print FILE "<BR /><BR /><h2><FONT color=\"Red\">$msg[$FW_LANG]</FONT></h2><BR /><BR />\n";
}
print FILE << "javascript";
    <BR />
    </body></html>
javascript

   close(FILE);
   return get_file("text/html", $htmlfile);
}

return 1;
