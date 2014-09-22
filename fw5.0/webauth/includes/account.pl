#!/usr/bin/perl

#Rev.0 - Version 5.0

# Account Manager

# CPF checks for Brazilian users
sub chkCpf {
  my ($cpf) = shift;
  my $ccpf = substr ($cpf, 0, 1);

  return 0 if (length($cpf) < 11 || length($cpf) > 11);
  return 0 if ($cpf =~ /[$ccpf]{11}+/);
  $cpf =~ s/[^0-9]//g;

  my $body = substr($cpf,0,9);
  my $dv = substr($cpf,9,2);
  my $d1 = 0;
  for ($i = 0; $i < 9; $i++) {
    $d1 += int(substr ($body, $i, 1)) * (10 - $i);
  }
  return 0 if ($d1 == 0);

  $d1 = 11 - ($d1 % 11);
  $d1 = 0 if ($d1 > 9);
  return 0 if (substr ($dv, 0, 1) != $d1);

  $d1 *= 2;
  for ($i = 0; $i < 9; $i++) {
     $d1 += int(substr($body, $i, 1)) * (11 - $i);
  }
  $d1 = 11 - ($d1 % 11);
  $d1 = 0 if ($d1 > 9);

  return 0 if (substr ($dv, 1, 1) != $d1);
  return 1;
}

# "Make web page sqlauth.html"
sub get_sqlauth {
    my $htmlfile="$HTMLDIR/admin/dynhttp/sqlauth.html";

    ### Making sqlauth.html
    open FILE, ">$htmlfile";

    CGI::Session->name("FWGSESS");
    my $session = CGI::Session->load(undef, $read_cookie, {Directory=>'/tmp/sessions'});
    my $sqlQuery = $session->param('sqlQuery');

    ### Getting SQL users
    my $sth;
    my $dbh;
    my $sql_ok = 1;
    if ($sqlQuery) {
      my $SQL;
      if ($sqlQuery ne "*") {
         if ($sqlQuery !~ /%/) { $sqlQuery = "= '$sqlQuery'"; }
         else { $sqlQuery = "like '$sqlQuery'"; }
         $sqlQuery = "where fg_username $sqlQuery or fg_fullname $sqlQuery or fg_email $sqlQuery";
      }
      else {
         $sqlQuery = "";
      }
      $SQL = "select * from fgaccount $sqlQuery order by fg_fullname ";
      $dbh = sqladm("connect") or $sql_ok=0;
      if ($sql_ok == 1 && $dbh != -1) {
         $sth = $dbh->prepare("$SQL") or $sql_ok=0;
         $sth->execute or $sql_ok=0;
      }
      else {
         $sql_ok = 0;
      }
    }
    else {
      $sql_ok = 0;
    }

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
           \$("#btadd").click(function() {
                 document.fiaccount.bt_ins.click();
                 return false;
           });
           \$("#btupd").click(function() {
                 document.fiaccount.bt_upd.click();
                 return false;
           });
           \$("#btcan").click(function() {
                 document.location.reload(true);
                 return false;
           });
           \$("#btdel").click(function() {
                 chkdel();
                 return false;
           });
           \$("#btres").click(function() {
                 document.fiaccount.bt_res.click();
                 return false;
           });
        });
  </script>

  <script type="text/javascript">

    jQuery(document).ready(function(){

        // Filter array
        var searchColumn1 = new Array();

        jQuery("#accountGrid").jqGrid({
           url:'/admin/sqlUser.js',
           datatype: "json",
           height: \$(window).height() - 300,
           width:\$(window).width() - 50,
javascript
if ($FW_LANG == 0) {
   print FILE "           colNames:[ 'ID', 'Login', 'Bloqueada', 'Nome completo', 'Endereço', 'Email', 'RG', 'Tel. 1', 'Tel. 2', 'Criação', 'Primeiro login', 'Ultimo login' ],\n";
}
else {
   print FILE "           colNames:[ 'ID', 'Login', 'Locked', 'Full name', 'Address', 'Email', 'NID', 'Phone 1', 'Phone 2', 'Born', 'First login', 'Last login' ],\n";
}
print FILE << "javascript";
           colModel: [
              { name:"id",          index:'id', width: 30, sortable:true, sorttype: "int", key: true },
              { name:"fg_username", index:'fg_username', sortable:true, editable:false, width:120 },
              { name:"fg_lock",     index:'fg_lock', sortable:false, editable:false, edittype:"checkbox", editoptions:{value:"Yes:No"}, width:78 },
              { name:"fg_fullname", index:'fg_fullname', sortable:true, editable:false, width:235 },
              { name:"fg_haddr",    index:'fg_haddr', sortable:false, editable:false, width:280 },
              { name:"fg_email",    index:'fg_email', sortable:true, editable:false, width:220 },
              { name:"fg_NID",      index:'fg_NID', sortable:true, editable:false, width:130 },
              { name:"fg_phone",    index:'fg_phone', sortable:false, editable:false, width:130 },
              { name:"fg_phone2",   index:'fg_phone2', sortable:false, editable:false, width:130 },
              { name:"fg_ctlogin",  index:'fg_ctlogin', sortable:false, editable:false, width:140 },
              { name:"fg_ftlogin",  index:'fg_ftlogin', sortable:false, editable:false, width:140 },
              { name:"fg_ltlogin",  index:'fg_ltlogin', sortable:true, editable:false, width:140 }
           ],
           pager: '#paccountGrid',
           rowNum: 15,
           rowList: [15],
           pgbuttons: true,
           pgtext: null,
           gridview: true,
           viewrecords: true,
           sortable: true,
           shrinkToFit: false,
           ondblClickRow: function (selid, iRow,iCol) {
              var selcur = jQuery("#accountGrid").jqGrid('getRowData', selid);
              newUser();
              document.fiaccount.chkLock.checked = false;
              document.fiaccount.username.value = selcur['fg_username'];
              document.fiaccount.password.value = selcur['acPassword'];
              document.fiaccount.cpassword.value = selcur['acPassword'];
              document.fiaccount.FullName.value = selcur['fg_fullname'];
              document.fiaccount.NID_RG.value = selcur['fg_NID'];
              document.fiaccount.haddr.value = selcur['fg_haddr'];
              document.fiaccount.EMail.value = selcur['fg_email'];
              document.fiaccount.Phone.value = selcur['fg_phone'];
              document.fiaccount.Phone2.value = selcur['fg_phone2'];
              if (selcur['fg_lock'] == "<font color=\\"Red\\">lock</font>") document.fiaccount.chkLock.checked = true;
           },
           gridComplete: function() {
              searchColumn1[0] = jQuery("#accountGrid").jqGrid('getCol','fg_username',true);
              searchColumn1[1] = jQuery("#accountGrid").jqGrid('getCol','fg_fullname',true);
              searchColumn1[2] = jQuery("#accountGrid").jqGrid('getCol','fg_email',true);
              searchColumn1[3] = jQuery("#accountGrid").jqGrid('getCol','fg_NID',true);
           },
javascript
$msg[1] = "<INPUT type=\"button\" value=\" SQL \" onclick=\"javascript: return doSqlQuery();\" />";
$msg[0] = "Pesquisa: <input type=\"search\" id=\"gridsearch1\" placeholder=\"Search\" results=\"0\" class=\"gridsearch\" onkeydown=\"if (event.keyCode == 13) { doSqlQuery(); return false; }\" /> &nbsp; $msg[1]";
$msg[1] = "Search: <input type=\"search\" id=\"gridsearch1\" placeholder=\"Search\" results=\"0\" class=\"gridsearch\" onkeydown=\"if (event.keyCode == 13) { doSqlQuery(); return false; }\" /> &nbsp; $msg[1]";
print FILE "           caption: '$msg[$FW_LANG]'\n";
$msg[0] = "As senhas não conferem!";
$msg[1] = "No match passwords!";
print FILE << "javascript";
        });
        jQuery("#accountGrid").css('font-size', '13px');
        jQuery("#accountGrid").jqGrid('navGrid',"#paccountGrid",{refresh:false,search:false,edit:false,add:false,del:false});

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

        // Include new account
        \$("#accountGrid").jqGrid('navButtonAdd','#paccountGrid',{
javascript
$msg[0] = "Adicionar";
$msg[1] = "Add";
print FILE "           caption:\"&nbsp;$msg[$FW_LANG]\",\n";
print FILE << "javascript";
            onClickButton:function(){
               changepass(1); 
               newUser();
            }
        });
    });

    // Apply SQL filter
    function doSqlQuery() {
       document.flsAccount.sqlQuery.value = document.getElementById(\'gridsearch1\').value; 
       document.flsAccount.submit();
    }
  </script>

<script type="text/javascript">
<!--

  function chkpass() {
     if (document.fiaccount.password.disabled == false && document.fiaccount.password.value != document.fiaccount.cpassword.value) {
        alert('$msg[$FW_LANG]');
        document.fiaccount.password.value = '';
        document.fiaccount.cpassword.value = '';
        document.fiaccount.password.focus();
     }
  }

  function changepass(foenable) {
     if (document.fiaccount.password.disabled == true || foenable == 1) {
        document.fiaccount.password.disabled = false;
        document.fiaccount.cpassword.disabled = false;
        document.fiaccount.password.focus();
     }
     else {
        if (document.fiaccount.password.value == document.fiaccount.cpassword.value) {
           document.fiaccount.password.disabled = true;
           document.fiaccount.cpassword.disabled = true;
        }
        else chkpass();
     }
  }

  function chkdel() {
      var ccond = document.getElementById('chcondition');
      ccond.style.position = \'absolute\';
      ccond.style.display = \'block\';
      ccond.style.visibility = \'visible\';
  }

  function newUser() {
     document.flsAccount.style.visibility = "hidden";
     document.fiaccount.style.visibility = "visible";
     document.fiaccount.style.width = "90%";
     document.fiaccount.style.align = "center";
     document.fiaccount.username.focus();
  }

//-->
</script>

javascript

  my @msg = ("", "");
  $msg[0] = "Captive portal: Contas de usu&aacute;rio MySQL";
  $msg[1] = "Captive portal: MySQL User Account";
  my $mstyle = menustyle("$msg[$FW_LANG] ");
  print FILE "$mstyle";
print FILE << "HTMLCODE";
  </head>
  <body bgcolor='#F2F2F2' $STYLE>
  <span id="text" style="font-weight:bold;">&nbsp; $msg[$FW_LANG]</span>

  <DIV align="center">
HTMLCODE

  print FILE "<DIV align=\"left\"><i>";
  print FILE "<span style=\"Font-Family: Arial, Helvetica; Position: Relative; Left: 20px;\">";
  if ($FW_LANG == 0) {
    print FILE " 1. Os filtros se aplicam aos campos *Login, Nome completo, Email ou RG*<BR />";
    print FILE " 2. Com a string \'%\', a pesquisa ser&aacute; feita como uma express&atilde;o SQL \'like\'<BR />";
    print FILE " 3. Para visualizar todos usu&aacute;rios utilize como filtro \"*\" e clique em \"SQL\"<BR />";
  }
  else {
    print FILE " 1. The filters are applied for Login, Full Name, Email field or NID<BR />";
    print FILE " 2. With '%' string, the search will be made by a SQL 'like' expression<BR />";
    print FILE " 3. To show all users use a \"*\" filter and click on button \"SQL\"<BR />";
  }
  print FILE "</span></i></DIV><BR />";

  print FILE << "HTML_CODE";
  <form name="fiaccount" action="/admin/chaccount.cgi" method="post" accept-charset="utf-8" style="visibility:hidden; position:absolute;">
  <table style="height:68%; width:100%;" align="center" border="0" cellspacing="1" cellpadding="5"><tbody>
    <tr valign="center" align="center"><td>
HTML_CODE

  print FILE "<DIV align=\"center\" valign=\"center\" id=\"chcondition\">";
  $msg[0] = "Remover a conta?";
  $msg[1] = "Delete account?";
  print FILE "    <span style=\"Font-Family: Arial, Helvetica;\"><strong>$msg[$FW_LANG]</strong></span><BR /><BR />";
  $msg[0] = "Sim";
  $msg[1] = "Yes";
  print FILE "    <INPUT type=\"button\" value=\"$msg[$FW_LANG]\" onclick=\"return document.fiaccount.bt_del.click();\">";
  $msg[0] = "N&atilde;o";
  $msg[1] = "No";
  print FILE "    <INPUT type=\"button\" value=\"$msg[$FW_LANG]\" onclick=\"return document.getElementById('chcondition').style.display = 'none';\">";
  print FILE "    <BR />";
  print FILE "</DIV>";

  $msg[0] = "Inclusão de uma nova conta";
  $msg[1] = "Include a new user account";
  print FILE << "HTML_CODE";
    <BR />
    <table width="76%" border="0" cellspacing="1" cellpadding="5" bgcolor="#CCCCCC"><tbody>
       <tr><td bgcolor="#56556a">
          <font color="#FFFFFF" size="2" face="Arial, Helvetica, sans-serif"><strong>$msg[$FW_LANG]</strong></font>
       </td></tr>
       <tr><td bgcolor="#eeeeee"><BR />
          <table border="0" cellpadding="2" cellspacing="0" width="100%" height="60%"><tbody>
            <tr><td style="text-align: right;"><font face="Arial, Helvetica, sans-serif" color="#800000" size="2">
HTML_CODE
  $msg[0] = "<strong>Usu&aacute;rio:</strong>";
  $msg[1] = "<strong>Username:</strong>";
  print FILE "              $msg[$FW_LANG]</font></td>";
  print FILE << "HTML_CODE";
                <td><font face="Arial, Helvetica, sans-serif" color="#800000" size="2">
                    <input name="username" size="16" type="text">
                    &nbsp; &nbsp; <strong>Locked </strong><input name="chkLock" type="checkbox"></font>
            </td></td></tr>
            <tr><td style="text-align: right;"><font face="Arial, Helvetica, sans-serif" color="#800000" size="2">
HTML_CODE
  $msg[0] = "<strong>Senha:</strong>";
  $msg[1] = "<strong>Password:</strong>";
  print FILE "              $msg[$FW_LANG]</font></td>";
  print FILE "              <td><input name=\"password\" size=\"16\" type=\"password\" disabled=\"true\"><font face=\"Arial, Helvetica, sans-serif\" color=\"#800000\" size=\"2\">";
  $msg[0] = "<strong>Troca senha</strong>";
  $msg[1] = "<strong>Change Password</strong>";
  print FILE "               &nbsp; &nbsp; $msg[$FW_LANG] <input name=\"chkPasswd\" size=\"16\" type=\"checkbox\" onclick=\"return changepass(0);\"></font>";
  print FILE "          </td></tr>";
  print FILE "          <tr><td style=\"text-align: right;\"><font face=\"Arial, Helvetica, sans-serif\" color=\"#800000\" size=\"2\">";
  $msg[0] = "<strong>Confirme a senha:</strong>";
  $msg[1] = "<strong>Password confirm:</strong>";
  print FILE "                  $msg[$FW_LANG]</font></td>";
  print FILE "          <td><input name=\"cpassword\" size=\"16\" type=\"password\" onblur=\"return chkpass();\" disabled=\"true\"></td></tr>";
  print FILE "          <tr><td style=\"text-align: right;\"><font face=\"Arial, Helvetica, sans-serif\" size=\"1\"><BR />";
  $msg[0] = "<strong>Nome completo:</strong>";
  $msg[1] = "<strong>Full Name:</strong>";
  print FILE "                  $msg[$FW_LANG]</font></td>";
  print FILE "              <td><font face=\"Arial, Helvetica, sans-serif\" size=\"1\"><BR />";
  print FILE "                  <input size=\"45\" name=\"FullName\"></font></td></tr>";
  print FILE "          <tr><td style=\"text-align: right;\"><font face=\"Arial, Helvetica, sans-serif\" size=\"1\">";
  $msg[0] = "<strong>ID nacional(RG):</strong>";
  $msg[1] = "<strong>National ID:</strong>";
  print FILE "                 &nbsp; $msg[$FW_LANG]</font></td>";
  print FILE "              <td><font face=\"Arial, Helvetica, sans-serif\" size=\"1\">";
  print FILE "                  <input size=\"25\" name=\"NID_RG\"></font></td></tr>";
  print FILE "          <tr><td style=\"text-align: right;\"><strong><font face=\"Arial, Helvetica, sans-serif\" size=\"1\">";
  $msg[0] = "<strong>Endere&ccedil;o:</strong>";
  $msg[1] = "<strong>Home Addr:</strong>";
  print FILE "                  $msg[$FW_LANG]</font></td>";
  print FILE "              <td><font face=\"Arial, Helvetica, sans-serif\" size=\"1\">";
  print FILE "                  <input size=\"52\" name=\"haddr\"></font></td></tr>";
  print FILE "          <tr><td style=\"text-align: right;\"><strong><font face=\"Arial, Helvetica, sans-serif\" size=\"1\">";
  print FILE "                  <strong>Email:</strong></font></td>";
  print FILE "              <td><font face=\"Arial, Helvetica, sans-serif\" size=\"1\">";
  print FILE "                  <input size=\"30\" name=\"EMail\"></font></td></tr>";
  print FILE "          <tr><td style=\"text-align: right;\"><strong><font face=\"Arial, Helvetica, sans-serif\" size=\"1\"><BR />";
  $msg[0] = "<strong>Telefone(fixo):</strong>";
  $msg[1] = "<strong>Phone:</strong>";
  print FILE "                  $msg[$FW_LANG]</font></td>";
  print FILE "              <td><font face=\"Arial, Helvetica, sans-serif\" size=\"1\"><BR />";
  print FILE "                  <input size=\"20\" name=\"Phone\"></font></td></tr>";
  print FILE "          <tr><td style=\"text-align: right;\"><strong><font face=\"Arial, Helvetica, sans-serif\" size=\"1\">";
  $msg[0] = "<strong>Telefone (celular):</strong>";
  $msg[1] = "<strong>Phone (mobile):</strong>";
  print FILE "                  $msg[$FW_LANG]</font></td>";
  print FILE "              <td><font face=\"Arial, Helvetica, sans-serif\" size=\"1\">";
  print FILE "                  <input size=\"20\" name=\"Phone2\"></font></td></tr>";
  print FILE << "HTML_CODE";
            <tr><td><BR /></td></tr>
          </tbody></table>
       </td></tr>
    </tbody></table><BR />
      <DIV align="center">
HTML_CODE
    $msg[0] = "Adicionar";
    $msg[1] = "Add";
    print FILE "<a href=\"#\" id=\"btadd\" class=\"uibt\">$msg[$FW_LANG]</a>";
    $msg[0] = "Atualizar";
    $msg[1] = "Update";
    print FILE " <a href=\"#\" id=\"btupd\" class=\"uibt\">$msg[$FW_LANG]</a>";
    $msg[0] = "Cancelar";
    $msg[1] = "Cancel";
    print FILE " &nbsp; <a href=\"#\" id=\"btcan\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
    $msg[0] = "Apagar";
    $msg[1] = "Delete";
    print FILE " <a href=\"#\" id=\"btdel\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
    $msg[0] = "Limpar";
    $msg[1] = "Clear";
    print FILE " &nbsp; <a href=\"#\" id=\"btres\" class=\"uibt_em\">$msg[$FW_LANG]</a>";
  print FILE << "HTML_CODE";
        <input value="Insert" name="bt_ins" type="submit" onclick="changepass(1);" style="visibility:hidden; position:absolute;">
        <input value="Update" name="bt_upd" type="submit" style="visibility:hidden; position:absolute;">
        <input value="Delete" name="bt_del" type="submit" style="visibility:hidden; position:absolute;">
        <input value="Reset"  name="bt_res" type="reset" style="visibility:hidden; position:absolute;">
      </DIV>
    </td></tr>
  </tbody></table>
  </form><BR />
HTML_CODE

    print FILE "<form name=\"flsAccount\" action=\"/admin/chsqlacct.cgi\" method=\"post\">";
    print FILE "<input type=\"textbox\" value=\"0\" name=\"AcFieldCt\" style=\"visibility:hidden; position:absolute;\" />";
    print FILE "<input name=\"sqlQuery\" type=\"textbox\" size=\"40\" style=\"visibility:hidden; position:absolute;\" />";
    # --- SQL Accounts (captive portal addon) ---
print FILE << "HTMLCODE";
    <table id="accountGrid" width="100%" style="font-size:12px;"></table>
    <div id="paccountGrid" width="100%" style="font-size:12px;"></div>
HTMLCODE

    print FILE "</form>";
    print FILE "</DIV></body></html>";
    close(FILE);

    return get_file("text/html", $htmlfile);
}

# Change SQL filter
sub chsqlacct {
   my $s = shift;
   my $SQL = undef;
   my @dvalue = ();
   my $txtvalue = "";
   my @msg = ("", "");
   my $res = HTTP::Response->new();

   foreach my $lines (split /&/, $s) {
      $lines = str_conv($lines);
      @dvalue = split /=/, $lines;
      if ($dvalue[0] eq "sqlQuery") {
        $SQL = $dvalue[1];
        $SQL =~ s/\+/ /g;
        last;
      }
   }
   if ($SQL) {
      CGI::Session->name("FWGSESS");
      my $session = CGI::Session->load(undef, $read_cookie, {Directory=>'/tmp/sessions'});
      $session->param("sqlQuery", "$SQL");
      $session->flush;
      $session->close;
      $msg[0] = "Filtro aplicado com sucesso!";
      $msg[1] = "Filter applied successfully!";
      $txtvalue = msgbox("info", "$msg[$FW_LANG]", "");
   }
   else { 
      $msg[0] = "Nada a ser feito!";
      $msg[1] = "Nothing to do!";
      $txtvalue = msgbox("info", "$msg[$FW_LANG]", "");
   }
   my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"2;URL=/admin/sqlauth.cgi\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
   $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
   $res->content($txtvalue);
   return $res;
}

# Include new user
sub chaccount {
   my $s = shift;
   my $cmd = shift;
   my $where = shift;
   my $lock = 0;
   my $txtvalue = "";
   my @msg = ("", ""), @msg2 = ("", "");
   my $username = "", $password = "", $cpassword = "", $fullname = "", $nid = "", $email = "", $phone = "";

   my $url = "/admin/sqlauth.cgi";
   my $complet = 0;
   my %upd = ();
   my @dvalue = ();
   my $res = HTTP::Response->new();
   $cmd = "changepw" if ($s =~ /&bt_chpw=/ && $cmd eq "insert");

   foreach my $lines (split /&/, $s) {
      $lines = str_conv($lines);
      @dvalue = split /=/, $lines;
      $dvalue[1] =~ s/\'|\"//g;
      if ($cmd eq "changepw") {
         $dvalue[0] = "" if ($dvalue[0] =~ /^(username|password|cpassword|NID_RG|EMail)$/);
         $dvalue[0] =~ s/^ch_//;
      }
      if ($dvalue[0] eq "username") {
         $username = $dvalue[1];
         $username =~ s/\s+//g;
         $username =~ s/\.|\/|\-//g;
         $complet++ if ($dvalue[1]);
      }
      elsif ($dvalue[0] eq "password") {
         $password = $dvalue[1];
         $complet++ if ($dvalue[1]);
      }
      elsif ($dvalue[0] eq "cpassword") {
         $cpassword = $dvalue[1];
         $upd{"$cpassword"} = $cpassword;
         $complet++ if ($dvalue[1]);
      }
      elsif ($dvalue[0] eq "NID_RG") {
         $nid_rg = $dvalue[1];
         $nid_rg =~ s/\.|\/|\-//g;
         $nid_rg =~ s/\+/ /g;
         $nid_rg = substr( $nid_rg, 0, 25 );
         $complet++ if ($dvalue[1]);
      }
      elsif ($dvalue[0] eq "EMail") {
         $email = $dvalue[1];
         $email = substr( $email, 0, 40 );
         $complet++ if ($dvalue[1]);
      }
      elsif ($cmd ne "changepw") {
        if ($dvalue[0] eq "FullName") {
           $fullname = $dvalue[1];
           $fullname =~ s/\+/ /g;
           $fullname =~ s/\s+/ /g;
           $fullname = substr( $fullname, 0, 45 );
           $complet++ if ($dvalue[1]);
        }
        elsif ($dvalue[0] eq "haddr") {
           $haddr = $dvalue[1];
           $haddr =~ s/\+/ /g;
           $haddr = substr( $haddr, 0, 52 );
           $complet++ if ($dvalue[1]);
        }
        elsif ($dvalue[0] eq "Phone") {
           $phone = $dvalue[1];
           $phone =~ s/\+/ /g;
           $phone = substr( $phone, 0, 20 );
           $complet++ if ($dvalue[1]);
        }
        elsif ($dvalue[0] eq "Phone2") {
           $phone2 = $dvalue[1];
           $phone2 =~ s/\+/ /g;
           $phone2 = substr( $phone2, 0, 20 );
           $complet++ if ($dvalue[1]);
        }
        elsif ($dvalue[0] eq "chkLock") {
           $lock = 1 if ($dvalue[1] eq "on");
        }
        elsif ($dvalue[0] eq "bt_ins" && $cmd eq "detect") {
           $cmd = "adm_ins";
        }
        elsif ($dvalue[0] eq "bt_upd" && $cmd eq "detect") {
           $cmd = "update";
        }
        elsif ($dvalue[0] eq "bt_del" && $cmd eq "detect") {
           $cmd = "delete";
        }
      }
   }

   $url = "/" if ($cmd eq "insert" || $cmd eq "changepw");
   my $rt_sql = 0;
   if ($cmd eq "insert" || $cmd eq "adm_ins") {
      if ($complet == 9 && $password eq $cpassword) {
        ## use a CPF validator?
        my $ckcpf = 1;
        if ($sqlweb{'cpf'} ne "") {
           if ($sqlweb{'cpf'} eq "username") {
              $username =~ s/![0-9]+//g;
              $ckcpf = 0 if (chkCpf($username) == 0);
           }
           if ($sqlweb{'cpf'} eq "nid_rg") {
              $nid_rg =~ s/![0-9]+//g;
              $ckcpf = 0 if (chkCpf($nid_rg) == 0);
           }
        }

        if ($ckcpf == 1) {
          ## Insert a new user account 
          $rt_sql = sqladm("insert", $username, $password, $fullname, $nid_rg, $haddr, $email, $phone, $phone2, $lock);
          if ($rt_sql == 0) {
             $msg[0] = "Esta conta já existe";
             $msg[1] = "This account already exist";
             $msg2[0] = "<font color=\"red\"><i>Por favor, tente outro nome</i></font>";
             $msg2[1] = "<font color=\"red\"><i>Please try another login name</i></font>";
             log_info("$msg[$FW_LANG]: $username");

             $msg[$FW_LANG]="$msg[$FW_LANG] (<strong>*$username*</strong>)";
             if ($where eq "admin") {
                $txtvalue = msgbox("denied", "$msg[$FW_LANG]", "$msg2[$FW_LANG]");
                $url = "/account.html" if ($cmd eq "insert");
             }
             else {
                return get_forbidden("$msg[$FW_LANG]<BR /><BR />$msg2[$FW_LANG]", "", "");
             }
          }
          else {
             $msg[0] = "Conta de usuário registrada com sucesso";
             $msg[1] = "User account registered successfully";

             if ($where ne "admin" && $rt_sql != -1) {
                log_info("$msg[$FW_LANG]: $username");
                $res = get_file("text/html", "$HTMLDIR/sql_ok.html");
                ${$res->content_ref} =~ s/MESSAGE/$msg[$FW_LANG]/;
                return $res;
             }
             $msg[$FW_LANG]="$msg[$FW_LANG] (<strong>*$username*</strong>)";
             $txtvalue = msgbox("info", "$msg[$FW_LANG]", "");
          }
        }
        else {
           $msg[0] = "CPF inválido";
           $msg[1] = "Invalid CPF";
           $msg2[0] = "<font color=\"red\"><i>Configure seu CPF em $sqlweb{'cpf'} ...</i></font>";
           $msg2[1] = "<font color=\"red\"><i>Configure your CPF in $sqlweb{'cpf'} ...</i></font>";
           log_info("$msg[$FW_LANG]: $username");

           if ($where eq "admin") {
              $txtvalue = msgbox("denied", "$msg[$FW_LANG]!", "$msg2[$FW_LANG]");
              $url = "/account.html" if ($cmd eq "insert");
           }
           else {
              return get_forbidden("$msg[$FW_LANG]!<BR />< BR/>$msg2[$FW_LANG]", "", "");
           }
        }
      }
      else {
          $msg[0] = "Dados incompletos";
          $msg[1] = "Incomplete data";
          $msg2[0] = "<font color=\"red\"><i>Todos os campos s&atilde;o obrigat&oacute;rios</i></font>";
          $msg2[1] = "<font color=\"red\"><i>All fields are required</i></font>";
          log_info("$msg[$FW_LANG]");

          if ($where eq "admin") {
             if ($cpassword ne $password) {
                $txtvalue = "<BR /><i>The passwords do not match...</i><BR />";
                $txtvalue = "<BR /><i>As senhas não conferem...</i><BR />" if ($FW_LANG == 0);
             }
             $txtvalue = msgbox("denied", "$msg[$FW_LANG]! $txtvalue", "$msg2[$FW_LANG]");
          }
          else {
             return get_forbidden("$msg[$FW_LANG]!<BR /><BR />$msg2[$FW_LANG]", "", "");
          }
      }
   }
   elsif ($cmd eq "update") {
      if ($username ne "") {
          $rt_sql = sqladm("update", $username, $password, $fullname, $nid_rg, $haddr, $email, $phone, $phone2, $lock);
          if ($rt_sql == 0) {
             $msg[0] = "Conta não encontrada";
             $msg[1] = "Account not found";
             $txtvalue = msgbox("denied", "$msg[$FW_LANG]!", "");
          }
          else {
             $msg[0] = "Conta atualizada com sucesso";
             $msg[1] = "Account updated successfully";
             $txtvalue = msgbox("info", "$msg[$FW_LANG] (<strong>*$username*</strong>)", "");
          }
          log_info("$msg[$FW_LANG]: $username");
      }
      else {
          $msg[0] = "Atualização inválida ou nome de login vazio";
          $msg[1] = "Invalid update or null login name";
          $msg2[0] = "Verifique todos os campos novamente";
          $msg2[1] = "Check all fields again";
          $txtvalue = msgbox("denied", "$msg[$FW_LANG]!", "<font color=\"red\"><i>$msg2[$FW_LANG]</i></font>");
          log_info("$msg[$FW_LANG]");
      }
   }
   elsif ($cmd eq "changepw") {
      if ($complet == 5 && $password eq $cpassword) {
          $rt_sql = sqladm("changepw", $username, $password, "", $nid_rg, "", $email, "", "", "");
          if ($rt_sql == 0) {
             $msg[0] = "Esta conta não pode ser acessada";
             $msg[1] = "This account cannt be accessed";
             log_info("$msg[$FW_LANG]: $username");
             return get_forbidden("ERR... $msg[$FW_LANG]!", "", "");
          }
          else {
             if ($rt_sql != -1) {
                $msg[0] = "Senha alterada com sucesso";
                $msg[1] = "Password changed successfully";
                $res = get_file("text/html", "$HTMLDIR/sql_ok.html");
                ${$res->content_ref} =~ s/MESSAGE/$msg[$FW_LANG]!/;
                log_info("$msg[$FW_LANG]: $username");
                return $res;
             }
          }
      }
      else {
          $msg[0] = "Dados inválidos ou incompletos";
          $msg[1] = "Invalid or incomplete data";
          $msg2[0] = "<font color=\"red\"><i>Todos os campos s&atilde;o obrigat&oacute;rios</i><BR />*Ou valores incorretos*</font>";
          $msg2[1] = "<font color=\"red\"><i>All fields are required</i><BR />*Or wrong values*</font>";
          log_info("$msg[$FW_LANG]: $username");
          return get_forbidden("$msg[$FW_LANG]!<BR /><BR />$msg2[$FW_LANG]", "", "");
      }
   }
   elsif ($cmd eq "delete") {
      $rt_sql = sqladm("delete", $username, "", "", "", "", "", "", "", "", "");
      if ($rt_sql == 0) {
         $msg[0] = "Não foi possível remover esta conta";
         $msg[1] = "I cant delete this account";
         $msg2[0] = "<font color=\"red\"><i>Ou conta n&atilde;o encontrada</i></font>";
         $msg2[1] = "<font color=\"red\"><i>Or not found account</i></font>";
         $txtvalue = msgbox("denied", "$msg[$FW_LANG]!", "$msg2[$FW_LANG]");
      }
      else {
         $msg[0] = "Conta removida com sucesso";
         $msg[1] = "Account deleted successfully";
         $txtvalue = msgbox("info", "$msg[$FW_LANG]!", "");
      }
      log_info("$msg[$FW_LANG]: $username");
   }

   if ($rt_sql == -1) {
      $msg[0] = "Erro de conexão ao servidor MySQL ou SQL inválido";
      $msg[1] = "Error connecting to MySQL server or invalid SQL";
      $msg2[0] = "<font color=\"red\"><i>Verifique a disponibilidade do banco de dados...</i></font>";
      $msg2[1] = "<font color=\"red\"><i>Check the server database status...</i></font>";

      log_info("$msg[$FW_LANG]");
      return get_forbidden("$msg[$FW_LANG]!<BR /><BR />$msg2[$FW_LANG]", "", "") if ($where ne "admin");
      $txtvalue = msgbox("denied", "$msg[$FW_LANG]!", "$msg2[$FW_LANG]");
   }
   my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"3;URL=$url\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
   $txtvalue = "<html>$meta<body bgcolor='#F2F2F2' $STYLE>$txtvalue</body></html>";
   $res->content_type("text/html");
   $res->content($txtvalue);
   return $res;
}

return 1;
