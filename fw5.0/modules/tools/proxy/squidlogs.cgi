#!/usr/bin/perl
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Will be used in proxy reports (in future releases - planning)
#

use DBI;

local ($buffer, @pairs, $pair, $name, $value, %FORM);

    # Read in text
    $ENV{'REQUEST_METHOD'} =~ tr/a-z/A-Z/;
    if ($ENV{'REQUEST_METHOD'} eq "POST")
    {
        read(STDIN, $buffer, $ENV{'CONTENT_LENGTH'});
    }else {
	$buffer = $ENV{'QUERY_STRING'};
    }

    # Split information into name/value pairs
    @pairs = split(/&/, $buffer);
    foreach $pair (@pairs)
    {
	($name, $value) = split(/=/, $pair);
	$value =~ tr/+/ /;
	$value =~ s/%(..)/pack("C", hex($1))/eg;
	$FORM{$name} = $value;
    }

$ts_to  = $FORM{idto};
$ts_from = $FORM{idfrom};
$sq_hostlist = $FORM{sqhostlist};
$sq_url = $FORM{squrl};

# set the admin user (root) and password
my $suser = "root";
my $spass = "senha123";
my $server = "127.0.0.1";

# set the squid user and password database
my $fg_user = "sqloguser";
my $fg_pass = "senha123";
my $fg_account = "$fg_user\@$server";


# Connect to squidconf
my $SQL = "";
my $sth;
my $dsn = "dbi:mysql:squidconf:$server:3306";
my $dbh = DBI->connect($dsn, $fg_user, $fg_pass);
return -1 if ($DBI::err == 2003);

my $sqlct = 0;
my $SQLfilter = "";
if (not $dbh) {
   $msgtext = "ERRO!<FONT color='Red'><h2>Não foi possível conectar ao banco de dados</h2></FONT>";
}
else {
   # Getting host list
   my $hlist = "";
   my $cthost=0;
   foreach (split /\s|,/, $sq_hostlist) {
      if ($cthost == 0) {
         $hlist = "'h-$_'";
      }
      else {
         $hlist = "$hlist, 'h-$_'"
      }
      $cthost++;
   }

   # SQL Filter
   if ($hlist ne "" || $ts_from || $ts_to || $sq_url) {
      if ($hlist ne "") {
         $hlist =  "hcl.host_name IN ($hlist)";
         $SQLfilter = "$hlist";
         $sqlct++;
      }
      if ($ts_from) {
         $tsfrom = "ah.access_timestamp >= UNIX_TIMESTAMP('$ts_from')";
         $tsfrom = "and $tsfrom" if ($sqlct > 0);
         $SQLfilter = "$SQLfilter $tsfrom";
         $sqlct++;
      }
      if ($ts_to) {
         $tsto = "ah.access_timestamp <= UNIX_TIMESTAMP('$ts_to')";
         $tsto = "and $tsto" if ($sqlct > 0);
         $SQLfilter = "$SQLfilter $tsto";
         $sqlct++;
      }
      if ($sq_url) {
         $squrl = "uc.url_name like '$sq_url'";
         $squrl = "and $squrl" if ($sqlct > 0);
         $SQLfilter = "$SQLfilter $squrl";
      }
      $SQLfilter = "where $SQLfilter";
   }
   else {
      $SQLfilter = "LIMIT 100";
   }

   $sth = $dbh->prepare("select ah.access_timestamp, ah.access_tsms, ac.access_resptime, hcl.host_name, rs.rstatus_name, ac.access_reqsize, mt.meth_name, uc.url_name, ac.access_hier, mi.mime_name  from ac_host ah inner join hostcli hcl on ah.host_id = hcl.host_id inner join access ac on ac.access_id = ah.access_id inner join rstatus rs on rs.rstatus_id = ac.rstatus_id inner join method mt on mt.meth_id = ac.meth_id inner join urlcut uc on uc.url_id = ac.url_id  inner join mime mi on mi.mime_id = ac.mime_id  $SQLfilter");
   $sth->execute();

   open FILE, ">/var/tmp/squidlogs.logs";
   while (my $row = $sth->fetchrow_arrayref()) {
      if ($row) {
         $logtext="";
         my $ctrow=0;

         # Getting rows
         foreach (@$row) {
            $ctrow++;
            if ($ctrow eq 2) {
               my $filled = sprintf("%03d", $_);;
               $logtext = "$logtext.$filled" ;
            }
            else {
               if ($ctrow eq 1) {
                  $logtext = "$_";
               }
               else {
                  $_ = sprintf ("%6d", $_) if ($ctrow eq 3);
                  $_ =~ s/^h-//  if ($ctrow eq 4);
                  $logtext = "$logtext -" if ($ctrow eq 9);
                  $logtext = "$logtext $_";
               }
            }
         }

         # Writting squid logs
         print FILE "$logtext\n";
      }
   }
   close(FILE);
   $dbh->disconnect();
}


print "Content-type:text/html\r\n\r\n";
print "<html>";
print "<meta HTTP-EQUIV='Refresh' CONTENT='3;URL=/websquid.html'>";
print "<head>";
print "<title>FwGuardian - SQL Squid Report 1.0</title>";
print "</head>";
print "<body>";
print "$msgtext<BR />Filtro SQL: $SQLfilter";
print "</body>";
print "</html>";

1;
