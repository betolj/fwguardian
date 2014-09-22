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

sub createdb {
   my $user = shift;
   my $pass = shift;
   my $server = shift;
   my $fg_account = shift;
   my $fg_pass = shift;

   my @SQL = ();
   my $sth;
   my $dbh_r = DBI->connect("dbi:mysql:mysql:$server:3306", $user, $pass) or return -1;

   push(@SQL, "CREATE DATABASE IF NOT EXISTS squidimport");
   push(@SQL, "USE squidimport");
   push(@SQL, "GRANT ALL privileges on squidimport.* to $fg_account identified by '$fg_pass' with GRANT OPTION");

   # Squidlog "external" tables
   push(@SQL, "CREATE TABLE IF NOT EXISTS proxy (proxy_id SMALLINT NOT NULL AUTO_INCREMENT PRIMARY KEY, proxy_name VARCHAR(20) NOT NULL, INDEX id_proxyname (proxy_name)) ENGINE=InnoDB");
   push(@SQL, "CREATE TABLE IF NOT EXISTS mime (mime_id SMALLINT NOT NULL AUTO_INCREMENT PRIMARY KEY, mime_name VARCHAR(40) NOT NULL) ENGINE=InnoDB");
   push(@SQL, "CREATE TABLE IF NOT EXISTS method (meth_id TINYINT NOT NULL AUTO_INCREMENT PRIMARY KEY, meth_name VARCHAR(25) NOT NULL) ENGINE=InnoDB");
   push(@SQL, "CREATE TABLE IF NOT EXISTS rstatus (rstatus_id SMALLINT NOT NULL AUTO_INCREMENT PRIMARY KEY, rstatus_name VARCHAR(40) NOT NULL) ENGINE=InnoDB");
   push(@SQL, "CREATE TABLE IF NOT EXISTS urlcut (url_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, url_name TEXT NOT NULL) ENGINE=InnoDB");
   push(@SQL, "CREATE TABLE IF NOT EXISTS hostcli  (host_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, host_name VARCHAR(20) NOT NULL, INDEX id_hostname (host_name)) ENGINE=InnoDB");
   push(@SQL, "CREATE TABLE IF NOT EXISTS username (user_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, user_name VARCHAR(16) NOT NULL DEFAULT '-', INDEX id_username (user_name)) ENGINE=InnoDB");
   push(@SQL, "CREATE INDEX id_urlname ON urlcut (url_name(30))");

   # Access table and foreign keys
   push(@SQL, "CREATE TABLE IF NOT EXISTS access (access_id BIGINT NOT NULL PRIMARY KEY, host_id INT NOT NULL, access_timestamp INT NOT NULL, access_tsms INT, access_resptime INT DEFAULT 0, rstatus_id SMALLINT NOT NULL, access_reqsize INT DEFAULT 0, meth_id TINYINT NOT NULL, url_id INT, user_id INT NOT NULL, access_hier VARCHAR(30), mime_id SMALLINT NOT NULL, proxy_id SMALLINT NOT NULL) ENGINE=InnoDB");
   push(@SQL, "ALTER TABLE access ADD fk_host_id  FOREIGN KEY ( host_id ) REFERENCES hostcli ( host_id )");
   push(@SQL, "ALTER TABLE access ADD CONSTRAINT fk_mime_id    FOREIGN KEY ( mime_id )  REFERENCES mime ( mime_id )");
   push(@SQL, "ALTER TABLE access ADD CONSTRAINT fk_rstatus_id FOREIGN KEY ( rstatus_id )  REFERENCES rstatus ( rstatus_id )");
   push(@SQL, "ALTER TABLE access ADD CONSTRAINT fk_proxy_id   FOREIGN KEY ( proxy_id ) REFERENCES proxy ( proxy_id )");
   push(@SQL, "ALTER TABLE access ADD CONSTRAINT fk_method_id  FOREIGN KEY ( meth_id )  REFERENCES method ( meth_id )");
   push(@SQL, "ALTER TABLE access ADD fk_url_id  FOREIGN KEY ( url_id )   REFERENCES urlcut ( url_id )");
   push(@SQL, "ALTER TABLE access ADD fk_user_id FOREIGN KEY ( user_id )  REFERENCES username ( user_id )");

   my $bug=0;
   foreach (@SQL) {
      $sth = $dbh_r->prepare("$_");
      $sth->execute or $bug=1;
      if ($bug == 1) {
         print $_;
         return 1;
      }
   }
   $dbh_r->disconnect;

   return 1;
}

# set the admin user (root) and password - only for database create (can removed after)
my $suser = "root";
my $spass = "pass123";
my $server = "127.0.0.1";

# set the squid user and password database
my $fg_user = "sqloguser";
my $fg_pass = "pass123";

# Reading database account from config file
my $cfgfile="/etc/squidimport.conf";
if (-e $cfgfile) {
   open FILE, "<$cfgfile";
   while (<FILE>) {
     $_ =~ s/\n//;
     $_ =~ s/"/\\"/g;
     $_ =~ s/'/\\'/g;
     my ($cmd, $data) = split /\s+/, $_, 2;

     if ($cmd eq "sql.admin.user") { $suser = $data; }
     elsif ($cmd eq "sql.admin.pass") { $spass = $data; }
     elsif ($cmd eq "sql.admin.server") { $server = $data; }
     elsif ($cmd eq "sql.squid.user") { $fg_user = $data; }
     elsif ($cmd eq "sql.squid.pass") { $fg_pass = $data; }
   }
   close (FILE);
}

my $fg_account = "$fg_user\@$server";


# Connect to squidimport
my $SQL = "";
my $sth;
my $dsn = "dbi:mysql:squidimport:$server:3306";
my $dbh = DBI->connect($dsn, $fg_user, $fg_pass);
return -1 if ($DBI::err == 2003);

if (not $dbh) {
   createdb($suser, $spass, $server, $fg_account, $fg_pass);
   $dbh = DBI->connect($dsn, $fg_user, $fg_pass) or exit;
}

print "\n1. Wait: loading external tables...";

my $row;
my %h_proxy = ();
my %h_host = ();
my %h_username = ();
my %h_mime = ();
my %h_method = ();
my %h_url = ();

# Read hosts list
$sth = $dbh->prepare("SELECT host_id, host_name FROM hostcli");
$sth->execute();
my $max=0;
while ($row = $sth->fetchrow_arrayref()) {
   if ($row) {
      $max=@$row[0] if (@$row[0] > $max);
      $h_host{@$row[1]} = @$row[0];
   }
}
$h_host{'id'} = $max;

# Read username list
$sth = $dbh->prepare("SELECT user_id, user_name FROM username");
$sth->execute();
$max=0;
while ($row = $sth->fetchrow_arrayref()) {
   if ($row) {
      $max=@$row[0] if (@$row[0] > $max);
      $h_username{@$row[1]} = @$row[0];
   }
}
$h_username{'id'} = $max;

# Read proxy list
$sth = $dbh->prepare("SELECT proxy_id, proxy_name FROM proxy");
$sth->execute();
$max=0;
while ($row = $sth->fetchrow_arrayref()) {
   if ($row) {
      $max=@$row[0] if (@$row[0] > $max);
      $h_proxy{@$row[1]} = @$row[0];
   }
}
$h_proxy{'id'} = $max;

# Read mime list
$sth = $dbh->prepare("SELECT mime_id, mime_name FROM mime");
$sth->execute();
$max=0;
while ($row = $sth->fetchrow_arrayref()) {
   if ($row) {
      $max=@$row[0] if (@$row[0] > $max);
      $h_mime{@$row[1]} = @$row[0];
   }
}
$h_mime{'id'} = $max;

# Read method list
$sth = $dbh->prepare("SELECT meth_id, meth_name FROM method");
$sth->execute();
$max=0;
while ($row = $sth->fetchrow_arrayref()) {
   if ($row) {
      $max=@$row[0] if (@$row[0] > $max);
      $h_method{@$row[1]} = @$row[0];
   }
}
$h_method{'id'} = $max;

# Read req_status list
$sth = $dbh->prepare("SELECT rstatus_id, rstatus_name FROM rstatus");
$sth->execute();
$max=0;
while ($row = $sth->fetchrow_arrayref()) {
   if ($row) {
      $max=@$row[0] if (@$row[0] > $max);
      $h_rstatus{@$row[1]} = @$row[0];
   }
}
$h_rstatus{'id'} = $max;

# Read url list
$sth = $dbh->prepare("SELECT url_id, url_name FROM urlcut");
$sth->execute();
$max=0;
while ($row = $sth->fetchrow_arrayref()) {
   if ($row) {
      $max=@$row[0] if (@$row[0] > $max);
      $h_url{@$row[1]} = @$row[0];
   }
}
$h_url{'id'} = $max;

my ($access_id) = $dbh->selectrow_array("select MAX(access_id) from access");

print "\n2. Writting data...";

# Drop index and insert log data into squidimport tables
my $sqlct=0;
my @SQL=();
if ($access_id > 1) {
   push(@SQL, "DROP INDEX id_htimestamp on access");
   push(@SQL, "DROP INDEX id_utimestamp on access");
   foreach (@SQL) {
      $sth = $dbh->prepare("$_");
      $sth->execute;
   }
}
foreach my $logfile (`ls /tmp/access.log.proxy*`) {
   $logfile =~ s/\n//;
   print "\n- Reading $logfile (wait)...";

   if (-e $logfile) {
      @SQL = ();
      #push(@SQL, "LOCK TABLES urlcut WRITE, hostcli WRITE, username WRITE, proxy WRITE, mime WRITE, method WRITE, rstatus WRITE, access WRITE, ac_host WRITE, ac_user WRITE");
      push(@SQL, "START TRANSACTION");
      open FILE, "<$logfile";
      print "\nFinish $logfile.";
      while (<FILE>) {
         $_ =~ s/\n//;
         $_ =~ s/\'/\\\'/g;
         $_ =~ s/\"/\\\"/g;
         my ($timestamp, $resptime, $host, $reqstatus, $reqsize, $reqmethod, $url, $username, $hier, $mime) = split /\s+/, $_;
         ($timestamp, $tsms) = split /\./, $timestamp, 2;
         $host = "$host" if ($host =~ /^([0-9]+.){3}[0-9]+$/);
         my (undef, undef, $proxy) = split /\./, $logfile, 3;

         $urlcut = $url;
         (undef, undef, $urlcut, undef) = split /\//, $url, 4 if ($url =~ /\//);
         if ($urlcut =~ /(metric\.gstatic|storage\.live|yahoodns|google|youtube|imageshack)\.(com|us|net)($|:443$)/) {
            my $url_s = "";
            $url_s = ":443" if ($urlcut =~ /:443$/);
            $urlcut = "metric.gstatic.com$url_s" if ($urlcut =~ /metric\.gstatic\.com($|:443$)/);
            $urlcut = "users.storage.live.com$url_s" if ($urlcut =~ /users\.storage\.live\.com($|:443$)/);
            $urlcut = "pack.google.com$url_s" if ($urlcut =~ /\.pack\.google\.com($|:443$)/);
            $urlcut = "imageshack.us$url_s" if ($urlcut =~ /\.imageshack\.us($|:443$)/);
            $urlcut = "c.youtube.com$url_s" if ($urlcut =~ /\.c\.youtube\.com($|:443$)/);
            $urlcut = "b.yahoodns.net$url_s" if ($urlcut =~ /\.b.yahoodns.net($|:443$)/);
         }
         #(undef, $urlcut) = split /\./, $urlcut, 2;

         if (!$h_host{$host} && $host) {
            $h_host{'id'}++;
            $h_host{$host} = $h_host{'id'};
            push(@SQL, "INSERT INTO hostcli (host_id, host_name) VALUES ('$h_host{$host}', '$host')");
         }

         if ($h_host{$host} && $urlcut) {
            $proxy = "default" if (!$proxy);
            if (!$h_proxy{$proxy} && $proxy) {
               $h_proxy{'id'}++;
               $h_proxy{$proxy} = $h_proxy{'id'};
               push(@SQL, "INSERT INTO proxy (proxy_id, proxy_name) VALUES ('$h_proxy{$proxy}', '$proxy')");
            }
            if (!$h_username{$username}) {
               $h_username{'id'}++;
               $h_username{$username} = $h_username{'id'};
               push(@SQL, "INSERT INTO username (user_id, user_name) VALUES ($h_username{$username}, '$username')");
            }
            $mime = "-" if ($mime !~ /^[a-zA-Z0-9\-\/]+$/ || length($mime) < 6);
            if (!$h_mime{$mime} && $mime) {
               $h_mime{'id'}++;
               $h_mime{$mime} = $h_mime{'id'};
               push(@SQL, "INSERT INTO mime (mime_id, mime_name) VALUES ('$h_mime{$mime}', '$mime')");
            }
            $reqmethod = "-" if (length($reqmethod) < 3);
            if (!$h_method{$reqmethod} && $reqmethod) {
               $h_method{'id'}++;
               $h_method{$reqmethod} = $h_method{'id'};
               push(@SQL, "INSERT INTO method (meth_id, meth_name) VALUES ('$h_method{$reqmethod}', '$reqmethod')");
            }
            $reqstatus = "-" if (length($reqstatus) < 4);
            if (!$h_rstatus{$reqstatus} && $reqstatus) {
               $h_rstatus{'id'}++;
               $h_rstatus{$reqstatus} = $h_rstatus{'id'};
               push(@SQL, "INSERT INTO rstatus (rstatus_id, rstatus_name) VALUES ('$h_rstatus{$reqstatus}', '$reqstatus')");
            }
            if (!$h_url{$urlcut} && $urlcut) {
               $h_url{'id'}++;
               $h_url{$urlcut} = $h_url{'id'};
               push(@SQL, "INSERT INTO urlcut (url_id, url_name)  VALUES ('$h_url{$urlcut}', '$urlcut')");
            }

            $access_id++;
            push(@SQL, "INSERT INTO access (access_id, host_id, access_timestamp, access_tsms, access_resptime, rstatus_id, access_reqsize, meth_id, url_id, user_id, access_hier, mime_id, proxy_id) VALUES ('$access_id', '$h_host{$host}', '$timestamp', '$tsms', '$resptime', '$h_rstatus{$reqstatus}', '$reqsize', '$h_method{$reqmethod}', '$h_url{$urlcut}', '$h_username{$username}', '$hier', '$h_mime{$mime}', '$h_proxy{$proxy}') ");

            if ($sqlct > 5000 || eof FILE) {
               #push(@SQL, "UNLOCK TABLES");
               push(@SQL, "COMMIT");
               foreach (@SQL) {
                  $sth = $dbh->prepare("$_");
                  $sth->execute or print "\nError: $_";
               }
               @SQL = ();
               push(@SQL, "START TRANSACTION");
               #push(@SQL, "LOCK TABLES urlcut WRITE, hostcli WRITE, username WRITE, proxy WRITE, mime WRITE, method WRITE, rstatus WRITE, access WRITE, ac_host WRITE, ac_user WRITE");
               $sqlct=0;
            }
            $sqlct++;
         }
      }
        
      close (FILE);
  }
}
print "\n";

# Building INDEX
@SQL=();
push(@SQL, "ALTER TABLE access ADD INDEX id_htimestamp (host_id,access_timestamp)");
push(@SQL, "ALTER TABLE access ADD INDEX id_utimestamp (user_id,access_timestamp)");
foreach (@SQL) {
   $sth = $dbh->prepare("$_");
   $sth->execute or print "\nError: $_";
}

$dbh->disconnect();

