#!/usr/bin/perl

#Rev.0 - Version 5.0

# Create database and table
sub createdb {
   my $user = shift;
   my $pass = shift;
   my $server = shift;
   my $fg_account = shift;
   my $fg_pass = shift;

   #printf "Can't connect to the DB: $DBI::errstr\nTry to create FwGuardian...";
   my @SQL = ();
   my $sth;
   my $dbh_r = DBI->connect("dbi:mysql:mysql:$server:3306", $user, $pass) or return -1;

   push(@SQL, "CREATE DATABASE IF NOT EXISTS fwguardian");
   push(@SQL, "USE fwguardian");
   push(@SQL, "GRANT ALL privileges on fwguardian.* to $fg_account identified by '$fg_pass' with GRANT OPTION");
   push(@SQL, "CREATE TABLE IF NOT EXISTS fgaccount (fg_username VARCHAR(16) NOT NULL, fg_password VARCHAR(50) NOT NULL, fg_fullname VARCHAR(45), fg_NID VARCHAR(25) NOT NULL, fg_haddr VARCHAR(52) NOT NULL, fg_email VARCHAR(40), fg_phone VARCHAR(20) NOT NULL, fg_phone2 VARCHAR(20) NOT NULL, fg_lock int(1) DEFAULT 0, fg_ctlogin DATETIME, fg_ftlogin DATETIME, fg_ltlogin DATETIME, PRIMARY KEY (fg_username), INDEX id_fullname (fg_fullname), INDEX id_email (fg_email)) ENGINE=InnoDB");
   foreach (@SQL) {
      $sth = $dbh_r->prepare("$_");
      $sth->execute or return -1;
   }
   $dbh_r->disconnect;

   return 1;
}

# Search user account
sub finduser {
   my $dbh = shift;
   my $username = shift;
   my $sth;
   $SQL = "select fg_username from fgaccount where fg_username='$username' ";
   $sth = $dbh->prepare("$SQL");
   $sth->execute;
   return 0 if ($sth->rows <= 0);
   return 1;
}

# MD5 Password calc
sub passmd5 {
   my $password = shift;;
   $password =~ s/(\/|\')//g;
   
   use Digest::MD5;
   
   my $salt="";
   my $md5pass = Digest::MD5->new;
   $salt = substr($password, 0,1).substr($password, length($password)/2, 1).substr($password, length($password)-1, 1);

   $md5pass = Digest::MD5->new;
   $md5pass->add($password.$salt);

   return $md5pass->b64digest;
}

# now connect and get a database handle
sub sqladm {

   use DBI;
   use POSIX qw( strftime );

   # SQL command
   my $cmd = shift;

   # data field
   my $username = shift;
   my $password = shift;
   my $fullname = shift;
   my $nid_rg = shift;
   my $haddr = shift;
   my $email = shift;
   my $phone = shift;
   my $phone2 = shift;
   my $lock = shift; 

   # set the admin user (root) and password
   my $suser = $sqlweb{'admin_user'};
   my $spass = $sqlweb{'admin_pass'};
   my $server = $sqlweb{'admin_server'};

   # set the fwguardian user and password database
   my $fg_user = $sqlweb{'web_user'};
   my $fg_pass = $sqlweb{'web_pass'};
   my $fg_account = "$fg_user\@$server";

   my $SQL = "";
   my $sth;
   my $dsn = "dbi:mysql:fwguardian:$server:3306";
   my $dbh = DBI->connect($dsn, $fg_user, $fg_pass);
   return -1 if ($DBI::err == 2003);

   if (not $dbh) {
      createdb($suser, $spass, $server, $fg_account, $fg_pass);
      $dbh = DBI->connect($dsn, $fg_user, $fg_pass) or return -1;
   }

   # Insert new user
   if ( $cmd eq "insert" ) {
      if ( finduser( $dbh, $username ) == 0 ) {
         $username =~ s/(\/|\')//g;
         $password = passmd5($password);
         my $ctlogin = strftime("%Y/%m/%d %k:%M:%S", localtime);
         $SQL = "insert into fgaccount (fg_username, fg_password, fg_fullname, fg_NID, fg_haddr, fg_email, fg_phone, fg_phone2, fg_ctlogin) values ('$username', '$password', '$fullname', '$nid_rg', '$haddr', '$email', '$phone', '$phone2', '$ctlogin')";
      }
      else {
         return 0;
      }
   }
   elsif ( $cmd eq "update" ) {
      if ( finduser( $dbh, $username ) == 1 ) {
         if ($password) {
             $password = passmd5($password);
             $password = "fg_password='$password',";
         }
         $fullname = "fg_fullname='$fullname'," if ($fullname);
         $nid_rg = "fg_NID='$nid_rg'," if ($nid_rg);
         $haddr = "fg_haddr='$haddr'," if ($haddr);
         $email = "fg_email='$email'," if ($email);
         $phone = "fg_phone='$phone'," if ($phone);
         $phone2 = "fg_phone2='$phone2'," if ($phone2);
         $lock = "fg_lock='$lock'";
         $SQL = "UPDATE fgaccount SET $password $fullname $nid_rg $haddr $email $phone $phone2 $lock where fg_username = '$username' ";
      }
      else {
         return 0;
      }
   }
   elsif ( $cmd eq "changepw" ) {
      if ( finduser( $dbh, $username ) == 1 ) {
         if ($password) {
             $password = passmd5($password);
             $password = "fg_password='$password'";
         }
         $SQL = "UPDATE fgaccount SET $password where fg_username = '$username' and fg_NID = '$nid_rg' and fg_email = '$email' and fg_lock = 0 ";
      }
      else {
         return 0;
      }
   }
   elsif ( $cmd eq "delete" ) {
      if ( finduser( $dbh, $username ) == 1 ) {
         $SQL = "delete from fgaccount where fg_username='$username'";
      }
      else {
         return 0;
      }
   }
   elsif ( $cmd eq "connect" ) {
      return $dbh;
   }
   elsif ( $cmd eq "chklogin" ) {
      $username =~ s/(\/|\')//g;
      $password = passmd5($password);

      ### Try to find username/password
      my ($auxpass, $lock, $ftlogin) = $dbh->selectrow_array("select fg_password, fg_lock, fg_ftlogin from fgaccount where fg_username='$username' and fg_password='$password'");

      if (($password eq $auxpass) && $lock == 0) {

         # update last login time
         my $ltlogin = strftime("%Y/%m/%d %k:%M:%S", localtime);
         $ftlogin = $ltlogin if (!$ftlogin || $ftlogin == undef);
         $SQL = "UPDATE fgaccount SET fg_ftlogin='$ftlogin', fg_ltlogin='$ltlogin' where fg_username = '$username' ";
         $sth = $dbh->prepare("$SQL");
         $sth->execute;
         $dbh->disconnect();

         # return true (correct login)
         return 1;
      }
      $dbh->disconnect();
      return 0;
   } 

   my $sql_ok = 1;
   $sth = $dbh->prepare("$SQL");
   $sth->execute or $sql_ok = -1;
   log_info("MySQL Error: $DBI::errstr, SQL=$SQL") if ($sql_ok == -1);

   $dbh->disconnect();
   $sql_ok = 0 if ($sth->rows <= 0 && $cmd eq "changepw" && $sql_ok > 0);
   return $sql_ok;
}

return 1;
