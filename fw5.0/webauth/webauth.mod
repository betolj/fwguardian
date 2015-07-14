#!/usr/bin/perl
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
#   Webserver based *initially* on HORATIO project
#    - http://www.cs.utexas.edu/users/mcguire/software/horatio/
#
#   Changes into webauth (some fwguardian features)
#    - Webserver health control
#    - Cache control
#    - Manager interface
#    - Alternative rollcall method
#    - iptables firewall support (nftables in future)
#    - fwroute.rules integrate
#    - redirect support in captive portal 
#


use lib "/usr/share/fwguardian/webauth";

sub BEGIN {
    $FW_DIR = $ARGV[0];
    $FW_DIR =~ s/\/webauth//;
    $WEB_DIR = $ARGV[0];
    $HTMLDIR = "$WEB_DIR/html";
    $STYLE = "style=\"background-image: url(data:image/gif;base64,R0lGODlhCAAIAJEAAMzMzP///////wAAACH5BAEHAAIALAAAAAAIAAgAAAINhG4nudroGJBRsYcxKAA7);\"";
    $FSTYLE = "";
    $FSTYLE = "background-image: url('/fback.png'); background-repeat: repeat;";
    $CURFILE="/usr/share/fwguardian/webauth/control/CUR_USERS";

    $FW_LANG = 1;
    $dropsess[0] = "Sessão bloqueada ou inválida";
    $dropsess[1] = "Invalid or forbidden session";
    $contactmsg[0] = "<BR /><font size='2'>Comunique o administrador da rede!</font>";
    $contactmsg[1] = "<BR /><font size='2'>Contact your network admin!</font>";

    $allowmail = 0;
    $ENV{PATH} = "/sbin:/bin:/usr/bin:/usr/sbin:/usr/local/etc:/usr/share/fwguardian/webauth";
    delete @ENV{'IFS', 'CDPATH', 'ENV', 'BASH_ENV'};
}

############################################
# Main webserver modules
use HTTP::Response;
use HTTP::Status;
use IO::File;
use Fcntl;
use URI::Escape qw(uri_unescape);
use Sys::Syslog;
use utf8;
use Encode;
#use Crypt::PasswdMD5 qw(unix_md5_crypt); #Deprecated
use POSIX ":sys_wait_h";

# Try to include "NetAddr" support (admin networks)
my $nonaddr = 0;
eval "use NetAddr::IP; 1" or $nonaddr = 1;

# Try to include "Net::SMTP" support
my $nomail = 0;
eval "use Net::SMTP; 1" or $nomail = 1;

# Try to include "RRDs" support
my $norrd = 1;
$norrd=0 if (-e "/usr/share/fwguardian/webauth/rrd/rrd_collect.pl");

# Try to include "DBI:MySql" support (SQL accounts)
my $nosql = 1;
my $testsql = 0;
eval "use DBI; 1" or $testsql++;
eval "use DBD::mysql; 1" or $testsql++;
$nosql = 0 if ($testsql == 0 && -e "/usr/share/fwguardian/modules/rtfilters.ctl" && -e "/usr/share/fwguardian/rtauth.ctl");


############################################
# Session control modules
use CGI::Carp qw/fatalsToBrowser warningsToBrowser/;
use CGI::Cookie;
use CGI::Session ( '-ip_match' );

############################################
# Admin modules
require "$WEB_DIR/includes/json.pl";
require "$WEB_DIR/includes/infra.pl";
require "$WEB_DIR/includes/modules.pl";
require "$WEB_DIR/includes/interfaces.pl";
require "$WEB_DIR/includes/srcctl.pl";
require "$WEB_DIR/includes/profile.pl";
require "$WEB_DIR/includes/cluster.pl";
require "$WEB_DIR/includes/banned.pl";
require "$WEB_DIR/includes/fwmasq.pl";
require "$WEB_DIR/includes/alias.pl";
require "$WEB_DIR/includes/fwmsn.pl";
require "$WEB_DIR/includes/fwinput.pl";
require "$WEB_DIR/includes/fwroute.pl";
require "$WEB_DIR/includes/fwprof.pl";
require "$WEB_DIR/includes/fwauth.pl";
require "$WEB_DIR/includes/fwnat.pl";
require "$WEB_DIR/includes/advroute.pl";
require "$WEB_DIR/includes/feset.pl";
require "$WEB_DIR/includes/fwstats.pl";
require "$WEB_DIR/includes/fwdiag.pl";
require "$WEB_DIR/includes/tfshow.pl";
require "$WEB_DIR/includes/account.pl";
require "$WEB_DIR/includes/authlog.pl";
require "$WEB_DIR/includes/dhcplease.pl";
require "$WEB_DIR/includes/qosset.pl";
require "$WEB_DIR/includes/qosfilter.pl";
require "$WEB_DIR/includes/qosegress.pl";
require "$WEB_DIR/includes/qosegressrules.pl";
require "$WEB_DIR/includes/vpnserver.pl";
require "$WEB_DIR/includes/vpnmapps.pl";
require "$WEB_DIR/includes/vpndirect.pl";
require "$WEB_DIR/includes/clustercfg.pl";

# Include RRD stats
if ($norrd == 0 && -d "/usr/share/fwguardian/webauth/rrd") { require "$WEB_DIR/includes/rrdstats.pl"; }

# Include sqladmin.pl code if exit "DBI" and "DBD::mysql" support 
if ($nosql == 0) { require "$WEB_DIR/includes/sqladm.pl"; }

# Include mail.pl code if exist "Net::SMTP" support
if ($nomail == 0) { require "$WEB_DIR/includes/mail.pl"; }


############################################
# Functions: syslogging
sub log_debug   { syslog("debug", "%s", shift); }
sub log_info    { syslog("info", "%s", shift); }
sub log_warning { syslog("warning", "%s", shift); }
sub log_error   { syslog("err", "%s", shift); }
sub log_exit    {
    my $msg = shift;
    syslog("err", "%s", $msg);
    die $msg;
}

# Read firewall IP address
sub read_fwips {
  @fwip = ();
  my $fileip="/usr/share/fwguardian/fw.ipaddr";
  if (-e $fileip) {
     open FILE, "<$fileip";
     while (<FILE>) {
        $_ =~ s/\n//;
        push(@fwip, $_);
     }
     close (FILE);
  }
  else {
     foreach (`ip addr ls | awk '/^[ |\\\t]*inet / {print \$2;}' | cut -d '/' -f1`) {
        $_ =~ s/\n//;
        push(@fwip, $_);
     }
  }
}

# Find firewall IP address
sub find_fwaddr {
  my $auxaddr = shift;
  foreach my $faddr (@fwip) {
    return 1 if ($auxaddr eq $faddr);
  }
  return 0;
}


# Verify the admin requests
sub verify_adminrequest {
  my $host = shift;
  my $allow = 0;
  my $chkip = NetAddr::IP->new($host) if ($nonaddr == 0);
  foreach my $netAddr (@admhost) {
     if ($host eq $netAddr || $netAddr eq "any") {
        $allow = 1;
        last;
     }
     else {
        if ($nonaddr == 0) {
           my $chknetwork  = NetAddr::IP->new($netAddr);
           if ($chkip->within($chknetwork)) {
              $allow = 1;
              last;
           }
        }
     }
   }
   return $allow;
}

# "Load interface settings" - interfaces
sub read_interfaces {
  @fwinterfaces = ();
  @fwinterfacescomments = ();
  if (-e $file_cfg{'interfaces'}) {
    open FILE, "<$file_cfg{'interfaces'}";
    while (<FILE>) {
      $_ =~ s/\n//;
      $_ =~ s/"/\\"/g;
      $_ =~ s/'/\\'/g;
      if ($_ !~ /^[\s]*(#|$|;)/) {
         push(@fwinterfaces, "$_");
      }
      else {
         push(@fwinterfacescomments, "$_");
      }
    }
    close (FILE);
  }
}

# "Load global alias" - webalias
sub read_webalias {
  @webalias = ();
  if (-e $file_cfg{'alias'}) {
    open FILE, "<$file_cfg{'alias'}";
    while (<FILE>) {
      $_ =~ s/\n//;
      $_ =~ s/"/\\"/g;
      $_ =~ s/'/\\'/g;
      push(@webalias, "$_") if ($_ =~ /^[\s]*alias[\s]/) ;
    }
    close (FILE);
  }
}

# Defining ifalias and netalias
sub splitalias {
   @ifalias = ();
   @netalias = ();

   foreach (@webalias) {
     $_ =~ s/\n//;
     $_ =~ s/(\s)+webalias$//;

     if ($_ =~ /^(\s)*alias(\s)/) {
        my (undef, $aalias, $avalue, undef) = (split /\s/, $_, 4);
        if ($avalue =~ /^(phy:)*([a-zA-Z0-9]+)([\.@][0-9]+)?[\+]*$/) {
           push(@ifalias,"$aalias");
        }
        elsif ($avalue =~ /^(iprange:)*(([0-9]+\.){3}[0-9]+)($|\-([0-9]+\.){3}[0-9]+|\/[0-9]+)$/) {
           $aalias = "iprange:$aalias" if ($avalue =~ /^iprange:/);
           push(@netalias,"$aalias");
        }
     }
   }
}

# "Read main config" - fwguardian.conf
sub read_fwcfg {
  my $filecfg="$FW_DIR/fwguardian.conf";
  my @auxline = ();

  %fwcfg = ();
  @fwchk = ();
  @fwifs = `ls /sys/class/net/ | tr ' ' '\n' | grep -v \"\^lo\$\"`;

  @fwcfgopt = ();
  %infrarules = ();

  if (-e "/usr/share/fwguardian/webauth/control/sourcefile" && -e "/usr/share/fwguardian/modules/clusterfw.ctl") {
     $srcfile = `cat /usr/share/fwguardian/webauth/control/sourcefile | tr -d '\n'`;
     $srcfile = "default" if ($srcfile eq "local");
  }
  else {
     $srcfile = "default";
  }

  %file_cfg=();
  my $files_cfg="alias interfaces accesslist/trust accesslist/bannedroutes accesslist/bannedaccess profile/profile.def fwmasq.net fwhosts fwmsn fwinput routing/fwroute.rules routing/fwroute.nat routing/fwroute.tables webauth/filedit.conf tfshape/shape.conf vpn/vpn.conf";
  foreach my $file_aux (split /\s+/, $files_cfg) {
     $file_cfg{$file_aux}="$FW_DIR/$file_aux";
  }

  read_webalias;
  splitalias;
  foreach my $auxifs (@ifalias) {
     push(@fwifs,"$auxifs") if (! -d "/sys/class/net/$auxifs");
  }

  if ( -e "/usr/share/fwguardian/modules/clusterfw.ctl") {
     rsynccfg();
     if ($srcfile eq "default" || $srcfile =~ /^[ |\t]*rsync_/) {
        if ($srcfile =~ /^[ |\t]*rsync_/) {
           foreach my $syfiles (@{$rsgp_syncfiles{$srcfile}}) {
              @sfileaux = split /\s+/, $syfiles;
              if ( $sfileaux[1] ) {
                 $sfileaux[1] = "$FW_DIR/cluster/rsync/$sfileaux[1]" if ($sfileaux[1] !~ /^\//);
                 $file_cfg{$sfileaux[0]} = "$sfileaux[1]";
              }
           }
        }
     }
     else {
        my $srcfile_aux = "gl_$srcfile";
        foreach my $file_aux (split /\s+/, $files_cfg) {
           $file_cfg{$file_aux}="$FW_DIR/cluster/glusterfs/cluster/$srcfile_aux/$file_aux";
        }
     }
  }

  ### Loading fwguardian.conf (Firewall config)
  if (-e $filecfg) {
    open FILE, "<$filecfg";
    while (<FILE>) {
      if ($_ !~ /^[ ]*(#|;)/) {
         $_ =~ s/\n//;
         @auxline = split /\s+/, $_;

         if ($auxline[0]) {
            if ($auxline[0] =~ /^(webserver|webhealth)$/) {
               push(@{$infrarules{'web'}}, "$_");
            }
            elsif ($auxline[0] =~ /^(syn_cookie|tcp_dos_protect|drop_portscan|rp_filter|icmp_bogus_error|ignore_brd_icmp|(secure|send)_redirects|deny_src_rt|deny_icmp_redir|defrag|unclean)$/) {
               push(@{$infrarules{'security'}}, "$_");
            }
            elsif ($auxline[0] =~ /^(forwarding|ip_dynamic|net_sharing|conntrack_bytes|enable_tcpreset|keepalive_sessions)$|_TOS$/) {
               push(@{$infrarules{'network'}}, "$_");
            }
            elsif ($auxline[0] =~ /^kill_/) {
               push(@{$infrarules{'kill'}}, "$_");
            }
            elsif ($auxline[0] =~ /^log_/) {
               push(@{$infrarules{'log'}}, "$_");
            }
            else {
               push(@fwcfgopt, "$auxline[0]");
               foreach my $opts (@auxline) {
                  if ($auxline[0] ne $opts && $auxline[0] ne "TRUST") {
                     push(@{$fwcfg{$auxline[0]}}, "$opts");
                  }
               }
            }
         }
      }
    }
    close(FILE);
  }

  # Load trust list
  if (-e "$FW_DIR/accesslist/trust") {
    foreach my $opts (`cat $FW_DIR/accesslist/trust`) {
       chomp($opts);
       push(@{$fwcfg{'TRUST'}}, "$opts");
    }
  }

  ### Read condition tests
  if (-e "$FW_DIR/conditions") {
    open FILE, "<$FW_DIR/conditions";
    while (<FILE>) {
      if ($_ =~ /^[ |\t]*set-condition[ |\t]/) {
        my (undef, $opts) = split /set-condition\s+/, $_;
        ($opts, undef) = split /\s+/, $opts;
        push(@fwchk, "$opts");
      }
    }
    close(FILE);
  }
}

# "Read all profiles" - FW_DIR/profile/profile.def
sub read_profiles {
    my $group = "";
    my $gpchk = "";
    %profline = ();
    @fwprof = ();
    @fwltprof = ();
    @profcomments = ();
    read_fwcfg;

    if (-e "$file_cfg{'profile/profile.def'}") {
       open FPFILE, "<$file_cfg{'profile/profile.def'}";
       while (my $lines = <FPFILE>) {
          $lines =~ s/\n//;
          if ($lines !~ /^[\s]*(#|;|$)/) {
             if ($lines =~ /[\s]*set-policy[\s]/) {
                $group = "";
                $gpchk = "";
                (undef, $group, $gpchk) = split /\s+/, $lines, 3;
                if ($gpchk && $gpchk =~ /^chk=/) {
                   $group = "$group $gpchk";
                   $group =~ s/[\s]+chk=/?chk=/;
                }
                if ($group =~ /^limit:/) {
                   push(@fwltprof, "$group") unless ($profline{$group});
                }
                else {
                   push(@fwprof, "$group") unless ($profline{$group});
                }
             }
             else {
                push(@{$profline{$group}}, "$lines");
             }
          }
          else {
             push(@profcomments, "$lines");
          }
       }
       close(FPFILE);
    }
}

# "Read fwmasq config" - FW_DIR/fwmasq.net
sub read_fwmasq {
    @fwmasqcomments = ();
    @fwmasqrules = ();
    read_fwcfg;

    if (-e $file_cfg{'fwmasq.net'}) {
       open FMFILE, "<$file_cfg{'fwmasq.net'}";
       while (my $lines = <FMFILE>) {
          $lines =~ s/\n//;
          if ($lines !~ /^[\s]*$/) {
             if ($lines !~ /^[\s]*(#|;|$)/) {
                push(@fwmasqrules, "$lines");
             }
             else {
                push(@fwmasqcomments, "$lines");
             }
          }
       }
       close(FMFILE);
    }
}

# "Read fwhosts config" - FW_DIR/fwhosts
sub read_fwhosts {
    @fwhostcomments = ();
    @fwhostset = ();
    @fwhostrules = ();
    read_fwcfg;

    if (-e $file_cfg{'fwhosts'}) {
       open FPFILE, "<$file_cfg{'fwhosts'}";
       while (my $lines = <FPFILE>) {
          $lines =~ s/\n//;
          if ($lines !~ /^[\s]*$/) {
             if ($lines !~ /^[\s]*(#|;|set[\s]|$)/) {
                push(@fwhostrules, "$lines");
             }
             else {
                if ($lines =~ /^[\s]*(#|;)/) {
                   push(@fwhostcomments, "$lines");
                }
                else {
                   $lines =~ s/\"//g;
                   $lines =~ s/\'//g;
                   push(@fwhostset, "$lines");
                }
             }
          }
       }
       close(FPFILE);
    }
}

# "Read fwroute.nat config" - FW_DIR/routing/fwroute.nat
sub read_fwnat {
    my $group = "";
    my $gpchk = "";
    %natrules = ();
    @natgroup = ();
    @natcomments = ();
    read_fwcfg;

    if (-e $file_cfg{'routing/fwroute.nat'}) {
       open FNFILE, "<$file_cfg{'routing/fwroute.nat'}";
       while (my $lines = <FNFILE>) {
          $lines =~ s/\n//;
          if ($lines !~ /^[\s]*(#|;|$)/) {
             if ($lines =~ /[\s]*set-policy[\s]/) {
                $group = "";
                $gpchk = "";
                (undef, $group, $gpchk) = split /\s+/, $lines, 3;
                if ($gpchk && $gpchk =~ /^chk=/) {
                   $group = "$group $gpchk";
                   $group =~ s/[\s]+chk=/?chk=/;
                }
                push(@natgroup, "$group") unless ($natrules{$group});
             }
             else {
                push(@{$natrules{$group}}, "$lines") if ($group =~ /^(DNAT|SNAT|NETMAP)($|\?chk=)/);
             }
          }
          else {
             push(@natcomments, "$lines");
          }
       }
       close(FNFILE);
    }
}

# "Read vpn.conf config" - FW_DIR/vpn/vpn.conf
sub read_fwvpn {
    my $group = "";
    my $gpchk = "";
    %vpnrules = ();
    @vpngroup = ();
    @vpncomments = ();
    read_fwcfg;

    # Server options
    my %vpncmd = ();
    my @vpncmd_aux = ("bind", "ppp-local", "ppp-pool", "ms-dns", "ms-wins", "proxy-arp", "default", "optional-mppe", "winbind-authgroup", "l2tp", "peerkey", "default-psk");

    if (-e $file_cfg{'vpn/vpn.conf'}) {
       open FVFILE, "<$file_cfg{'vpn/vpn.conf'}";
       while (my $lines = <FVFILE>) {
          $lines =~ s/\n//;
          if ($lines !~ /^[\s]*(#|;|$)/) {
             if ($lines =~ /[\s]*set-policy[\s]/) {
                $group = "";
                $gpchk = "";
                (undef, $group, $gpchk) = split /\s+/, $lines, 3;
                if ($gpchk && $gpchk =~ /^chk=/) {
                   $group = "$group $gpchk";
                   $group =~ s/[\s]+chk=/?chk=/;
                }
                push(@vpngroup, "$group") unless ($vpnrules{$group});
                push(@{$vpnrules{$group}}, 'status ERROR') if ($group =~ /^(PPTP|IPSEC)-SERVER/);
             }
             else {
                if ($group =~ /^((PPTP|IPSEC)-SERVER|IP-USERMAPS|DIRECT)($|\?chk=)/) {
                   # Defined server options
                   if ($group =~ /^(PPTP|IPSEC)-SERVER/) {
                      my ($cmdline, undef) = split /\s+/, $lines, 2;

                      if ($group =~ /^PPTP/) { push(@{$vpncmd{'PPTP-SERVER'}}, "$group $cmdline"); }
                      else { push(@{$vpncmd{'IPSEC-SERVER'}}, "$group $cmdline"); }
                   }
                   push(@{$vpnrules{$group}}, "$lines");
                }
             }
          }
          else {
             push(@vpncomments, "$lines");
          }
       }
       close(FVFILE);

       # Append server options if not defined
       my $findcmd=0;
       my @vpntype = ("PPTP-SERVER", "IPSEC-SERVER");
       foreach my $cmd_aux (@vpncmd_aux) {
          foreach my $group (@vpntype) {
             $findcmd=0;
             my $vpngroup = $group;
             for($i = 0; $i < scalar(@{$vpncmd{$group}}); $i++) {
                my $cmd_server = ${$vpncmd{$group}}[$i];

                ($vpngroup, $cmd_server) = split /\s+/, $cmd_server, 2;
                $findcmd=1 if ($cmd_aux eq $cmd_server);
             }
             $findcmd=1 if (($cmd_aux eq "peerkey" || $cmd_aux eq "default-psk" || $cmd_aux eq "l2tp") && $group eq "PPTP-SERVER");

             if ($findcmd == 0) {
                if ($cmd_aux =~ /^(proxy-arp|default|optional-mppe|l2tp|winbind-authgroup|peerkey|default-psk)$/) {
                   push(@{$vpnrules{$vpngroup}}, "$cmd_aux None") if ($cmd_aux eq "winbind-authgroup");
                   push(@{$vpnrules{$vpngroup}}, "$cmd_aux psk") if ($cmd_aux eq "peerkey");
                   push(@{$vpnrules{$vpngroup}}, "$cmd_aux auto") if ($cmd_aux eq "default-psk");
                   push(@{$vpnrules{$vpngroup}}, "$cmd_aux No") if ($cmd_aux =~ /^(proxy-arp|default|optional-mppe|l2tp)$/);
                }
                else {
                   push(@{$vpnrules{$vpngroup}}, "$cmd_aux 127.0.0.1");
                }
             }
          }
       }
    }
}

# "Read shape.conf config" - FW_DIR/tfshape/shape.conf
sub read_fwqos {
    my $setcur = "", $group = "", $parent = "", $parentaux = "";
    @qoscomments = ();
    @qosset = ();
    @qosrules = ();
    @qosegress = ();
    @qosegressrules = ();
    @qosparent = ();
    %qosinparent = ();
    read_fwcfg;

    if (-e $file_cfg{'tfshape/shape.conf'}) {
       open FQFILE, "<$file_cfg{'tfshape/shape.conf'}";
       while (my $lines = <FQFILE>) {
          $lines =~ s/\n//;
          if ($lines !~ /^[\s]*(#|;|$)/) {
             if ($lines =~ /[\s]*set-/) {
                $group = "";
                $setcur = "";
                (undef, $parent, undef) = split /\s+/, $lines, 3;
                if ($lines =~ /[\s]*set-qos[\s]/) {
                   $setcur = "qos";
                   push(@qosset, "$lines");
                   push(@qosparent, "$parent");
                }
                elsif ($lines =~ /[\s]*set-filter($|[\s])/) {
                   $setcur = "filter";
                }
                elsif ($lines =~ /[\s]*set-egress[\s]/) {
                   $setcur = "egress";
                   $group = $parent;
                   push(@qosegress, "$lines");

                   ($parentaux, $parent) = split /->/, $parent;
                   push(@qosparent, "$parent");
                   $qosinparent{$parentaux}=1;
                   $qosinparent{$parent}=0 if ($qosinparent{$parent} && $qosinparent{$parent} != 1);
                }
             }
             else {
                if ($setcur eq "filter") {
                   push(@qosrules, "$lines");
                }
                elsif ($setcur eq "egress") {
                   push(@{$qosegressrules{$group}}, "$lines")
                }
             }
          }
          else {
             push(@qoscomments, "$lines");
          }
       }
       close(FQFILE);
    }
}

# "Read routing tables" - FW_DIR/routing/fwroute.tables
sub read_advroute {
    my $polcur = "", $group = "";
    @advroutecomments = ();
    @advrouteset = ();
    @advroutelink = ();
    @advrouterules = ();
    @rtlink = ();
    read_fwcfg;

    if (-e $file_cfg{'routing/fwroute.tables'}) {
       open FRTFILE, "<$file_cfg{'routing/fwroute.tables'}";
       while (my $lines = <FRTFILE>) {
          $lines =~ s/\n//;
          if ($lines !~ /^[\s]*$/) {
             if ($lines !~ /^[\s]*(#|;|set[\s]|$)/) {
                if ($lines =~ /[\s]*set-/) {
                   if ($lines =~ /[\s]*set-link([\s]|$)/) {
                      $polcur = "link";
                   }
                   else {
                      $polcur = $lines;
                      $polcur =~ s/^[\s]*set-policy[\s]+//;
                   }
                }
                else {
                   if ($polcur eq "link") {
                      push(@advroutelink, "$lines");

                      my (undef, undef, undef, $linkid, undef) = split /[\s]+/, $lines, 5;
                      push(@rtlink, $linkid);
                   }
                   else {
                      if ($polcur =~ /^[\s]*(iproute|netfilter)([\s]|$)/) {
                         $group = $polcur;
                         $group =~ s/[\s]+chk=/\?chk=/ if ($group =~ /[\s]chk=/);
                         $lines = "$group $lines";
                         push(@advrouterules, "$lines");
                      }
                   }
                }
             }
             else {
                if ($lines =~ /^[\s]*(#|;)/) {
                   push(@advroutecomments, "$lines");
                }
                else {
                   $lines =~ s/\"//g;
                   $lines =~ s/\'//g;
                   push(@advrouteset, "$lines");
                }
             }
          }
       }
       close(FRTFILE);
    }
}

# "Read fwmsn config" - FW_DIR/fwmsn
sub read_fwmsn {
    @fwmsncomments = ();
    @fwmsnrules = ();
    @fwmsncheckaddr = ();
    @fwmsncheckproxy = ();
    read_fwcfg;

    if (-e $file_cfg{'fwmsn'}) {
       open FPFILE, "<$file_cfg{'fwmsn'}";
       while (my $lines = <FPFILE>) {
          $lines =~ s/\n//;
          if ($lines !~ /^[\s]*$/) {
             if ($lines !~ /^[\s]*(#|;|check\.(proxy|addr|address)[\s]|$)/) {
                $lines =~ s/^[\s]*allow.login[\s]+//;
                push(@fwmsnrules, "$lines");
             }
             else {
                if ($lines =~ /^[\s]*(#|;)/) {
                   push(@fwmsncomments, "$lines");
                }
                else {
                   $lines =~ s/\"//g;
                   $lines =~ s/\'//g;
                   if ($lines =~ /^[\s]*check\.(addr|address)/) {
                      $lines =~ s/[\s]*check\.address[\s]+//;
                      $lines =~ s/[\s]*check\.addr[\s]+//;
                      push(@fwmsncheckaddr, "$lines");
                   }
                   else {
                      $lines =~ s/[\s]*check\.proxy[\s]+//;
                      push(@fwmsncheckproxy, "$lines");
                   }
                }
             }
          }
       }
       close(FPFILE);
    }
}

# Read fwroute.rules or fwinput file
sub read_fwrules {
  read_fwcfg;

  my $target = shift;
  my $rofile = "$file_cfg{'routing/fwroute.rules'}";
  my $polcur;
  my $auxPol = "";
  my $poltype = "policy";
  my $findgp = 0;
  if ($target eq "route") {
     @routefw = ();
     @routefwtab = ();
     @routecomments = ();
     @gpset = ();
     @gpauthfw = ();
     @gpauthfwtab = ();
     %gpauthrule = ();
  }
  else {
     @inputfw = ();
     @inputfwtab = ();
     @inputcomments = ();
     $rofile = "$file_cfg{'fwinput'}";
  }

  ### Loading rule
  if (-e $rofile) {
    open FILE, "<$rofile";
    $polcur = "set-policy any";
    while (<FILE>) {
      $_ =~ s/"/\\"/g;
      $_ =~ s/'/\\'/g;
      $_ =~ s/^[ |\t]*;tab-pol[ |\t]+/set-policy /;
      $_ =~ s/^[ |\t]*auth.group[ |\t]+/set-policy auth:/;

      if (($_ !~ /^[\s]*(#|;|$)/) || ($_ =~ /^[\s]*(set-(policy|auth|alias))([\s]|$)/)) {
         if ($_ =~ /^[\s]*set-(policy|auth|alias)([\s]+|$)/) {
            $poltype = "";
            $polcur = $_;

            $auxPol = $polcur;
            $auxPol =~ s/\n//;
            $auxPol =~ s/[\s]+chk=/?chk=/ if ($auxPol =~ /[\s]chk=/);

            if ($_ =~ /^[\s]*set-policy([\s]+|$)/) {
               $poltype = "policy";
               $auxPol =~ s/^[\s]*set-policy[\s]+//;
               if ($target eq "input") { push(@inputfwtab, "$polcur"); }
               elsif ($target eq "route") {
                 if ($_ =~ /^[\s]*set-policy[\s]+auth:/) { push(@gpauthfwtab, "$polcur"); }
                 else { push(@routefwtab, "$polcur"); }
               }
            }
            elsif ($_ =~ /^[\s]*set-auth([\s]+|$)/) {
               $auxPol =~ s/^[\s]*set-auth[\s]+//;
               $poltype = "auth";
               push(@gpset, "$auxPol");
            }
         }
         elsif ($poltype ne "") {
            $_ =~ s/\n//g;
            if ($poltype eq "policy") {
               if ($target eq "input") {
                  push(@inputfw, "$auxPol $_");
               }
               elsif ($target eq "route") {
                  if ($polcur =~ /^[\s]*set-policy[\s]+auth:/) {
                     push(@gpauthfw, "$auxPol $_");
                  }
                  else { 
                     push(@routefw, "$auxPol $_");
                  }
               }
            }
            else {
               push(@{$gpauthrule{$auxPol}}, "$_");
            }
         }
      }
      else {
         push(@inputcomments, "$_") if ($target eq "input");
         push(@routecomments, "$_") if ($target eq "route");
      }
    }
    close (FILE);
  }
}

# "Read cluster config" - FW_DIR/cluster/cluster.conf
sub read_cluster {
    my $group = "";
    %clrules = ();
    @clgroup = ();
    @clcomments = ();
    read_fwcfg;

    if (-e "$FW_DIR/cluster/cluster.conf") {
       $clrules{'cluster_id'} = "clusterid";
       $clrules{'cluster_prio'} = "1";
       $clrules{'gluster_group'} = "none";
       $clrules{'gluster_server'} = "none";
       $clrules{'mac_type'} = "default";
       $clrules{'preempt'} = "no";
       $clrules{'sync_state'} = "no";
       $clrules{'active_active'} = "no";
       $clrules{'vip_nat'} = "no";
       $clrules{'self_member'} = "no";

       open FCFILE, "<$FW_DIR/cluster/cluster.conf";
       while (my $lines = <FCFILE>) {
          $lines =~ s/\n//;
          if ($lines !~ /^[\s]*(#|;|$)/) {
             if ($lines =~ /[\s]*set-(interface|vipconf|vipaddr)(\s|$)/) {
                $group = "";
                (undef, $group) = split /-/, $lines, 2;
                push(@clgroup, "$group") unless ($clrules{$group});
             }
             else {
                if ($group =~ /^(interface|vipconf|vipaddr)$/) {
                   push(@{$clrules{$group}}, "$lines");
                }
                else {
                   ($clopt, $clvalue) = split /\s+/, $lines, 2;
                   $clrules{$clopt} = $clvalue if ($clopt =~ /^((cluster|router)_id|member_pass|gluster_server|gluster_group|self_member|mac_type|preempt|sync_state|active_active|vip_nat)$/);

                   ($clrules{'cluster_id'}, $clrules{'cluster_prio'}) = split /\s+/, $clrules{'cluster_id'}, 2 if ($clopt eq "cluster_id" || $clopt eq "router_id"); 
                }
             }
          }
          else {
             push(@clcomments, "$lines");
          }
       }
       close(FCFILE);
    }
}

# "The mapped users table (webauth control)"
sub read_mapuser {
  my @auxline = ();
  my $file="/usr/share/fwguardian/rtfilters.authmap.ctl";

  if (-e $file) {
    open FILE, "<$file";
    while (<FILE>) {
      @auxline = split(' ',$_);
      $mapip{"$auxline[0]"}=$auxline[1];
    }
    close(FILE);
  }
}

# "Users that can be mapped to IP addr"
sub read_mapaddr {
  my @auxline = ();
  my $file="/usr/share/fwguardian/rtfilters.mapaddr.ctl";

  if (-e $file) {
    open FILE, "<$file";
    while (<FILE>) {
      @auxline = split(' ',$_);
      push(@{$permpeer{$auxline[1]}}, "$auxline[0]");
    }
    close(FILE);
  }
}

# "Message box for access denied/allowed or info box"
sub msgbox {
  my $msgtype = shift;
  my $txtvalue = shift;
  my $auxvalue = shift;
  my %msgtop;
  if ($FW_LANG == 1) {
     $msgtop{'info'} = "INFO!";
     $msgtop{'largeinfo'} = "INFO!";
     $msgtop{'denied'} = "Access DENIED!";
     $msgtop{'allowed'} = "Access ALLOWED!";
     $msgtop{'authorized'} = "Access AUTHORIZED!";
  }
  else {
     $msgtop{'info'} = "INFORMA&Ccedil;&Atilde;O!";
     $msgtop{'largeinfo'} = "INFORMA&Ccedil;&Atilde;O!";
     $msgtop{'denied'} = "Acesso NEGADO!";
     $msgtop{'allowed'} = "Acesso LIBERADO!";
     $msgtop{'authorized'} = "Acesso AUTORIZADO!";
     $txtvalue =~ s/á/&aacute\;/g;
     $txtvalue =~ s/ã/&atilde\;/g;
     $auxvalue =~ s/ã/&atilde\;/g;
     $txtvalue =~ s/í/&iacute\;/g;
     $txtvalue =~ s/ó/&oacute\;/g;
     $txtvalue =~ s/ç/&ccedil\;/g;
  }
  $colortop{'denied'} = "Red";
  $colortop{'info'} = "#56556a";
  $colortop{'largeinfo'} = "#56556a";
  $colortop{'allowed'} = "#52C5A1";
  $colortop{'authorized'} = "#52C5A1";
  $msgwidth = 450;
  $msgwidth = 650 if ($msgtype eq "largeinfo");

$txtvalue = << "TxtVal";
    <table align="center" width="$msgwidth" height="100%" border="0" cellpadding="0" cellspacing="0">
       <tr><td>
         <table width="100%" border="0" cellspacing="1" cellpadding="5" bgcolor="#CCCCCC">
            <tr><td bgcolor="$colortop{$msgtype}"><font color="#FFFFFF" size="4" face="Arial, Helvetica, sans-serif">
            <strong>$msgtop{$msgtype}</strong></font></td></tr>
            <tr>
               <td bgcolor="#eeeeee">
                 <table align="center" width="100%" border="0" cellspacing="0" cellpadding="2">
                   <tr><td align="center" valign="center"><BR />
                   <strong><font size="3" face="Arial, Helvetica, sans-serif">$txtvalue
                   </strong></font><BR />
                   $auxvalue<BR /><BR /></td>
                   </tr>
                 </table>
               </td>
            </tr>
         </table>
       </td></tr>
    </table>
TxtVal
  return $txtvalue;
}

sub mailNotFound {
   my @msg = ("" , "");
   $msg[0] = "Nenhum servidor de email configurado!";
   $msg[1] = "No mail server configured!";
   return get_forbidden("$msg[$FW_LANG]", "", "");
}

# "Message for disabled firewall modules"
sub dismodule {
  my $url = shift;
  my $peer = shift;
  my $res = HTTP::Response->new();
  my $txtvalue;
  my @msg = ("", "");

  $msg[0] = "Modulo desabilitado";
  $msg[1] = "Disabled module";

  log_error("$msg[$FW_LANG]: url $url, peer $peer");
  $txtvalue = msgbox("info", "<font color=\'Red\'>$msg[$FW_LANG]</font>: url $url", "$contactmsg[$FW_LANG]");
  $txtvalue = "<html><head></head><body bgcolor=\"#F2F2F2\" $STYLE>$txtvalue</body></html>";
  $res->content($txtvalue);
  return $res;
}

############################################
# "Check permitions for webadmin"
sub chkperm {
  my $url = shift;
  my $peer = shift;
  my $method = shift;
  my $req = shift;
  my $res = undef;
  my $allow = 0;
  my $bwport = 0;
  my $txtvalue;
  my $curuser = "";
  my @msg = ("", "");
  my @msg2 = ("", "");

  CGI::Session->name("FWGSESS");
  my $session = CGI::Session->load(undef, $read_cookie, {Directory=>'/tmp/sessions'});
  my $invalid = 0;

  ### Check admin hosts
  $allow = verify_adminrequest($peer);

  ### Check admin cookie session
  my $diftime = $session->atime - $session->ctime;
  if ($session->is_expired || $session->is_empty || $diftime >= $session->param("_SESSION_ETIME")) {
     $invalid = 1;
     $session->delete;
  }
  else {
     # Check for restricted modules
     if ($allow == 1) {
       $curuser = $session->param('user');
       if ($curuser) {
         foreach (@{$ckmoduser{$url}}) {
           $allow = -1;
           if ($curuser eq $_) {
             $allow = 1;
             last;
           }
         }
       }
     }
  }

  # Invalid session
  if($invalid == 1 || $allow lt 1) {
     log_error("$dropsess[$FW_LANG]: $url peer $peer");
     if ($allow == 0) {
        $msg[0] = "Endereço administrativo não autorizado";
        $msg[1] = "Manager address not allowed";
        $msg2[0] = "ENDERE&Ccedil;O N&Atilde;O AUTORIZADO!";
        $msg2[1] = "HOST NOT ALLOWED!";

        log_error("$msg[$FW_LANG]: $peer");
        $txtvalue = "$msg2[$FW_LANG]";
     }
     elsif ($invalid == 0) {
        if ($allow == -1) {
           $msg[0] = "USU&Aacute;RIO N&Atilde;O AUTORIZADO!";
           $msg[1] = "USER NOT ALLOWED!";
           $msg2[0] = "Modulo *$url* não liberado ao usuário: $curuser!";
           $msg2[1] = "Module *$url* not allowed for user: $curuser!";

           log_error("$msg2[$FW_LANG]");
           $txtvalue = "$msg[$FW_LANG]";
        }
     }

     $res = HTTP::Response->new();
     $txtvalue = "<BR /><font color='red'><i>$txtvalue</i></font>" if ($txtvalue ne "");
     $txtvalue = msgbox("denied", " $dropsess[$FW_LANG] $txtvalue", "$contactmsg[$FW_LANG]");

     my $meta = "";
     $meta = "HTTP-EQUIV=\"Refresh\" CONTENT=\"3;URL=/admin/index2.html?u=$url\"" if ($allow != 0);
     $meta = "<head><META CACHE-CONTROL=\"no-cache, no-store, must-revalidate\" $meta></head>";
     $meta = "$meta<META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">";
     $txtvalue = "<html>$meta<body bgcolor=\"#F2F2F2\" $STYLE>$txtvalue</body></html>";

     $nodebug = 1;

     $res->content($txtvalue);
     return $res;
  }
  else {
     $bwport = $session->param("bwcount");
  }
  $session->flush;

  if ($allow) {
    if ($method eq "get") {
      if ($url eq "/admin/banned.cgi") {
         if (-e "/usr/share/fwguardian/modules/bannedfw.ctl") { 
           $res = get_banned($url);
         } 
         else { 
           $res = dismodule($url, $peer);
         }
      } elsif ($url eq "/admin/infra.cgi") {
          $res = get_global($url);
      } elsif ($url =~ /^\/admin\/getinfra\.json?/) {
          $res = get_infra($url);
      } elsif ($url eq "/admin/modules.cgi") {
          $res = get_modules($url);
      } elsif ($url eq "/admin/alias.cgi") {
          $res = get_alias($url);
      } elsif ($url =~ /^\/admin\/getalias\.json?/) {
          $res = get_aliasJs($url);
      } elsif ($url eq "/admin/profiles.cgi") {
          if (-e "/usr/share/fwguardian/profiles.ctl") {
            $res = get_profile($url);
          }
          else { 
            $res = dismodule($url, $peer);
          }
      } elsif ($url =~ /^\/admin\/getprofile\.json?/) {
          $res = get_ProfileRules($url);
      } elsif ($url eq "/admin/interfaces.cgi") {
          $res = get_interfaces($url);
      } elsif ($url =~ /^\/admin\/getinterface\.json?/) {
          $res = get_interfacesJs($url);
      } elsif ($url eq "/admin/fwmasq.cgi") {
          if (-e "/usr/share/fwguardian/fwmasq.ctl") {
            $res = get_fwmasq($url);
          }
          else { 
            $res = dismodule($url, $peer);
          }
      } elsif ($url eq "/admin/fwprof.cgi") {
          if (-e "/usr/share/fwguardian/profiles.ctl" && -e "/usr/share/fwguardian/modules/fwhosts.ctl") {
            $res = get_fwprofile($url);
          }
          else { 
            $res = dismodule($url, $peer);
          }
      } elsif ($url =~ /^\/admin\/getfwhosts\.json?/) {
          $res = get_fwhostsJs($url);
      } elsif ($url eq "/admin/srcctl.cgi") {
          if (-e "/usr/share/fwguardian/modules/clusterfw.ctl") {
            $res = get_srcctl($url);
          }
          else { 
            $res = dismodule($url, $peer);
          }
      } elsif ($url =~ /\/admin\/cluster(cfg|vip|vipad)\.cgi$/) {
          if (-e "/usr/share/fwguardian/modules/clusterfw.ctl") {
             if ($url eq "/admin/clustercfg.cgi") {
                $res = get_clustercfg($url, "interface");
             }
             elsif ($url eq "/admin/clustervip.cgi") {
                $res = get_clustercfg($url, "clustervip");
             }
             else {
                $res = get_clustercfg($url, "clustervipad");
             }
          }
          else { 
            $res = dismodule($url, $peer);
          }
      } elsif ($url =~ /^\/admin\/getclusterinter\.json?/) {
          $res = get_clusterJs($url, "interface");
      } elsif ($url =~ /^\/admin\/getclustervip\.json?/) {
          $res = get_clusterJs($url, "vipconf");
      } elsif ($url =~ /^\/admin\/getclustervipad\.json?/) {
          $res = get_clusterJs($url, "vipaddr");
      } elsif ($url =~ /^\/admin\/getfwmsn\.json/) {
          $res = get_fwmsnJs($url);
      } elsif ($url eq "/admin/fwmsn.cgi") {
          if (-e "/usr/share/fwguardian/modules/msnctl.ctl") {
            $res = get_fwmsn($url);
          }
          else {
            $res = dismodule($url, $peer);
          }
      } elsif ($url eq "/admin/fwinput.cgi") {
          if (-e "/usr/share/fwguardian/modules/infilters.ctl") {
            $res = get_fwinput($url);
          }
          else { 
            $res = dismodule($url, $peer);
          }
      } elsif ($url =~ /^\/admin\/getinput.json?/) {
          $res = get_fwruleJs($url, "fwinput");
      } elsif ($url eq "/admin/fwroute.cgi") {
          if (-e "/usr/share/fwguardian/modules/rtfilters.ctl") {
             $res = get_fwroute($url);
          }
          else { 
             $res = dismodule($url, $peer);
          }
      } elsif ($url =~ /^\/admin\/getroute\.json?/) {
          $res = get_fwruleJs($url, "fwroute");
      } elsif ($url =~ /^\/admin\/(auth|getauth)(mapps|nets|log|userlog)\.(cgi|json)/) {
         if ((-e "/usr/share/fwguardian/modules/rtfilters.ctl" && -e "/usr/share/fwguardian/rtauth.ctl") || $url =~ /^\/admin\/auth(log|userlog)\.(cgi$|json?)/) {
            if ($url eq "/admin/authmapps.cgi") {
               $res = get_authmapps($url);
            } elsif ($url eq "/admin/authnets.cgi") {
               $res = get_authnets($url);
            } elsif ($url =~ /\/admin\/getauthmapps\.json?/) {
               $res = get_authmappsrules($url, "authmaps");
            } elsif ($url =~ /\/admin\/getauthnets\.json?/) {
               $res = get_authmappsrules($url, "networks");
            } else {
               if ($url =~ /\/admin\/authlog\.json(\?_search=false&nd=.*&sord=(asc|desc))/) {
                  $res = get_authdata($url);
               } elsif ($url =~ /\/admin\/authuserlog\.json(\?_search=false&nd=.*&sord=(asc|desc))/) {
                  $res = get_authuserdata();
               } elsif ($url eq "/admin/authlog.cgi") {
                  $res = get_authlog();
               }
            }
         }
         else {
            $res = dismodule($url, $peer);
         }
      } elsif ($url eq "/admin/sqlauth.cgi" || $url =~ /^\/admin\/sqlUser\.js(\?_search=false&nd=.*&sord=(asc|desc))/) {
          if ($nosql == 0 && $sqlweb{'web_user'}) {
             if ($url eq "/admin/sqlauth.cgi") {
                $res = get_sqlauth($url);
             }
             else {
                $res = get_sqlUserpl($url);
             }
          }
          else { 
             $res = dismodule($url, $peer);
          }
      } elsif ($url eq "/admin/lease.cgi") {
          $res = get_lease();
      } elsif ($url =~ /\/admin\/lease\.js(\?_search=false&nd=.*&sord=(asc|desc))/) {
          $res = get_leasedata($url);
      } elsif ($url eq "/admin/fwnat.cgi") {
          if (-e "/usr/share/fwguardian/modules/rtnat.ctl") {
            $res = get_fwnat($url);
          }
          else { 
            $res = dismodule($url, $peer);
          }
      } elsif ($url =~ /\/admin\/tf(shape|filter|egress(class|rules))\.cgi$/) {
         if (-e "/usr/share/fwguardian/modules/tfstart.ctl") {
            if ($url eq "/admin/tfshape.cgi") {
               $res = get_qosset($url);
            } elsif ($url eq "/admin/tffilter.cgi") {
               $res = get_qosfilter($url);
            } elsif ($url eq "/admin/tfegressclass.cgi") {
               $res = get_qosegress($url);
            } elsif ($url eq "/admin/tfegressrules.cgi") {
               $res = get_qosegressrl($url);
            }
         }
         else {
            $res = dismodule($url, $peer);
         }
      } elsif ($url =~ /\/admin\/vpn(mapps|direct|servers)\.cgi$/) {
         if (-e "/usr/share/fwguardian/modules/vpnfw.ctl") {
            if ($url eq "/admin/vpnmapps.cgi") {
               $res = get_vpnmapps($url);
            } elsif ($url eq "/admin/vpndirect.cgi") {
               $res = get_vpndirect($url);
            } elsif ($url eq "/admin/vpnservers.cgi") {
               $res = get_vpnserver($url);
            }
         }
         else {
            $res = dismodule($url, $peer);
         }
      } elsif ($url eq "/admin/advlkroute.cgi" || $url eq "/admin/advrlroute.cgi") {
          if (-e "/usr/share/fwguardian/modules/rttables.ctl") {
            if ($url eq "/admin/advlkroute.cgi") {
               $res = get_advlkroute($url);
            }
            else {
               $res = get_advrlroute($url);
            }
          }
          else {
            $res = dismodule($url, $peer);
          }
      } elsif ($url =~ /^\/admin\/getadv(lk|rl)route\.json/) {
          if ($url =~ /^\/admin\/getadvlkroute\.json?/) {
             $res = get_advLkrouteJs($url);
          }
          else {
             $res = get_advRlrouteJs($url);
          }
      } elsif ($url =~ /^\/admin\/getnatrl\.json/) {
          $res = get_natrules($url);
      } elsif ($url =~ /^\/admin\/getvpn(mapps|direct|server)\.json(\?_search=false&nd=.*&sord=(asc|desc))/) {
          if ($url =~ /^\/admin\/getvpndirect\.json/) {
             $res = get_vpnrules($url, "DIRECT");
          }
          else {
             if ($url =~ /^\/admin\/getvpnmapps\.json/) {
                $res = get_vpnrules($url, "IP-USERMAPS");
             }
             else {
                $res = get_vpnrules($url, "server");
             }
          }
      } elsif ($url =~ /^\/admin\/getsetqos\.json?/) {
          $res = get_QosCfg($url);
      } elsif ($url =~ /^\/admin\/getegressqos\.json?/) {
          $res = get_QosEgress($url);
      } elsif ($url =~ /^\/admin\/getegressrlqos\.json?/) {
          $res = get_QosEgressRl($url);
      } elsif ($url =~ /^\/admin\/getfilterqos\.json?/) {
          $res = get_QosFilterRl($url);
      } elsif ($url eq "/admin/fwstats.cgi") {
          $res = get_fwstats($url);
      } elsif ($url eq "/admin/fwdiags.cgi") {
          $res = get_fwdiags($url);
      } elsif ($url =~ /^\/admin\/rrdstats\.cgi/) {
          if ($norrd == 0) {
             if ($url =~ /^\/admin\/rrdstats\.cgi\?(stats$|allif=)/) {
                $res = get_rrdstats($url, "allnettraf");
             }
             else {
                $res = get_rrdstats($url, "nettraf");
             }
          }
          else {
             $res = dismodule($url, $peer);
          }
      } elsif ($url =~ /\/admin\/tfshow\.(cgi|cgi?(default|shell)$)/) {
          if (`$FW_DIR/modules/tools/tfshow/tfshow -j -t` eq "Ok") {
             if ($url eq "/admin/tfshow.cgi" || $url eq "/admin/tfshow.cgi?default") {
                $res = get_tfshow("default");
             }
             else {
                if (-e "/usr/share/fwguardian/modules/bwshell.ctl") {
                   if ($bwport > 6180) {
                      system("iptables -D INPUT -s $peer -p tcp --dport $bwport -m comment --comment 'bwshell_ctl' -j ACCEPT 2>/dev/null");
                      system("iptables -I INPUT -s $peer -p tcp --dport $bwport -m comment --comment 'bwshell_ctl' -j ACCEPT");
                   }
                   $res = get_tfshow("shell");
                }
                else {
                   $res = dismodule($url, $peer);
                }
             }
          }
          else {
            $msg[0] = "Requer a versão 1.2 ou superior de tfshow!";
            $msg[1] = "Needed tfshow version 1.2 or newer!";
            $res = dismodule("$url<BR /><BR /><strong>$msg[$FW_LANG]</strong><BR />$FW_DIR/modules/tools/tfshow/build", $peer);
          }
      } elsif ($url =~ /^\/admin\/tfdata\.(js$|js\?)/) {
          $res = get_tfdata($url);
      } elsif ($url =~ /^\/admin\/getfwmasq\.json(\?_search=false&nd=.*&sord=(asc|desc))/) {
          $res = get_FwMasqJS($url);
      } elsif ($url =~ /^\/admin\/fe(set|man)\.cgi/) {
          if ($url eq "/admin/feset.cgi") {
              $res = get_feset($url);
          } elsif ($url eq "/admin/feman.cgi") {
              $res = get_feman($url);
          } elsif ($url eq "/admin/feman.cgi?cancel") {
              system("rm -f /tmp/sessions/cgisess_$read_cookie.app.fe 2>/dev/null");
              $res = get_feman($url);
          }
      } elsif ($url =~ /^\/admin\/getfeset\.json(\?_search=false&nd=.*&sord=(asc|desc))/) {
          $res = get_FeSetJS($url);
      }
    }
    else {
      if ($url->path eq "/admin/chbanned.cgi") {
          $res = chbanned($req->content);
      } elsif ($url->path eq "/admin/chprofile.cgi") {
          $res = chprofile($req->content);
      } elsif ($url->path eq "/admin/chfwprof.cgi") {
          $res = chfwprof($req->content);
      } elsif ($url->path eq "/admin/chinfraloc.cgi") {
          $res = chinfra($req->content, "local");
      } elsif ($url->path eq "/admin/chinfrasup.cgi") {
          $res = chinfra($req->content, "support");
      } elsif ($url->path eq "/admin/chinfraopc.cgi") {
          $res = chinfra($req->content, "options");
      } elsif ($url->path eq "/admin/chmodules.cgi") {
          $res = chmodules($req->content);
      } elsif ($url->path eq "/admin/chalias.cgi") {
          $res = chalias($req->content);
      } elsif ($url->path eq "/admin/chinterface.cgi") {
          $res = chinterfaces($req->content);
      } elsif ($url->path eq "/admin/chmasq.cgi") {
          $res = chmasq($req->content);
      } elsif ($url->path eq "/admin/chsrcctl.cgi") {
          $res = chsrcctl($req->content);
      } elsif ($url->path eq "/admin/chmsncheck.cgi") {
          $res = chmsncheck($req->content);
      } elsif ($url->path eq "/admin/chfwmsn.cgi") {
          $res = chfwmsn($req->content);
      } elsif ($url->path eq "/admin/chinput.cgi") {
          $res = chinput($req->content);
      } elsif ($url->path eq "/admin/chroute.cgi") {
          $res = chroute($req->content);
      } elsif ($url->path eq "/admin/chauthmapps.cgi") {
          $res = chauthmapps($req->content, "authmaps");
      } elsif ($url->path eq "/admin/chauthnets.cgi") {
          $res = chauthmapps($req->content, "networks");
      } elsif ($url->path eq "/admin/authleave.cgi") {
          $res = authleave($req->content);
      } elsif ($url->path =~ /^\/admin\/chtfilter_(default|shell).cgi$/) {
          if ($url->path eq "/admin/chtfilter_default.cgi") {
             $res = chtfilter($req->content, "default");
          }
          else {
             $res = chtfilter($req->content, "shell");
          }
      } elsif ($url->path eq "/admin/chnatrl.cgi") {
          $res = chnatrl($req->content);
      } elsif ($url->path eq "/admin/chvpnserver.cgi") {
          $res = chvpnserver($req->content);
      } elsif ($url->path eq "/admin/chvpnmapps.cgi") {
          $res = chvpnmapps($req->content);
      } elsif ($url->path eq "/admin/chvpndirect.cgi") {
          $res = chvpndirect($req->content);
      } elsif ($url->path eq "/admin/chtfshape.cgi") {
          $res = chqosset($req->content);
      } elsif ($url->path eq "/admin/chtffilter.cgi") {
          $res = chtffilter($req->content);
      } elsif ($url->path eq "/admin/chegress.cgi") {
          $res = chqosegress($req->content);
      } elsif ($url->path eq "/admin/chegressrl.cgi") {
          $res = chqosegressrl($req->content);
      } elsif ($url->path eq "/admin/chadvlkroute.cgi") {
          $res = chadvlkroute($req->content);
      } elsif ($url->path eq "/admin/chadvrlroute.cgi") {
          $res = chadvrlroute($req->content);
      } elsif ($url->path eq "/admin/chclusterbase.cgi") {
          $res = chcluster($req->content, "base");
      } elsif ($url->path eq "/admin/chclusterinter.cgi") {
          $res = chcluster($req->content, "interface");
      } elsif ($url->path eq "/admin/chclustervip.cgi") {
          $res = chcluster($req->content, "vipconf");
      } elsif ($url->path eq "/admin/chclustervipad.cgi") {
          $res = chcluster($req->content, "vipaddr");
      } elsif ($url->path eq "/admin/chaccount.cgi") {
          $res = chaccount($req->content, "detect", "admin");
      } elsif ($url->path eq "/admin/sendmail.cgi" && $allowmail == 1) {
          $res = sendmail($req->content, "admin", $peer);
      } elsif ($url->path eq "/admin/chsqlacct.cgi" && $nosql == 0) {
          $res = chsqlacct($req->content);
      } elsif ($url->path eq "/admin/chfeset.cgi") {
          $res = chfeset($req->content);
      } elsif ($url->path eq "/admin/chfeman.cgi") {
          $res = chfeman($req->content);
      } elsif ($url->path eq "/admin/chfecfg.cgi") {
          $res = chfecfg($req->content);
      } elsif ($url->path eq "/admin/chtarget.cgi") {
          $res = chtarget($req->content);
      }
    }
  }
  return $res;
}

############################################
# Function: recording process id
sub record_pid {
    my $pidlogfile = shift;
    my $fh = new IO::File $pidlogfile, "w";
    if (defined $fh) {
	print $fh "$$\n";
	$fh->close;
    } else {
	log_error("Cannot record process id");
    }
}

############################################
# Functions: add and remove forwarding rules
sub enterhostlist {
    my $hostl = shift;
    my $userl = shift;
    my $cookie = shift;
    return 1 if (system("/usr/share/fwguardian/webauth/webctl.sh", "enter", $hostl, $userl, $cookie) > -1);
    return 0;
}
sub leavehostlist {
    my $hostl = shift;
    return 1 if (system("/usr/share/fwguardian/webauth/webctl.sh", "leave", $hostl, "null") > -1);
    return 0;
}
sub queryhostlist {
    my $hostl = shift;
    return `/usr/share/fwguardian/webauth/webctl.sh query $hostl | tr -d '\n'`;
}
sub restorehostlist {
    return 1 if (system("/usr/share/fwguardian/webauth/webctl.sh", "restore") > -1);
    return 0;
}

### Deprecated function
#sub rollcall {
#    return 1 if (system("/usr/share/fwguardian/webauth/webctl.sh", "rollcall") > -1);
#    return 0;
#}

############################################
# Functions: Decode URL encoded username or password
sub decode_auth_info {
    # pick username and password out of URL encoded string
    my $s = shift;
    my @a;
    foreach $kv (split /&/, $s) {
	my ($k, $v) = split /=/, $kv;
	$k = uri_unescape($k);
	$v = uri_unescape($v);
        if ($k eq "username") {
	  $a[0] = $v;
          $usern=$v;
        }
	$a[1] = $v if ($k eq "password");
    }
    return @a;
}

############################################
# Functions: Initialize and lookup %passwd
sub read_passwd_file {
    # Format: <username>:<password>
    my $filename = shift;
    my %passwd;
    my @msg = ("", "");
    my $fh = new IO::File $filename, "r";
    if (defined $fh) {
	while (<$fh>) {
	    chomp;
	    my ($u, $p) = split /:/;
	    if (not $u or not $p) {
                $msg[0] = "Linha passwd inv&aacute;lida";
                $msg[1] = "Bad passwd entry";
                log_error("$msg[$FW_LANG]: $_");
		next;
	    }
	    $passwd{$u} = $p;
	}
	$fh->close;
    } else {
        $msg[0] = "Não pude ler o arquivo passwd";
        $msg[1] = "Cannot read passwd file";
        log_error("$msg[$FW_LANG]");
    }
    return %passwd;
}

############################################
# Functions: Initialize %errors
sub read_error_files {
    my $errordir = shift;
    undef %errors;
    my $error;
    my @msg = ("", "");
    foreach $error (@errors) {
	my $fh = new IO::File $errordir . "/" . $error . ".html", "r";
	if (defined $fh) {
	    $errors{$error} = join("", <$fh>);
	} else {
            $msg[0] = "Não pude ler o arquivo html";
            $msg[1] = "Cannot read file html";
            log_exit("$msg[$FW_LANG]/" . $error . ".html");
	}
	$fh->close;
    }
}

# List of HTTP error codes returned to client; see specific errors below
@errors = ();

############################################
# Functions: Read configuration file
sub read_config_file {
    my $fh = new IO::File $CONFIGFILE, "r";

    my @filesimg = ();  ## Image files
    push(@filesimg, glob "$HTMLDIR/*.png");
    push(@filesimg, glob "$HTMLDIR/*.gif");
    push(@filesimg, glob "$HTMLDIR/*.jpg");
    push(@filesimg, glob "$HTMLDIR/css/images/*.png");
    push(@filesimg, glob "$HTMLDIR/js/tabpane/img/*.gif");
    push(@filesimg, glob "$HTMLDIR/admin/buttons/*.png");
    push(@filesimg, glob "$HTMLDIR/admin/dynhttp/img/*.png");

    my @fileshtml = (); ## HTML files
    push(@fileshtml, glob "$HTMLDIR/*.html");
    push(@fileshtml, glob "$HTMLDIR/js/*.js");
    push(@fileshtml, glob "$HTMLDIR/js/*.css");
    push(@fileshtml, glob "$HTMLDIR/css/*.css");        #jqgrid
    push(@fileshtml, glob "$HTMLDIR/js/i18n/*.js");     #jqgrid
    push(@fileshtml, glob "$HTMLDIR/js/i18n/*.js.template");     #jqgrid
    push(@fileshtml, glob "$HTMLDIR/js/plugins/*.js");  #jqgrid
    push(@fileshtml, glob "$HTMLDIR/js/plugins/*.css"); #jqgrid
    push(@fileshtml, glob "$HTMLDIR/admin/*.html");
    push(@fileshtml, glob "$HTMLDIR/admin/js/*.js");
    push(@fileshtml, glob "$HTMLDIR/js/tabpane/*.js");
    push(@fileshtml, glob "$HTMLDIR/js/tabpane/*.css");
    $HTTPFILES{"/"} = [ "text/html", "$HTMLDIR/index.html" ];
    $HTTPSFILES{"/"} = [ "text/html", "$HTMLDIR/index.html" ];
    $HTTPFILES{"/admin"} = [ "text/html", "$HTMLDIR/admin/index.html" ];
    $HTTPSFILES{"/admin"} = [ "text/html", "$HTMLDIR/admin/index.html" ];

    foreach (@filesimg) {
       my $path = $_;
       $path =~ s/^$HTMLDIR//;
       if ($_ =~ /.png/) {
         $HTTPFILES{$path} = [ "image/png", $_ ];
         $HTTPSFILES{$path} = [ "image/png", $_ ];
       } elsif ($_ =~ /.gif/) {
         $HTTPFILES{$path} = [ "image/gif", $_ ];
         $HTTPSFILES{$path} = [ "image/gif", $_ ];
       } elsif ($_ =~ /.jpg/) {
         $HTTPFILES{$path} = [ "image/jpg", $_ ];
         $HTTPSFILES{$path} = [ "image/jpg", $_ ];
       }
    }
    foreach (@fileshtml) {
       my $path = $_;
       $path =~ s/^$HTMLDIR//;
       if ($_ =~ /.js$/) {
         $HTTPFILES{$path} = [ "text/javascript", $_ ];
         $HTTPSFILES{$path} = [ "text/javascript", $_ ];
       }
       elsif ($_ =~ /.css$/) {
         $HTTPFILES{$path} = [ "text/css", $_ ];
         $HTTPSFILES{$path} = [ "text/css", $_ ];
       }
       else {
         $HTTPFILES{$path} = [ "text/html", $_ ];
         $HTTPSFILES{$path} = [ "text/html", $_ ];
       }
    }

    if (defined $fh) {
	while (<$fh>) {
	    chomp;
	    while (s/\\$//) {	# Join continued lines
		$_ .= <$fh>;
	    }
	    s/#.*//;		# Remove comments, beginning, and ending space
	    s/^\s+//;
	    s/\s+$//;
	    next if (/^$/);	# Skip empty lines
	    my ($cmd, $val) = split /\s+/, $_, 2;
	    if ($cmd eq "password_files") {
		@PASSWD = split /\s+/, $val;
		log_error("Password file list empty") unless (@PASSWD);
	    } elsif ($cmd eq "state_directory") {
		$HORATIO = $val;
            } elsif ($cmd eq "bind.http") {
               ($svaddr, $svport) = split /:/, $val;
            } elsif ($cmd eq "bind.https") {
               ($svsaddr, $svsport) = split /:/, $val;
            } elsif ($cmd eq "lang.pt_BR") {
                $FW_LANG = 0 if ($val =~ /^(1|yes)$/);
            } elsif ($cmd eq "adm_addr") {
                push(@admhost, $val);
            } elsif ($cmd eq "adm_user") {
                $ckadmuser{$val} = "allow";
            } elsif ($cmd eq "restrict_module") {
	        my (undef, $val1, $val2) = split /\s+/, $_, 3;
                push(@{$ckmoduser{$val1}}, "$val2");
            } elsif ($cmd eq "server.name") {
                $servername = $val;
            } elsif ($cmd eq "maxip.sess.admin") {
                $maxip{'admin'} = $val;
            } elsif ($cmd eq "maxip.sess.captive") {
                $maxip{'fwauth'} = $val;
            } elsif ($cmd eq "default.auth.posix") {
                $default{'posix'} = 1 if ($val =~ /^(1|yes)$/);
            } elsif ($cmd eq "default.auth.sql") {
                $default{'sql'} = 1 if ($val =~ /^(1|yes)$/ && $nosql == 0);
            } elsif ($cmd =~ /^sql\./) {
               if ($nosql == 0) {
                 if ($cmd eq "sql.admin.user") {
                    $sqlweb{'admin_user'} = $val;
                 } elsif ($cmd eq "sql.admin.pass") {
                    $sqlweb{'admin_pass'} = $val;
                 } elsif ($cmd eq "sql.admin.server") {
                    $sqlweb{'admin_server'} = $val;
                 } elsif ($cmd eq "sql.web.user") {
                    $sqlweb{'web_user'} = $val;
                 } elsif ($cmd eq "sql.web.pass") {
                    $sqlweb{'web_pass'} = $val;
                 } elsif ($cmd eq "sql.user.self.register") {
                    $sqlweb{'user_self'}=1 if ($val =~ /^(1|yes)$/);
                 } elsif ($cmd eq "sql.web.chk_cpf.field") {
                    $sqlweb{'cpf'}=$val;
                 }
               }
            } elsif ($cmd =~ /^rollcall\./) {
               if ($cmd eq "rollcall.mode") {
                 ($ROLLMODE, $ROLLVALUE) = split /\s+/, $val;
 	       } elsif ($cmd eq "rollcall.period" || $cmd eq "rollcall.interval") {
 	          $ROLLDELAY = $val;
               } elsif ($cmd eq "rollcall.log") {
                  $ROLLLOG=1 if ($val =~ /^(1|yes)$/);
               }
            } elsif ($cmd eq "redir.after.auth") {
                $REDIR = 1 if ($val =~ /^(1|yes)/);
            } elsif ($cmd =~ /^mail\./) {
               if ($cmd eq "mail.server") {
                  $MAILSERVER = $val;
               } elsif ($cmd eq "mail.account") {
                  $MAILACCOUNT = $val;
               }
	    } elsif ($cmd eq "ssl_key") {
		if ($val =~ /^\//) {
		    $KEYFILE = $val;
		} else {
		    log_error("state_directory not defined: $_") unless
			(defined $HORATIO);
		    $KEYFILE = "$HORATIO/$val";
		}
	    } elsif ($cmd eq "ssl_certificate") {
		if ($val =~ /^\//) {
		    $CERTFILE = $val;
		} else {
		    log_error("state_directory not defined: $_") unless
			(defined $HORATIO);
		    $CERTFILE = "$HORATIO/$val";
		}
	    } else {
                log_error("Unrecognized command in $CONFIGFILE: $_");
	    }
	}
        if (-e "/etc/turnkey_version" && -e "/etc/ssl/certs/cert.pem") {
           $KEYFILE = "/etc/ssl/certs/cert.key";
           $CERTFILE = "/etc/ssl/certs/cert.pem";
        }
        $allowmail = 1 if (defined $MAILSERVER && defined $MAILACCOUNT);
	$fh->close;

	log_exit("No password files specified") unless (@PASSWD);
	log_exit("No state directory specified") unless ($HORATIO);
	read_error_files($HTMLDIR);

        ### HTML lang
        if (-d "$HTMLDIR/lang") {
          if ($FW_LANG == 0) {
             if (! -e "$HTMLDIR/admin/pt_BR.weblang" || -e "$HTMLDIR/admin/en.weblang") {
                system("rm -rf $HTMLDIR/admin/*\.weblang 2>/dev/null");
                system("cp -a -f $HTMLDIR/lang/pt_BR/*.html $HTMLDIR/");
                system("cp -a -f $HTMLDIR/admin/lang/pt_BR/*.html $HTMLDIR/admin/");
                system("touch $HTMLDIR/admin/pt_BR.weblang");
             }
          }
          else {
             if (! -e "$HTMLDIR/admin/en.weblang" || -e "$HTMLDIR/admin/pt_BR.weblang") {
                system("rm -rf $HTMLDIR/admin/*\.weblang 2>/dev/null");
                system("cp -a -f $HTMLDIR/lang/en/*.html $HTMLDIR/");
                system("cp -a -f $HTMLDIR/admin/lang/en/*.html $HTMLDIR/admin/");
                system("touch $HTMLDIR/admin/en.weblang");
             }
          }
        }

        log_exit("No SSL keyfile specified") unless (!%HTTPSFILES || $KEYFILE);
        log_exit("No certificate file specified") unless (!%HTTPSFILES || $CERTFILE);
    } else {
        log_exit("Cannot read configuration file $CONFIGFILE");
    }
}

############################################
# Functions: rollcall confs
sub rollcall_cfg {
   $ROLLLOG = 0 if (not $ROLLLOG);
   if ($ROLLDELAY && $ROLLDELAY >= 15) {
      if (!$ROLLMODE || $ROLLMODE !~ /^(fping|session|cookie|forcedown)$/) {
         $ROLLMODE = "forcedown";
         $ROLLVALUE = "";
         log_error("Using *forcedown* rollcall mode!");
      }
      else {
         log_info("Using *$ROLLMODE* rollcall mode");
      }
   }
   else {
      log_info("Warning: Disabled Rollcall (period < 15)!");
      $ROLLDELAY = 0;
   }
}

############################################
# Functions: specific requests

# Show HTTP query string -- testing
sub get_query {
    my $url = shift;
    my $res = HTTP::Response->new(200);
    $res->content_type("text/plain");
    if ($url->query) {
	$res->content($url->query);
    } else {
	$res->content("No query");
    }
    return $res;
}

# Show HTTP request -- testing
sub get_request {
    my $req = shift;
    my $res = HTTP::Response->new(200);
    $res->content_type("text/plain");
    $res->content($req->as_string);
    return $res;
}

# For cookie rollcall mode
sub get_ckauth {
    my $req = shift;
    my $cookie = shift;
    my $cmd = shift;  #make or update
    my $host = shift;
    my $session;
    my $meta = "";
    my @msg = ("", "");
    my @msg2 = ("", "");
    my $res = HTTP::Response->new();

    CGI::Session->name("RTSESS");

    if ($cmd eq "update") {
       $session = CGI::Session->load(undef, $cookie, {Directory=>'/tmp/sessions'});
       if($session->is_expired || $session->is_empty) {
          $session->delete;
          system("/usr/share/fwguardian/webauth/webctl.sh", "leave", "$host", "__rollcall__");
          log_error("Invalid or forbidden session (cookie rollcall mode)");
          $msg[0] = "Tente um novo login";
          $msg[1] = "Try a new login";
          return get_forbidden("$dropsess[$FW_LANG]<BR /><BR /><font color='red'><i>$msg[$FW_LANG]</i></font>", "auth", "");
       }
       else {
          $session->param("ALIVE", "1");
          $msg[0] = "Sua sess&atilde;o permanece ativa!";
          $msg[1] = "Your session stay alive!";
          $msg2[0] = "N&atilde;o feche esta janela...";
          $msg2[1] = "Dont close this window...";
          $txtvalue = msgbox("authorized", "$msg[$FW_LANG]<BR /><BR /><strong>$msg2[$FW_LANG]</strong>", "");
          $meta = "<META HTTP-EQUIV=\"Refresh\" CONTENT=\"10;URL=/ckauth\">";
       }
       $session->flush;
    }
    else {
       $msg[0] = "Acesso liberado";
       $msg[1] = "Access allowed";
       $msg2[0] = "Utilizando o modo de rollcall cookie...";
       $msg2[1] = "Using cookie rollcall mode...";
       $txtvalue = msgbox("authorized", "$msg[$FW_LANG] <i>(PEER)</i>!", "$msg2[$FW_LANG]");
       $meta = "<META http-equiv=\"set-cookie\" content=\"RTSESS=$cookie;expires=$ROLLVALUE;path=/ckauth\">";
       $meta = "$meta <META HTTP-EQUIV=\"Refresh\" CONTENT=\"2;URL=/ckauth\">";
    }

    $meta = "$meta<META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">";
    $txtvalue = "<html><head>$meta</head><body bgcolor=\"#F2F2F2\" $STYLE>$txtvalue</body></html>";
    $res->content($txtvalue);
    return $res;
}

# Close/Remove client apps
sub close_apps {
    my $app_cookie = shift;

    system("$FW_DIR/webauth/shell.sh $FW_DIR/webauth close $app_cookie") if (-e "/tmp/sessions/cgisess_$app_cookie.app.shellinabox");
    system("rm -f /tmp/sessions/cgisess_$app_cookie\.app\.* 2>/dev/null");
}

# Check admin sessions
sub chk_admaccess {
    my $session;
    if (-e "/usr/share/fwguardian/webauth/control/ipsess.admin") {
       CGI::Session->name("FWGSESS");
       open FILE, "</usr/share/fwguardian/webauth/control/ipsess.admin";
       while (my $adm_cookie = <FILE>) {
          $adm_cookie =~ s/\n//;
          $session = CGI::Session->load(undef, $adm_cookie, {Directory=>'/tmp/sessions'});

          # Destroy old sessions
          my $curtime = time();
          my $elapsedtime = $curtime - $session->param("_SESSION_CTIME");
          if($elapsedtime > $session->param("_SESSION_ETIME")) {
             if (-e "/usr/share/fwguardian/modules/bwshell.ctl") {
                my $peer = $session->param("_SESSION_REMOTE_ADDR");
                system("iptables -nL INPUT --line-numbers | grep \" $peer \" | awk \'/ bwshell_ctl / { print \"iptables -D INPUT \"$1; }\' | /bin/bash -") if ($peer);
             }

             $session->delete;
             $session->flush;
             close_apps($adm_cookie);
             system("echo -e \',g/\^$adm_cookie\\$/d\\nw\\nq\'| ed \"/usr/share/fwguardian/webauth/control/ipsess.admin\"");
          }
       }
       close (FILE);
    }
}

# Admin login or logout
sub get_admaccess {
    my $req = shift;
    my $ltype = shift;
    my $cuser = shift;
    my $url = shift;
    my $session;
    my $meta = "";
    my $sid;
    my @msg = ("", "");

    my $res = HTTP::Response->new();

    chk_admaccess;
    CGI::Session->name("FWGSESS");
    if ( $ltype eq "logout" ) {
       # Delete the admin cookie
       system("echo -e \',g/\^$read_cookie\\$/d\\nw\\nq\'| ed \"/usr/share/fwguardian/webauth/control/ipsess.admin\"");

       $session = CGI::Session->load(undef, $read_cookie, {Directory=>'/tmp/sessions'});
       if($session->is_expired || $session->is_empty) {
          $msg[0] = "logout: Nenhuma sessão encontrada.";
          $msg[1] = "logout: No session found.";
          log_info("$msg[$FW_LANG]");
          $txtvalue = msgbox("denied", "Admin logout!", "<BR /><font size='2'>$msg[$FW_LANG]</font>");
       }
       else {
          $msg[0] = "<BR /><i>Sua sess&atilde;o foi removida com seguran&ccedil;a.</i>";
          $msg[1] = "<BR /><i>Your session has been safely removed.<i>";
          $txtvalue = msgbox("info", "Admin logout!", "$msg[$FW_LANG]");
       }

       if (-e "/usr/share/fwguardian/modules/bwshell.ctl") {
          my $peer = $session->param("_SESSION_REMOTE_ADDR");
          system("iptables -nL INPUT --line-numbers | grep \" $peer \" | awk \'\/ bwshell_ctl \/ { print \"iptables -D INPUT \"\$1; }\' | /bin/bash -") if ($peer);
       }

       $session->delete;
       $session->flush;

       close_apps($read_cookie);
       $meta = "<META CACHE-CONTROL=\"no-cache, no-store, must-revalidate\">";
       $url="null";
    }
    else {
       $msg[0] = "Acesso administrativo liberado";
       $msg[1] = "Allowed admin access";
       $txtvalue = msgbox("authorized", "$msg[$FW_LANG] <i>(PEER)</i>!", "");
        
       $session = new CGI::Session(undef, undef, {Directory=>'/tmp/sessions'});
       $sid = $session->id;
       $session->expire('+2h');
       $session->param('user', $cuser);

       if (-e "/usr/share/fwguardian/modules/bwshell.ctl") {
          $bwcount = `cat /usr/share/fwguardian/webauth/control/bwcount | tr -d '\n'` if (-e "/usr/share/fwguardian/webauth/control/bwcount");
          $bwcount++;
          $bwcount = 1 if ($bwcount > 1000);
          system("echo $bwcount > /usr/share/fwguardian/webauth/control/bwcount");
          $session->param('bwcount', $bwcount + 6180);
       }

       $url = "/admin/rrdstats.cgi" if ($norrd == 0 && $url !~ /\?u=/);
       system("echo $sid >> /usr/share/fwguardian/webauth/control/ipsess.admin");
       $meta = "<META http-equiv=\"set-cookie\" content=\"FWGSESS=$sid;expires=+2h;path=/admin\">";
    }

    if ($url =~ /\?u=/) {
       $url =~ s/.*\?u=//g;
    } 
    else {
       $url = "/admin/index2.html" if ($url ne "/admin/rrdstats.cgi");
    }

    $meta = "$meta<META HTTP-EQUIV=\"Refresh\" CONTENT=\"3;URL=$url\">";
    $meta = "$meta<META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">";
    $txtvalue = "<html><head>$meta</head><body bgcolor=\"#F2F2F2\" $STYLE>$txtvalue</body></html>";
    $res->content($txtvalue);

    return $res;
}

# Generic error response
sub get_error {
    my $status = shift;
    my $msg = shift;
    my $res = HTTP::Response->new($status);
    if (defined $errors{$status}) {
	$res->content_type("text/html");
	$res->content($errors{$status});
	${$res->content_ref} =~ s/MESSAGE/$msg/ if $msg;
    } else {
	log_error("Unknown error code: $status");
	$res->content_type("text/plain");
	if ($msg) {
	    $msg = status_message($status) . ":" . $msg;
	} else {
	    $msg = status_message($status);
	}
	$res->content($msg);
    }
    return $res;
}

# Not Found error response
sub get_notfound {
    return get_error(RC_NOT_FOUND, shift);
}
push @errors, RC_NOT_FOUND;

# Authorization Failed error response
sub get_forbidden {
    my $message = shift;
    my $ltype = shift;
    my $url = shift;
    my @msg = ("", "");
    my @msg2 = ("", "");
    my $meta = "CACHE-CONTROL=\"no-cache, no-store, must-revalidate\"";
    return get_error(RC_FORBIDDEN, $message) if ($ltype ne "admin");

    # Define URL refresh
    $res = HTTP::Response->new();
    if ($url =~ /\?u=/) {
       $url =~ s/.*\?u=//g;
    }
    else {
       $url = "/admin/index2.html";
    }
    $meta = "<META $meta HTTP-EQUIV=\"Refresh\" CONTENT=\"3;URL=$url\">";

    # Admin Forbidden response
    $msg[0] = "Negado:";
    $msg[1] = "Forbidden:";
    $msg2[0] = "Login inválido (verifique os logs)!";
    $msg2[1] = "Invalid login (verify the logs)!";
    $txtvalue = msgbox("denied", "$msg[$FW_LANG] <i>$msg2[$FW_LANG]</i>", "$contactmsg[$FW_LANG]");
    $txtvalue = "<html><head>$meta</head><body bgcolor=\"#F2F2F2\" $STYLE>$txtvalue</body></html>";
    $res->content($txtvalue);
    return $res;
}
push @errors, RC_FORBIDDEN;

# Internal Error response
sub get_internal_error {
    return get_error(RC_INTERNAL_SERVER_ERROR, shift);
}
push @errors, RC_INTERNAL_SERVER_ERROR;

# Return a file
sub get_file {
    my $filetype = shift;
    my $filename = shift;
    my @msg = ("", "");
    my $fh = new IO::File $filename, "r";
    if (defined $fh) {
	my $res = HTTP::Response->new(200);
	$res->content_type($filetype);
	$res->content(join("", <$fh>));
	$fh->close;
	return $res;
    } else {
        $msg[0] = "Cannot read file $filename";
        $msg[1] = "N&atilde;o foi poss&iacute;vel ler o arquivo $filename";
        log_error("$msg[$FW_LANG]");
        return get_notfound("$msg[$FW_LANG]");
    }
}

# Return session cookie
sub get_sess {
    my $host = shift;
    my $shost;

    $shost = `grep " $host\$" $CURFILE 2>/dev/null`;
    $shost =~ s/\n//;
    $shost =~ s/ .*//;

    if ($shost ne "") {
       CGI::Session->name("RTSESS");
       my $session = CGI::Session->load(undef, $shost, {Directory=>'/tmp/sessions'});

       if ($session->param("_SESSION_REMOTE_ADDR")) {
          if ($session->is_expired || $session->is_empty) {
             $session->delete;
             $session->flush;
          }
          else {
             $shost = $session->param("_SESSION_REMOTE_ADDR");
          }
       }
    }
    return $shost;
}

# Check if exist a firewall user chain
sub get_urules {
    my $srules = 0;
    my $user = shift;

    $srules = `grep -q \"^gpuser_$user\$\" /usr/share/fwguardian/rtwebauth.chains && echo \"find\" | wc -l`;
    return $srules;
}

# "POST /login.cgi" -> check authorization
sub get_authorization {
    my ($username, $password) = decode_auth_info(shift);
    my $host = shift;
    my $protocol = shift;
    my $ltype = shift;
    my $url = shift;
    my $shost = "null";
    my $srules = 0;
    my @msg = ("", "");
    my $allow = 1;
    my $auxname = $username;

    $ipsess{'admin'} = 0;
    $ipsess{'admin'} = `cat /usr/share/fwguardian/webauth/control/ipsess.admin | wc -l` if (-e "/usr/share/fwguardian/webauth/control/ipsess.admin");

    # Check if routeauth is enabled
    if ($ltype ne "admin") {
       if (! -e "/usr/share/fwguardian/rtauth.ctl" || $ROLLDELAY < 15) {
          $msg[0] = "Recurso desabilitado";
          $msg[1] = "Disabled feature";
          if ($ROLLDELAY < 15) {
              log_info("$msg[1]: Captive portal - Configure a higher rollcall.interval (greater then 14)!");
          }
          else {
              log_info("$msg[1]: Captive portal - None *auth:* policies defined!");
          }
          return get_forbidden("$msg[$FW_LANG]: <b>Captive portal</b>", $ltype, $url);
       }
    }
    else {
       # Check admin hosts
       $allow = verify_adminrequest($host);
       chk_admaccess if ($ipsess{'admin'} > 0);
    }

    # Check auth fields
    if (not $username or not $password) {
       $msg[0] = "Login - Usuário ou senha não informado";
       $msg[1] = "Login - Username or Password not supplied";
       log_info("$msg[$FW_LANG] \($host\)");
       return get_forbidden("$msg[$FW_LANG]", $ltype, $url);
    }
    else {
       $ipsess{'fwauth'} = 0;
       $ipsess{'fwauth'} = `cat /usr/share/fwguardian/webauth/control/CUR_USERS | wc -l`;

       if ($ltype eq "admin" || $ipsess{'fwauth'} >= $maxip{'fwauth'}) {
          if ($ltype eq "admin" && $ipsess{'admin'} >= $maxip{'admin'} || $ltype ne "admin") {
             $msg[0] = "Nro de sessões excedidas: $username ($host)";
             $msg[1] = "Exceeded sessions: $username ($host)";
             log_info("$msg[1]");
             return get_forbidden("$msg[$FW_LANG]", $ltype, $url);
          }
       }
    }

    # Check every file for $username even if one matches with a different password
    push (@PASSWD, 'MySQL') if ($sqlweb{'web_user'});
    foreach my $pwdf (@PASSWD) {
        # Check user credentials to login
        if ($pwdf ne "MySQL" || $ltype eq "admin") {
           my %passwd = read_passwd_file($pwdf);
           next if (not exists $passwd{$username});

           my $salt = $passwd{$username};
#           if ((unix_md5_crypt( $password, $salt ) eq $passwd{$username}) || (crypt($password, $salt) eq $passwd{$username})) {
           if (crypt($password, $salt) eq $passwd{$username}) {
              $allowpos = 1;
           }
        }
        elsif (sqladm("chklogin", "$username", "$password") == 1) {
           $allowsql = 1;
        }

        # Allowed access
        if ($allowpos == 1 || ($allowsql == 1 && $ltype ne "admin")) {
           if ($ltype ne "admin") {

              # Check firewall user configs
              $srules = get_urules($username);

              # Test if need a mapping default user
              if ( $srules == 0 ) {
                  $username = "def_sql" if ($allowsql == 1 && $default{'sql'} == 1);
                  $username = "def_pos" if ($allowpos == 1 && $default{'posix'} == 1);
                  $srules = get_urules($username, $ltype, $url) if ($username =~ /^def_/);
                  if ($srules == 0) {
                     $msg[0] = "ERRO... Regras insuficientes para ";
                     $msg[1] = "ERROR... Insuficient rules for ";
                     log_info("$msg[1] $username");
                     return get_forbidden("$msg[$FW_LANG]<b><FONT color='Red'>$username</FONT></b> ($host)", $ltype, $url);
                  }
               }

               ### Create a new session control!
               if ($ROLLMODE =~ /^(session|cookie)$/) {

                  CGI::Session->name("RTSESS");
 
                  ### Check if exist a valid session
                  $shost = get_sess($host);

                  if($shost eq "") {
                      my $session;
                      $session = new CGI::Session(undef, undef, {Directory=>'/tmp/sessions'});
                      $session->expire("$ROLLVALUE");
                      $session->param("ALIVE", "1");
                      $session->param("NRLOOP", "-1");
                      $shost = $session->id;
                  }
                  else {
                     $msg[0] = "Sua sessão já; está; ativa ($host)";
                     $msg[1] = "Your host session alread alive ($host)";
                     log_info("$msg[1]");
                     return get_forbidden("$msg[$FW_LANG]!", $ltype, $url);
                  }
               }
 
               if (enterhostlist($host,$username,$shost)) {
                   log_info("$host login $auxname from $pwdf via $protocol");
                   return get_ckauth($req, $shost, "make", $host) if ($ROLLMODE eq "cookie");
                   return get_file("text/html", "$HTMLDIR/authorized.html");
               } 
               else {
                   $msg[0] = "Não foi possível adicionar o endereço $host ($auxname/$pwdf)";
                   $msg[1] = "Cannot add host $host ($auxname/$pwdf)";
                   log_info("$msg[1]");
                   return get_internal_error("$msg[$FW_LANG]");
               }
           }
           else {
              if ($allow == 0) {
                 log_info("Denied *admin* access for $host");
              }
              elsif ( $ckadmuser{$username} eq "allow" ) {
                 log_info("Admin user login $username by $host");
                 return get_admaccess($req, "authorized", $username, $url);
              }
           }
        }
    }

    $msg[0] = "Login incorreto em $host ($auxname)";
    $msg[1] = "Incorrect login from host $host ($auxname)";
    log_warning("$msg[1]") if ($allow);
    return get_forbidden("$msg[$FW_LANG]", $ltype, $url);
}

# "POST /logout.cgi" -> logout button
sub get_logout {
    my $host = shift;
    my $protocol = shift;
    my @msg = ("", "");

    # Check if routeauth is enabled
    if (! -e "/usr/share/fwguardian/rtauth.ctl") {
        $msg[0] = "Recurso desabilitado";
        $msg[1] = "Disabled feature";
        log_info("$msg[$FW_LANG]: *Routing Auth*!");
        return get_forbidden("$msg[$FW_LANG]: <b>*Routing Auth*<b>", "", "");
    }
    else {

      ### Remove Rollcall session
      if ($ROLLMODE =~ /^(session|cookie)$/) {

         ### Getting session cookie
         my $shost = get_sess($host);

         CGI::Session->name("RTSESS");
         my $session;

         ### Delete session
         if($shost && $shost ne "") {
            $session = CGI::Session->load(undef, $shost, {Directory=>'/tmp/sessions'});
            $session->delete;
            $session->flush;
         }
      }

      ### Remove host from CUR_USERS
      log_info("$host logout via $protocol");
      if (leavehostlist($host)) {
	  return get_file("text/html", "$HTMLDIR/logout_ok.html");
      } else {
          $msg[0] = "N&atilde;o foi poss&iacute;vel remover o endere&ccedil;o $host";
          $msg[1] = "Cannt remove host $host";
          log_warning("$msg[$FW_LANG]");
          return get_internal_error("$msg[$FW_LANG]");
      }
    }
}


############################################
# Functions: multiplex request methods and paths
#
# This function finds whatever response goes with the request req and
# returns it.
sub get_response {
    my $req = shift;
    my $peer = inet_ntoa(shift);
    my $protocol = shift;
    my $url = $req->url;
    my $res = undef;
    my $mpaddr;
    my $nurl = $url->as_string;
    my $fwcookie = "";
    my @msg = ("", "");
    my $cooktype = "FWGSESS";
    local $SIG{CHLD} = 'DEFAULT';

    # Read Client Cookie
    if ($url =~ /\/(admin|ckauth)/) {
       $cooktype = "RTSESS" if ($url =~ /\/ckauth/);
       foreach (split /;/, $req->header('Cookie')) {
           $_ =~ s/\n//;
           ($fwcookie, $read_cookie) = split /=/, $_ if ($fwcookie ne $cooktype);
       }
       #$ENV{'COOKIE'} = $read_cookie;
       $ENV{'HTTP_COOKIE'} = "$fwcookie=$read_cookie";

       $nurl =~ s/\/admin\/index2\.html//g;
    }
    $ENV{'REMOTE_ADDR'} = $peer;

    # Identify the 'Host' header request
    my $commitRedir = 0;
    $targetHost = $req->header('Host');

    # Set targetHost for internal or url redirs
    my $pubd = $targetHost;
    $pubd =~ s/:[0-9]+//;

    if ($req->method eq 'GET') {

	# GET requests -> If we're serving the URL, return a file
	if (exists $files{$url->path} || $url->path eq "/admin/") {
            if ($url->path =~ /\/account.html/) {
               # test SQL connection
               if ($nosql == 0) {
                  my $dbh = 0, $sql_ok = 1;
                  $dbh = sqladm("connect") or $sql_ok=0;
                  if ($sql_ok == 1 && $dbh != -1 ) {
                     $dbh->disconnect();
                  }
                  else {
                     $sqlweb{'user_self'} = 10;
                  }
               }
               else {
                  $sqlweb{'user_self'} = 10;
               }
               if ($sqlweb{'user_self'} != 1 || ! -e "/usr/share/fwguardian/rtauth.ctl") {
                  my $addmsg="";
                  if ($sqlweb{'user_self'} == 10) {
                     $msg[0] = "N&atilde;o foi poss&iacute;vel conectar ao servidor MySQL!";
                     $msg[1] = "I cant connect on MySQL server!";
                  }
                  else {
                     $msg[0] = "<BR /><strong>*Routing Auth*</strong> desabilitado!";
                     $msg[1] = "<BR />Disabled <strong>*Routing Auth*</strong>!";
                     $addmsg="$msg[$FW_LANG]" if (! -e "/usr/share/fwguardian/rtauth.ctl");

                     $msg[0] = "N&atilde;o autorizado!<BR />$addmsg<BR /><i>Isto requer a op&ccedil;&atilde;o sql.user.self.register</i>";
                     $msg[1] = "Unauthorized!<BR />$addmsg<BR /><i>This need sql.user.self.register</i>";
                  }
                  $res = get_forbidden("$msg[$FW_LANG]", "auth", "") if ($sqlweb{'user_self'} != 1);
               }
               else {
                  $res = get_file(@{$files{$url->path}});
               }
            }
            else {
               if ($url->path =~ /^\/mail.html/ && $allowmail == 0) {
                  $res = mailNotFound();
               }
               else {
                  my $getpath = $url->path;
                  $getpath = "/admin" if ($getpath eq "/admin/");
                  $res = get_file(@{$files{$getpath}});
               }
            }

	    # Testing
	} elsif ($url->path eq "/query.html") {
	    $res = get_query($url);
	} elsif ($url->path eq "/request.html") {
	    $res = get_request($req);
	} elsif ($url->path eq "/admin/logout.html") {
	    $res = get_admaccess($req, "logout", undef, $peer);
	} elsif ($url->path eq "/ckauth") {
	    $res = get_ckauth($req, $read_cookie, "update", $peer);
        } elsif ($url->path =~ "/admin") {
            $res = chkperm($url, $peer, "get", "null");
	}

        # Finding the best server IP address to GET request
        if (find_fwaddr($pubd) == 0) {
           my $cmd;
           $cmd = "ip route get $peer | sed 's/.* src //' ";
           $pubd = $1 if `$cmd` =~ /(\d+\.\d+\.\d+\.\d+)/;
           $res = get_file(@{$files{"/index.html"}}) if (not $res);

           $commitRedir = 1;
        }

        if ($servername && $servername eq $targetHost) {
           $pubd = $servername;
        }
        else {
           $pubd = `hostname -i` if ($pubd eq "" || not $pubd);
        }
        $myaddr = "http://$pubd:$svport";
        $myaddr = "https://$pubd:$svsport" if ($svsport) ;

    } elsif ($req->method eq 'POST') {
	# POST requests -> If it's a login or logout, return the response
	if ($url->path eq "/login.cgi") {
	    $res = get_authorization($req->content, $peer, $protocol, "null", "null");
	} elsif ($url->path =~ "/admlogin.cgi") {
	    $res = get_authorization($req->content, $peer, $protocol, "admin", $url->as_string);
	} elsif ($url->path eq "/logout.cgi") {
	    $res = get_logout($peer, $protocol);

	    # Testing
	} elsif ($url->path eq "/query.html") {
	    $res = get_query($url);
	} elsif ($url->path eq "/request.html") {
	    $res = get_request($req);
        } elsif ($url->path eq "/chaccount.cgi") {
            $res = chaccount($req->content, "insert", "auth");
        } elsif ($url->path eq "/sendmail.cgi") {
            $res = sendmail($req->content, "auth", $peer);
        } elsif ($url->path =~ "/admin") {
            $res = chkperm($url, $peer, "post", $req);

	}
    }
    if ($url->path !~ /\.(js|json|css|jpg|png|gif)$/) {
      if (not $res) {
         # Not serving the URL, bad POST, etc.
         $msg[0] = "Requisição não encontrada";
         $msg[1] = "Request not found";
         log_info(sprintf("$msg[$FW_LANG]: \"%s %s\" (%s)", $req->method, $req->uri, $peer));
         $res = get_notfound(sprintf("$msg[$FW_LANG]: \"%s %s\" (%s)", $req->method, $req->uri, $peer));
      }
      elsif ($url->path !~ /^\/admin/) {
        ## Mapped users
        read_mapaddr;
        foreach (@{$permpeer{$peer}}) {
          $mpaddr="$_<BR />$mpaddr";
        }
        $msg[0] = "Mapeamentos permitidos:";
        $msg[1] = "Allowed maps:";
        ${$res->content_ref} =~ s/\bMPADDR\b/$msg[$FW_LANG] $mpaddr/g;

        if ($mapip{$usern} && $url->path ne "/admlogin.cgi") {
           ${$res->content_ref} =~ s/\bPEER\b/$mapip{$usern}/g; 
        } 
        else {
           ${$res->content_ref} =~ s/\bPEER\b/$peer/g;
        }
        my $access = queryhostlist($peer);
        if ($access eq "denied") {
           $msg[0] = "bloqueado";
           $msg[1] = "denied";
           ${$res->content_ref} =~ s/\bACCESS\b/\<font color=\"red\"\>$msg[$FW_LANG]\<\/font\>/g;
        }
        else {
           $msg[0] = "autorizado";
           $msg[1] = "allowed";
           ${$res->content_ref} =~ s/\bACCESS\b/\<font color=\"\#0B610B\"\>$msg[$FW_LANG]\<\/font\>/g;
        }
        if ($REDIR == 1) {
           system("echo $targetHost > /usr/share/fwguardian/webauth/control/redir/$peer") if ($commitRedir == 1);
           if ($access eq "allowed" && $ROLLMODE ne "cookie") {
              $targetHost = `cat  /usr/share/fwguardian/webauth/control/redir/$peer | tr -d '\n'`;
              ${$res->content_ref} =~ s/URL=\/index-http.html/URL=http\:\/\/$targetHost/ if ($targetHost);
           }
        }
        ${$res->content_ref} =~ s/\bMYADDR\b/$myaddr/g;
      }
      else {
        ${$res->content_ref} =~ s/\[URL\]/$nurl/;
      }
    }
    else {
      if ($req->header('Cache-Control') !~ /(nocache|no-cache)/ && $url->path !~ /^\/admin\/((sqlUser|lease|authlog|authuserlog|tfdata)\.js|(.*)\.json|dynhttp\/img\/.*\.png)/) {
         my $maxage = (3600 * 168); # 7 days
         my $nowtime = time;
         my $ims = $req->header('If-Modified-Since');
         if (defined $ims) {
            my $time = HTTP::Date::str2time($ims);
            $time = $time + $maxage;
            if (defined $time and $time >= $nowtime) {
               my $method = $req->method;
               my $urlpath = $url->path;
               return HTTP::Response->new( &HTTP::Status::RC_NOT_MODIFIED, "$method $urlpath" );
            }
         }
         $res->remove_header('Cache-Control') if ($req->header('Cache-Control'));
         $res->header('Cache-Control', "max-age=$maxage, must-revalidate");
         $res->header('Last-Modified', HTTP::Date::time2str($nowtime));
      }
    }

    # Using HTTPS login if supported
    if ($svsport) {
       if ($url->path eq "/index2.html") {
          ${$res->content_ref} =~ s/\/login.cgi/_WEBLOG/;
          ${$res->content_ref} =~ s/\b_WEBLOG\b/https:\/\/$pubd:$svsport\/login.cgi/;
       }
    }
    ${$res->content_ref} =~ s/\bMYADDR\b/$myaddr/ if ($url->path =~ /\/admin(\/(index.html|\/)|$)$/);

    $res->content_length(length($res->content_ref)) if (defined $res->content_ref);
    $res->date(time);
    if (!$nodebug) {
       log_debug(sprintf("%s - - [%s] \"%s %s %s\" %s %s",
		      $peer, scalar localtime, $req->method, $req->uri,
		      $req->protocol, $res->code, $res->content_length));
    }
    return $res;
}

############################################
# Functions: Serve web requests
# sub REAPER { 1 until waitpid(-1 , WNOHANG) == -1 };
sub REAPER {
  my $rchild;
  my $sign = shift;

  while (($rchild = waitpid(-1,WNOHANG)) > 0) {}
  $SIG{CHLD} = \&REAPER;
}

sub server_loop {
    my $d = shift;
    my $protocol = shift;

    $SIG{CHLD} = \&REAPER;
    openlog "fwguardian(webauth):", "cons,pid", "daemon";	# Syslog?
    while (1) {
	$c = eval { $d->accept; } until ($c);	# Skip errors and timeouts
	if (!fork) {
	    if ($protocol eq 'HTTPS') {
		$d->close(SSL_no_shutdown => 1);
	    } else {
                $c->timeout(30);   #Include timeout
		$d->close();
	    }
	    $0 = "$0 [" . $c->peerhost . "]";
	    while ($req = $c->get_request) {
               if ($req->method eq 'GET' || $req->method eq 'POST') {
                  $c->send_response(get_response($req, $c->peeraddr, $protocol));
                  $c->force_last_request;
               }
               else {
                  exit;
               }
	    }
	    exit;
	}
	if ($protocol eq 'HTTPS') {
	    $c->close(SSL_no_shutdown => 1);
	} else {
	    $c->close();
	}
	undef($c);
    }
}

############################################
# Child process: Periodic Rollcall validations
sub CHDROLL {
   $ROLLMODE = shift;
   $ROLLLOG = shift;

   if ($child = fork) { return $child; }
   $0 = "$0 [rollcall]";     # Set process name
   log_debug("ROLLCALL process forked");
   $SIG{HUP} = "DEFAULT";             # Reset SIGHUP handler
   #$SIG{CHLD} = \&REAPER;
   openlog "fwguardian(webauth):", "cons,pid", "daemon";	# Syslog?

   my $host;
   my $shost;
   my $diftime;
   my $candel;
   my $session;

   my ($ctloop, $nrloop) = 0;  #Loop counter
   while (1) {
      $ctloop++;
      $nrloop = $ctloop % 2;

      ### Read control auth file
      if (-e $CURFILE) {

         open (CRFILE, "cat $CURFILE|");
         while (<CRFILE>) {
           $candel=0;
           ($shost, undef, $host) = split /\s+/, $_;

           ### Rollcall by session mode
           if ( $ROLLMODE =~ /^(cookie|session)$/ ) {

              $ENV{'REMOTE_ADDR'} = $host;
              CGI::Session->name("RTSESS");
              $session = CGI::Session->load(undef, $shost, {Directory=>'/tmp/sessions'});
              $diftime = $session->atime - $session->ctime;
              $ENV{'REMOTE_ADDR'} = $session->param("_SESSION_REMOTE_ADDR") if ($ROLLMODE eq "cookie");
              if ($session->is_expired || $session->is_empty || $diftime >= $session->param("_SESSION_ETIME") || ($session->param("ALIVE") eq "0" && $session->param("NRLOOP") ne $nrloop)) {
                 $session->delete;
                 $session->flush;
                 $candel=1;
              }
              else {
                 if ($ROLLMODE eq "cookie") {
                    $session->param("ALIVE", "0");
                    $session->param("NRLOOP", $nrloop);
                 }
              }
              $session->flush;
           }
           elsif ( $ROLLMODE eq "fping") {
              ### Rollcall by fping mode
              $candel = system("fping -u $host 2>/dev/null"); 
           }

           ### Logout by rollcall 
           if ($candel == 1 || $ROLLMODE eq "forcedown") {
              log_info("Logout by Rollcall: $host") if ($ROLLLOG);
              system("/usr/share/fwguardian/webauth/webctl.sh", "leave", "$host", "__rollcall__");
           }
         }
         close (CRFILE);
      }
      sleep $ROLLDELAY;
      $ctloop = $nrloop;
   }
   exit; 
}

############################################
# Child process: Serve HTTP requests
sub HTTP {
    if ($child = fork) { return $child; }
    $0 = "$0 [http]";		# Set process name
    use HTTP::Daemon;
    log_debug("HTTP server forked");
    $SIG{HUP} = "DEFAULT";	# Reset SIGHUP handler
    read_config_file;
    %files = %HTTPFILES;
    my $d = new HTTP::Daemon LocalAddr => $svaddr, LocalPort => $svport, Reuse => 1;
    server_loop($d, "HTTP") if ($d);
    log_debug("HTTP server exiting: $d");
    exit;
}

############################################
# Child process: Serve HTTPS requests
sub HTTPS {
    if (!defined $svsaddr) { return; }
    if ($child = fork) { return $child; }
    $0 = "$0 [https]";		# Set process name
    use HTTP::Daemon::SSL;
    # use IO::Socket::SSL;
    # $IO::Socket::SSL::DEBUG = 5;
    # use Net::SSLeay;
    # $Net::SSLeay::trace=3;
    log_debug("HTTPS server forked");
    $SIG{HUP} = "DEFAULT";	# Reset SIGHUP handler
    read_config_file;
    %files = %HTTPSFILES;
    my $d = new HTTP::Daemon::SSL (LocalAddr => $svsaddr,
                                   LocalPort => $svsport,
				   ReuseAddr => 1,
				   SSL_verify_mode => 0x00,
				   SSL_server => 1,
				   SSL_error_trap => sub {},
				   SSL_key_file => $KEYFILE,
				   SSL_cert_file => $CERTFILE);
#				   Timeout => 10);               # bug with large POST
    server_loop($d, "HTTPS") if ($d);
    log_debug("HTTPS server exiting: $d");
    exit;
}


############################################
# Main: an HTTP/HTTPS server
$CONFIGFILE = "$WEB_DIR/webauth.conf";
read_mapuser;
read_fwips;
read_fwcfg;
read_profiles;
$nodebug = 0;
%file_cfg = ();
%ckadmuser = ();
%ckmoduser = ();
%rsgp_syncfiles = ();

@srcrsync = ();
push(@srcrsync, "default");

%maxip = ();
%ipsess = ();
%sqlweb = ();
$sqlweb{'cpf'}="";
$default{'sql'} = 0;
$default{'posix'} = 0;
$maxip{'admin'} = 256;          # Max admin sessions
$maxip{'fwauth'} = 1000;        # Max firewall auth sessions

$bwcount = 0;                   # Set shellinabox port counter

$REDIR = 0;                     # Redir url when "redir.after.auth" yes 
$targetHost = "";

if (fork) { exit; }		# Become a daemon
setpgrp;			# Make a new process group
				# Sysloging
openlog "fwguardian(webauth):", "cons,pid", "daemon";
read_config_file;		# Set up global variables
				# Change to Horatio directory
rollcall_cfg;                   # Setting and checking the rollcall defs
chdir $HORATIO or log_exit("Cannot change dir to $HORATIO");
open STDIN, "</dev/null";	# File descriptors
				# Redirect output to log file
rename "webauth.out", "webauth.out.0" if (-e "webauth.out");
open STDOUT, ">webauth.out" or log_exit("Cannot redirect output");
open STDERR, ">webauth.out";
record_pid("webauth.pid");	# Record master process id

# Only with fwguardian --reload-rules
#restorehostlist;		# Break locks, reopen existing hosts

$0 = "$0 [master]";		# Set process name

$SIG{HUP} = sub {
    read_config_file;
				# Restart servers
    if (defined $http) {
	kill "TERM", $http;
	undef $http;
    }
    if (defined $https) {
	kill "TERM", $https;
	undef $https;
    }
    if (defined $rollcall) {
	kill "TERM", $rollcall;
	undef $rollcall;
    }

    $http = HTTP if (%HTTPFILES);
    $https = HTTPS if (%HTTPSFILES);
    $rollcall = CHDROLL($ROLLMODE,$ROLLLOG) if ($ROLLDELAY >= 15);
};
kill "HUP", $$;			# Start servers

$SIG{TERM} = sub {		# Pass on TERM signals and exit
    kill "TERM", $http if (defined $http);
    kill "TERM", $https if (defined $https);
    kill "TERM", $rollcall if (defined $rollcall);
    exit;
};

$http = HTTP if (%HTTPFILES && not defined $http);
$https = HTTPS if (%HTTPSFILES && not defined $https);
$rollcall = CHDROLL($ROLLMODE,$ROLLLOG) if ($ROLLDELAY >= 15 && not defined $rollcall);


# Deprecated sigalarm
#$SIG{ALRM} = sub {		# Periodic rollcall
#    CHDROLL($ROLLMODE,$ROLLLOG);
#    alarm $ROLLDELAY;
#};
#alarm $ROLLDELAY if ($ROLLDELAY >= 15);

while (1) {			# Master loop
    $id = wait;
    if (defined $http && $id == $http) {
	log_info("HTTP daemon died");
    } elsif (defined $https && $id == $https) {
	log_info("HTTPS daemon died");
    } elsif (defined $rollcall && $id == $rollcall) {
	log_info("Rollcall daemon died");
    }
}
