#!/usr/bin/perl
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# Cluster server (ClusterManager v1.0)
#  - This is a main cluster control (join, leave, ssh key exchange and etc)
#  - Sets the cluster environment according to the cluster.conf file
#  - Works with UDP socket for multicast communications
#  - Works with TCP socket or ssh connection for node updates
#

use IO::File;
use File::Path;
use File::Path;
use Sys::Syslog;
use Term::ANSIColor;
use POSIX ":sys_wait_h";

# Try to include "Socket::Multicast" support
use IO::Socket;
my $nomcast = 0;
eval "use IO::Socket::Multicast; 1" or $nomcast = 1;


sub BEGIN {
   $FW_DIR=`readlink -f "\$(dirname $0)"/`;
   substr($FW_DIR, index($FW_DIR, ' '), 1) = '';
   $FW_DIR =~ s/modules.*//;
   $filecfg = "$FW_DIR/cluster/cluster.conf";
   $DATA_DIR = "/usr/share/fwguardian/cluster";

   $clid = 1;
   $wtchk = 1;
   $clkey = "";
   $mbaddr = `hostname -i | cut -d ' ' -f1 | tr -d '\\n'`;
   $mgaddr = $mbaddr;
   $gl_group = "";

   $mself = 0;
   $syncw = 0;
   $waitst = 0;
   $daemon = 0;
   $members = 0;
   $ena_gluster = 0;
}
sub log_info    { syslog("info", "%s", shift); }


## Server options
sub help {
   system("clear");
   print "\nClusterManager 'options'\n";
   print "\n\t--help                                     This help";
   print "\n\t--daemon                                   Run as service (daemon)\n\n";
}

## Recording process id
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

## Server TCP unicast socket address
sub serverBind {
   my $socket = new IO::Socket::INET(
        LocalHost => $mbaddr,
        LocalPort => 5858,
        Proto     => 'tcp',
        Listen    => 250,
        MultiHomed => 1,
        Reuse     => 1);
   $socket or die "I cant bind in $mbaddr:5858";
   return $socket;
}

## Server UDP multicast socket address
sub mcastBind {
   my $socket = IO::Socket::Multicast->new(
        Proto      => 'udp',
        LocalPort  => 5858,
        LocalAddr  => '225.1.1.12',
        ReuseAddr  => 1);
   $socket or die "I cant bind in $mbaddr:5858";
   return $socket;
}

## Member request (member->peer)
sub mgrReq {
   my $reqpeer = shift;

   if (-e "$DATA_DIR/members/$reqpeer/status.ok" || not -e "$DATA_DIR/sshkey/$reqpeer.cldsa.key.pub") {
      my $socket = new IO::Socket::INET(
          PeerAddr => $reqpeer,
          PeerPort => 5858,
          Timeout => 3,
          Proto    => 'tcp');
      $socket or return undef;
      return $socket;
   }
   else{
      return undef;
   }
}

## Force sync (when a dead peer comes back)
sub force_sync {
   my $speer = shift;

   if ($speer ne "") {
      log_info("Resync peer:$speer");
      system("touch /var/tmp/clustersync.lock");

      my $syncport = `cat $DATA_DIR/ssh | tr -d '\n'`;
      $syncport = "22" if (not $syncport);
      my $sshopt = "-o \'ConnectTimeout 3\' -o \'StrictHostKeyChecking no\' -p $syncport -i $DATA_DIR/sshkey/cldsa.key";
      my $synclog = "$FW_DIR/logs/cluster_rsync.log";

      my $syncdir = "/var/tmp";
      my $files_cfg="alias accesslist/trust accesslist/bannedroutes accesslist/bannedaccess profile/profile.def fwmasq.net fwhosts fwmsn fwinput routing/fwroute.rules routing/fwroute.nat routing/fwroute.tables webauth/webauth.conf webauth/filedit.conf tfshape/shape.conf vpn/vpn.conf cluster/rsync.mapps cluster/gluster.mapps";

      foreach my $auxfile (split /\s+/, $files_cfg) {
         # Sync default files
         my $syncfile="$FW_DIR/$auxfile";
         my $syncdir = `dirname $syncfile | tr -d '\n'`;
         system("rsync -arlpq -e \"ssh $sshopt\" $syncfile root\@$speer:$syncdir 2>&1 >> $synclog");

         # Sync group mapped files
         if (-e "/usr/share/fwguardian/webauth/control/sourcefile") {
            foreach my $sfiles (`cat /usr/share/fwguardian/webauth/control/sourcefile`) {
               $sfiles =~ s/\n//;
               my $syncdir = `dirname $syncfile | tr -d '\n'`;
               foreach my $syncfile (@{$rsgp_syncfiles{$sfiles}}) {
                  system("rsync -arlpq -e \"ssh $sshopt\" $syncfile root\@$speer:$syncdir 2>&1 >> $synclog");
               }
            }
         }
      }

      system("rsync -arlpq --delete -e \"ssh $sshopt\" /usr/share/fwguardian/modules/ root\@$speer:/usr/share/fwguardian/modules/ 2>&1 >> $synclog");
      rmtree("/var/tmp/clustersync.lock");
   }
}

# Get peer ssh pub key
sub get_sshkey {
   my $peeraddr = shift;
   my $sock = mgrReq($peeraddr);

   if (defined $sock) {
      $sock->autoflush(1);
      $sock->send("interactive\n");
      $sock->recv($buf, 48);

      # Send hello command for access test
      $err = 0;
      $sock->send("hello\n");
      $sock->recv($buf, 40);
      $err = 1 if ($buf !~ /^200: Ok/);

      # Getting the ssh pub key
      if ($err == 0) {
         $sock->send("get-sshkey\n");
         $sock->send("exit\n");
         open FILE, ">$DATA_DIR/sshkey/$peeraddr.cldsa.key.pub";
         while (my $s = <$sock>) {
            print FILE "$s" if ($s ne "Goodbye...\n");
         }
         close(FILE);
      }
   }
   close $sock;
}

## FwGuardian restart function
sub fwRestart {
   system("$FW_DIR/fwguardian --ignore-cluster 2>&1 >/dev/null");
   system("$FW_DIR/fwguardian --ignore-webserver 2>&1 >/dev/null");
   system("$FW_DIR/fwguardian 2>&1 >/dev/null &");
}

## Master election
sub master_election {
   my $mpeer = `cat $DATA_DIR/cluster.clid | sort -k1,2 -n | head -1 | cut -d ' ' -f2 | tr -d '\n'`;

   if (length($mpeer) > 5) {
      log_info("Master election call!");
      rmtree("$DATA_DIR/members/$mgaddr/manager") if (-e "$DATA_DIR/members/$mgaddr/manager");

      if ($mpeer eq $mbaddr) {
         # Setting as manager
         $ismanager=1;
         if (not -e "/var/tmp/cluster.manager") {
            log_info("Changing to *Master* state!");
            system("touch /var/tmp/cluster.manager");
         }
         system("touch $DATA_DIR/members/$mpeer/manager");
      }
      else {
         # Setting as slave
         $ismanager=0;
         if (-e "/var/tmp/cluster.manager") {
            log_info("Changing to *Slave* state!");
            rmtree("/var/tmp/cluster.manager");
            rmtree("/var/tmp/master.fault.$mpeer") if (-e "/var/tmp/master.fault.$mpeer");
            rmtree("$DATA_DIR/members/$mbaddr/manager") if (-e "$DATA_DIR/members/$mbaddr/manager");

            if (-e "/var/tmp/cluster.forcesync") {
               system("touch $DATA_DIR/allowed/$mpeer.forcesync");
               rmtree("/var/tmp/cluster.forcesync");
            }
            system("touch /usr/share/fwguardian/modules/restart") if (not -e "$DATA_DIR/members/$mpeer/manager");
         }

         # Setting the new manager
         log_info("Setting a new Master:$mpeer");
         system("touch $DATA_DIR/members/$mpeer/manager");
      }
      $mgaddr = $mpeer;
   }
}

## Peer verify
sub chkPeers {
   my $cmd = shift;
   my @peerkey = ();
   system("rm -f $DATA_DIR/cluster.clid") if ($cmd eq "flush-rsync");

   # Update peer status
   my $plist = "";
   foreach my $peeraddr (`ls $DATA_DIR/members/ 2>/dev/null`) {
      $peeraddr =~ s/\n//;
      my $memberpath="$DATA_DIR/members/$peeraddr";
      if (-e "$DATA_DIR/allowed/$peeraddr") {
         if ($plist eq "") { 
            $plist = $peeraddr;
         }
         else {
            $plist = "$plist $peeraddr";
         }
      }

      if (-d $memberpath && not -e "$memberpath/status.dead") {
         if ($cmd eq "flush-rsync") {
            rmtree("$memberpath") if (-e "$memberpath/rsync");
         }
         else {
            if (-e "$memberpath/status.fault2") {
               log_info("Peer DOWN:$peeraddr");
               system("touch $memberpath/status.dead");
               if (-e "$memberpath/manager") {
                  system("touch /var/tmp/master.fault.$peeraddr");
                  rmtree("$memberpath/manager");
               }
               system("echo -e ',g/ $peeraddr\$/d\nw\nq' | ed \"$DATA_DIR/cluster.clid\" 2>&1 >/dev/null");
               rmtree("$memberpath/cluster.clid");
               rmtree("$memberpath/status.ok");
               master_election;
            }
            else {
               if (-e "$DATA_DIR/sshkey/$peeraddr.cldsa.key.pub") {
                  if (-e "$memberpath/status.ok" && $waitst > 3) {
                     system("touch $memberpath/status.fault2") if (-e "$memberpath/status.fault1");
                     system("touch $memberpath/status.fault1") if (-e "$memberpath/status.warn");
                     system("touch $memberpath/status.warn");
                  }
               }
               else {
                  push(@peerkey, $peeraddr) if (-e "$DATA_DIR/allowed/$peeraddr" && $peeraddr ne $mbaddr);
               }
            }
         }
      }
   }

   # Update authorized_keys and PAM access module (root access)
   my $updkey=0;
   system("touch /var/tmp/clustersync.lock");
   if (scalar @peerkey > 0) {
      system("echo -e \",g/ #pam_clfgaccess/d\\nw\\nq\" | ed \"/etc/security/access.conf\"");
      system("echo -e \",g/ #pam_clfgaccess/d\\nw\\nq\" | ed \"/etc/pam.d/sshd\"");
      foreach my $peeraddr (@peerkey) {
         $updkey=1;
         get_sshkey($peeraddr);
      }
   }
   if ($updkey == 1) {
      rmtree("$DATA_DIR/sshkey/authorized_keys2");
      system("echo -e ',g/fgcluster_/d\nw\nq' | ed \"/root/.ssh/authorized_keys2\" 2>&1 >/dev/null") if (-e "/root/.ssh/authorized_keys2");
      foreach my $akey (`ls $DATA_DIR/sshkey/*.key.pub 2>/dev/null`) {
         $akey =~ s/\n//;
         system("cat $akey >> /root/.ssh/authorized_keys2");
      }

      if ($plist ne "") {
         my $ssh_fpsize = "cat /etc/pam.d/sshd | wc -l | tr -d '\n'";
         $plist = "-:root:ALL EXCEPT localhost 127.0.0.1 $plist   #pam_clfgaccess";
         system("echo \"$plist\" >> /etc/security/access.conf");
         if ($ssh_fpsize < 3) {
            system("echo \"account     required    pam_access.so   #pam_clfgaccess\" > /etc/pam.d/sshd");
         }
         else {
            system("sed -i \"/account .*system-auth/ iaccount     required    pam_access.so   #pam_clfgaccess\" /etc/pam.d/sshd");
         }
      }
   }
   rmtree("/var/tmp/clustersync.lock");
}

# Make Gluster config
sub make_glustercfg {
  my $peeraddr = shift;

  if (-e "$FW_DIR/cluster/gluster.mapps") {
     my $glgroup = "";
     my $auxmb = 2;
     $auxmb = 1 if ($members == 1);
     system("touch /var/tmp/clustersync.lock");
     log_info("Making glusterfs configuration for:$auxmb member(s)!");
     rmtree("/tmp/glusterfs.lock");
     rmtree("$FW_DIR/cluster/glusterfs/done");

     if (-e "/var/tmp/cluster.manager") {
        sleep 5;
        my %allowaddr = ();
        my $EXP_DIR = "", $peerpb = 0;
        open FILE, "<$FW_DIR/cluster/gluster.mapps";
        while (my $glines = <FILE>) {
           $glines =~ s/\n//;
           if ($glines =~ /^[\s]*group[\s]/) {
              $glgroup = $glines;
              (undef, $glgroup) = split /\s+/, $glgroup, 2;
              $glgroup = "gl_$glgroup";
              $EXP_DIR = "$FW_DIR/cluster/glusterfs/export/$glgroup";
              $allowaddr{$glgroup} = "$mbaddr";

              # Redefine allowed policies
              system("umount -f -l $FW_DIR/cluster/glusterfs/cluster/$glgroup 2>/dev/null");

              # Set gluster brick type (self or replica) - "autoconfiguration"
              # This configure replica only for the first 2 peers, but you can use the gluster cmds for add new bricks and you can allow it into "fwinput")
              sleep 1;
              system("echo 1:$glgroup | sed 's/1:/echo y | gluster volume stop force /' | /bin/bash - 2>/dev/null");
              system("echo 1:$glgroup | sed 's/1:/echo y | gluster volume delete /' | /bin/bash - 2>/dev/null");
              if (-d "$EXP_DIR") {
                 rmtree("/tmp/$glgroup") if (-d "/tmp/$glgroup");
                 rmtree("$FW_DIR/cluster/glusterfs/local/$glgroup") if (-d "$FW_DIR/cluster/glusterfs/local/$glgroup");
                 rmtree("$FW_DIR/cluster/glusterfs/cluster/$glgroup") if (-d "$FW_DIR/cluster/glusterfs/cluster/$glgroup");

                 system("mv $EXP_DIR /tmp/");
                 mkpath("$EXP_DIR");
              }
              if ($mself == 0) {
                 if ($peerpb == 0) {
                    $peerpb = 1;
                    system("gluster peer probe $peeraddr");
                    sleep 1;
                 }
                 system("gluster volume create $glgroup replica 2 transport tcp $mbaddr:$EXP_DIR $peeraddr:$EXP_DIR");
              }
              else {
                 system("gluster volume create $glgroup transport tcp $mbaddr:$EXP_DIR");
              }

              # Volume settings
              log_info("Fwguardian/Glusterfs: Making volume $glgroup...");
              mkpath("$FW_DIR/cluster/glusterfs/local/$glgroup") if (not -d "$FW_DIR/cluster/glusterfs/local/$glgroup");
              mkpath("$FW_DIR/cluster/glusterfs/cluster/$glgroup") if (not -d "$FW_DIR/cluster/glusterfs/cluster/$glgroup");
              system("gluster volume set $glgroup nfs.disable on");
              system("gluster volume set $glgroup performance.cache-max-file-size 2MB");
              system("gluster volume set $glgroup performance.cache-refresh-timeout 4");
              system("gluster volume set $glgroup performance.cache-size 128MB");
              system("gluster volume set $glgroup performance.write-behind-window-size 4MB");
              system("gluster volume set $glgroup performance.io-thread-count 32");
              system("gluster volume start $glgroup");
              rmtree("$EXP_DIR/allow.proxy") if (-e "$EXP_DIR/allow.proxy");
              rmtree("$EXP_DIR/allow.firewall") if (-e "$EXP_DIR/allow.firewall");
              if ($mbaddr ne $peeraddr || $mself == 0) {
                 $allowaddr{$glgroup} = "$mbaddr,$peeraddr";
                 system("gluster volume set $glgroup auth.allow $mbaddr,$peeraddr");
              }
              else {
                 system("gluster volume set $glgroup auth.allow $mbaddr");
              }
           }
           else {
              if ($glgroup ne "") {
                 my $auxgl = $glines;
                 $auxgl =~ s/^\s+//;
                 my ($glcmd, $glval) = split /\s+/, $auxgl, 2;
                 if ($glcmd eq "allow-policy") {
                    system("touch $FW_DIR/cluster/glusterfs/export/$glgroup/allow.proxy") if ($glval eq "proxy");
                    if ($glval eq "firewall") {
                       system("touch $FW_DIR/cluster/glusterfs/export/$glgroup/allow.firewall");

                       my $files_cfg="accesslist/trust accesslist/bannedroutes accesslist/bannedaccess profile/profile.def fwmasq.net fwhosts fwinput routing/fwroute.rules routing/fwroute.nat routing/fwroute.tables tfshape/shape.conf vpn/vpn.conf";
                       mkpath("$EXP_DIR") if (not -d "$EXP_DIR");
                       mkpath("$EXP_DIR/vpn");
                       mkpath("$EXP_DIR/profile");
                       mkpath("$EXP_DIR/tfshape");
                       mkpath("$EXP_DIR/routing");
                       mkpath("$EXP_DIR/accesslist");
                       foreach my $auxfile (split /\s+/, $files_cfg) {
                           system("touch $EXP_DIR/$auxfile");
                       }

                       system("rsync -arlpq --exclude '*~' --exclude '^.' /tmp/$glgroup/ $EXP_DIR/ 2>/dev/null >/dev/null") if (-d "/tmp/$glgroup");
                    }
                 }
                 elsif ($glcmd eq "allow-ipaddr") {
                    $allowaddr{$glgroup} = "$allowaddr{$glgroup},$glval";
                    system("echo $glval >> $DATA_DIR/glusterfs.done");

                    system("gluster volume set $glgroup auth.allow $allowaddr{$glgroup}");
                 }
              }
           }
        }
        my $syncport = `cat $DATA_DIR/ssh | tr -d '\n'`;
        $syncport = "22" if (not $syncport);

        system("touch $FW_DIR/cluster/glusterfs/done");
        system("ssh -i $DATA_DIR/sshkey/cldsa.key -p $syncport $peeraddr \"touch $FW_DIR/cluster/glusterfs/done\"");
        close(FILE);
     }
     else {
        # Rebuild slave directory
        if (-d "$FW_DIR/cluster/glusterfs/local") {
           rmtree("$FW_DIR/cluster/glusterfs/local");
           mkpath("$FW_DIR/cluster/glusterfs/local");
        }
        if (-d "$FW_DIR/cluster/glusterfs/cluster") {
           rmtree("$FW_DIR/cluster/glusterfs/cluster");
           mkpath("$FW_DIR/cluster/glusterfs/cluster");
        }
        if (-d "$FW_DIR/cluster/glusterfs/export") {
           rmtree("$FW_DIR/cluster/glusterfs/export");
           mkpath("$FW_DIR/cluster/glusterfs/export");
        }

        # wait upto 120s when slave
        my $waitsl = 0;
        while ($waitsl < 120) {
           sleep 1;
           $waitsl = 120 if (-e "$FW_DIR/cluster/glusterfs/done");
           $waitsl++;
        }
     }
     system("touch $DATA_DIR/glusterfs.done");
     system("$FW_DIR/modules/tools/cluster/glusterfs/restart.sh $FW_DIR");
     sleep 3;
     if (-e "/var/tmp/cluster.manager") {
        system("rsync -arlpq --exclude '*~' --exclude '^.' $FW_DIR/cluster/glusterfs/export/ $FW_DIR/cluster/glusterfs/cluster/ 2>/dev/null >/dev/null");
     }
     elsif ($gl_group ne "") {
        if ($daemon == 1) {
           rmtree("$FW_DIR/cluster/glusterfs/local/fs") if (-e "$FW_DIR/cluster/glusterfs/local/fs");
           system("rsync -arlpq --exclude '*~' --exclude '^.' $FW_DIR/cluster/glusterfs/cluster/$gl_group $FW_DIR/cluster/glusterfs/local/ 2>/dev/null >/dev/null");
           system("ln -sf $FW_DIR/cluster/glusterfs/local/$gl_group $FW_DIR/cluster/glusterfs/local/fs");
        }
     }

     sleep 3;
     fwRestart;
     rmtree("/var/tmp/clustersync.lock");
  }
  else {
     log_info("Ignoring glusterfs: Sorry, i cant find gluster.mapps file");
  }
}

# Read cluster.conf
sub read_config_file {
   my $fh = new IO::File $filecfg, "r";
   my $settype = "";
   if (defined $fh) {
      while (<$fh>) {
          chomp;
          while (s/\\$//) {
              $_ .= <$fh>;
          }
          s/#.*//;
          s/^[\s]*;.*//;
          s/^\s+//;
          s/\s+$//;
          next if (/^$/);

          if ($_ =~ /^[\s]*(set-|(member_pass|gluster_(server|group)|self_member|heartbeat|cluster_id|host_id)[\s])/) {
             my ($opt, $val, $auxval, $auxval2) = split /\s+/, $_, 4;
             $val =~ s/[\||&|;]//g;

             if ($opt eq "cluster_id" || $opt eq "host_id") {
                $clid = $auxval;

                mkpath("$DATA_DIR/sshkey") if (not -d "$DATA_DIR/sshkey");
                mkpath("$DATA_DIR/allowed") if (not -d "$DATA_DIR/allowed");
             } elsif ($opt eq "member_pass") {
                $clkey = $val;
             } elsif ($opt eq "gluster_server") {
                rmtree("/var/tmp/gluster.server") if (-e "/var/tmp/gluster.server");
                if ($val ne "none") {
                   $ena_gluster = 1;
                   system("echo $val > /var/tmp/gluster.server") if ($val ne "any");
                   system("touch /usr/share/fwguardian/cluster.glusterfs-server") if (not -e "/usr/share/fwguardian/cluster.glusterfs-server");
                }
             } elsif ($opt eq "gluster_group" && $ena_gluster == 1) {
                if ($val ne "none") {
                   $gl_group = "gl_$val";
                   system("echo gl_$val > /var/tmp/gluster.group");
                   if ($daemon == 1) {
                      rmtree("$FW_DIR/cluster/glusterfs/local/fs") if (-e "$FW_DIR/cluster/glusterfs/local/fs");
                      system("ln -sf $FW_DIR/cluster/glusterfs/local/gl_$val $FW_DIR/cluster/glusterfs/local/fs");
                   }
                }
                else {
                   rmtree("/var/tmp/gluster.group") if (-e "/var/tmp/gluster.group");
                   rmtree("$FW_DIR/cluster/glusterfs/local/fs") if (-e "$FW_DIR/cluster/glusterfs/local/fs");
                }
             } elsif ($opt eq "self_member" && $val eq "yes") {
                $mself = 1;
                $members=1;
             } elsif ($opt =~ /^[\s]*set-/) {
                $settype="";
                $settype="interface" if ($opt eq "set-interface");
             } elsif ($opt eq "heartbeat" && $settype eq "interface") {
                $mbaddr = $auxval;
                $mbaddr =~ s/\/.*//;
                if ($mself == 1) {
                   system("touch /var/tmp/cluster.manager");
                   if ($daemon == 1 && not -e "/var/tmp/gluster.server") {
                      if (not -e "$DATA_DIR/glusterfs.done") {
                         if ($mbaddr eq "127.0.0.1") {
                            log_info("ERR: You cant configure a 127.0.0.1 peer");
                         }
                         else {
                            make_glustercfg("$mbaddr");
                         }
                      }
                   }
                }
                else {
                   system("ssh-keygen -t dsa -f $DATA_DIR/sshkey/cldsa.key -q -N '' -C \'fgcluster_$mbaddr\'") if (not -e "$DATA_DIR/sshkey/cldsa.key");
                }
                system("echo $mbaddr $val >> /var/tmp/cluster.sync.peers") if (not -e "/var/tmp/cluster.sync.peers");
             }
          }
       }
   }
   else {
     print "\tERR: I cant read cluster.conf!\n";
     exit;
   }
   print " Cluster Manager\n" if ($ismanager);
}

## Load cluster.conf defs
$ismanager = 0;

sub REAPER {
  my $rchild;
  my $sign = shift;

  while (($rchild = waitpid(-1,WNOHANG)) > 0) {}
  $SIG{CHLD} = \&REAPER;
}

## TCP server loop
sub tcpServer {
   my $interactive = 0;
   my ($d, $buf);

   # Fork tcp unicast server
   my $sock = serverBind;
   if (my $child = fork) { return $child; }

   $SIG{CHLD} = \&REAPER;
   openlog("fwguardian(webauth): TCP ClusterManager ($mbaddr)", "cons,pid", "daemon");
   STDOUT->autoflush(1);

   $0 = "$0 [TCP Server]";
   print " Bind address = $mbaddr:5858" if (not $daemon);
   while (1) { # Bind Loop
     while ($d = $sock->accept()) { # Request Loop
        $interactive = 0;
        my $peer = $d->peerhost;
        next if $child = fork;
        die "fork: $!" unless defined $child;

        print($d "FwGuardian - ClusterManager v1.0\n");
        while (defined($buf = <$d>)) {
          if ($buf =~ /^(\s)*\binteractive\b/) {
             $interactive = 1;
          }
          elsif ($buf =~/^(\s)*\bhello\b/) {
             if (-e "$DATA_DIR/allowed/$peer") {
                print $d "200: Ok\n";
             }
             else {
                print $d "403: Denied\n";
             }
          }
          elsif ($buf =~/^(\s)*\bget-sshkey\b/) {
             if (-e "$DATA_DIR/allowed/$peer") {
                my $fh = new IO::File "$DATA_DIR/sshkey/cldsa.key.pub", "r";
                if (defined $fh) {
                   while (<$fh>) {
                      print $d $_;
                   }
                }
                close $fh;
             }
             else {
                print $d "403: Denied\n";
             }
          }
          elsif ($buf =~ /^(\s)*\b(exit|quit)\b/) {
             print($d "Goodbye...\n");
             $interactive = 0;
          }
          else {
             print $d "500: Unknown command: $buf";
          }
          close $d if ($interactive == 0);
        }
        exit;
     } continue {
        close $d;
     }
   }
}

## Multicast server loop
sub mcastServer {
   my ($d, $buf);
   my $mdev=`ip route get 225.1.1.12 2>/dev/null | head -1 | sed 's/.* src //' | cut -d ' ' -f1 | tr -d '\\n'`;
   $mdev = "eth0" if (not $mdev);

   # Fork udp multicast server
   my $socket = mcastBind;
   $socket->mcast_add('225.1.1.12', $mdev) || die "Couldn't set group: $!\n";
   if (my $child = fork) { return $child; }

   $SIG{CHLD} = \&REAPER;
   openlog("fwguardian(webauth): UDP mcast ClusterManager (225.1.1.12)", "cons,pid", "daemon");

   $0 = "$0 [Member control]"; 
   print "\n Bind address = $mbaddr:5858 (225.1.1.12 mcast member)\n" if (not $daemon);
   my $peer;
   my $mlocal = 0;
   while (1) {
      next unless $peer = $socket->recv($d,1024);
      my ($cmd, $msg) = split /\s+/, $d, 2;

      # Getting peer address 
      my (undef, $peeraddr) = sockaddr_in($peer);
      $peeraddr=inet_ntoa($peeraddr);

      # Update member status
      my $allowedmb = "$DATA_DIR/allowed/$peeraddr";
      my $memberpath = "$DATA_DIR/members/$peeraddr";
      if ($cmd eq "hello" && -e "$allowedmb") {
         if (-d $memberpath) {
            if (-e "$DATA_DIR/sshkey/$peeraddr.cldsa.key.pub" || $peeraddr eq $mbaddr) {
               if (-e "$allowedmb.forcesync") {
                  force_sync($peeraddr) if ($peeraddr ne $mbaddr);
                  rmtree("$allowedmb.forcesync");
               }

               if (-e "$memberpath/status.dead") {
                  rmtree($memberpath);
               }
               else {
                  if (-e "$memberpath/status.fault1" || -e "$memberpath/status.warn") {
                     if (-e "$memberpath/status.fault1") {
                        system("rm -f $memberpath/status.fault1");
                        system("rm -f $memberpath/status.fault2") if (-e "$memberpath/status.fault2");
                     }
                     system("rm -f $memberpath/status.warn");
                  }

                  # Cluster prio to the master elections
                  my $melection=0;
                  if (not -e "$memberpath/cluster.clid") {
                     system("echo $msg $peeraddr > $memberpath/cluster.clid");
                     system("echo $msg $peeraddr >> $DATA_DIR/cluster.clid");
                     system("$FW_DIR/modules/tools/cluster/realmanager.sh $DATA_DIR $msg $peeraddr");
                  }

                  # Use rsync to multicast members
                  if (not -e "$memberpath/status.ok") {
                     log_info("Peer UP:$peeraddr");
                     $members++;
                     $melection=1 if ($peeraddr ne $mbaddr);
                     system("touch $memberpath/status.ok");
                     system("touch $memberpath/rsync") if (not -e "$memberpath/rsync");
                  }
                  if ($members < 2 && $peeraddr eq $mbaddr && $mlocal < 15 && (not -e "$memberpath/manager")) {
                     $mlocal++;
                     $melection = 1 if ($mlocal >= 15);
                  }

                  if ($melection == 1 && ($members > 1 || $mlocal == 15)) {
                     master_election;
                     system("touch $allowedmb.forcesync") if (-e "/var/tmp/cluster.manager" && $peeraddr ne $mbaddr);

                     # Make and enable glusterfs bricks
                     if ($ena_gluster == 1 && ($members > 1 && (not -e "$DATA_DIR/glusterfs.done"))) {
                        system("echo $peeraddr > $DATA_DIR/glusterfs.replica");
                        make_glustercfg("$peeraddr");
                     }

                     # Restart after master comes back
                     if (-e "/usr/share/fwguardian/modules/restart") {
                        fwRestart if (-e "$memberpath/manager");
                        rmtree("/usr/share/fwguardian/modules/restart");
                     }
                  }
               }
            }
            else {
               if (-e "$memberpath/status.dead") {
                  rmtree("$memberpath/status.dead");
                  rmtree("$memberpath/status.fault2") if (-e "$memberpath/status.fault2");
               }
            }
         }
         else {
            mkpath("$memberpath");
         }
      }
      elsif ($cmd eq "join") {
         if (-d "$DATA_DIR/members/$mbaddr" || $peeraddr eq $mbaddr) {
            if ($msg eq $clkey && not -e "$allowedmb") {
               log_info("Join peer:$peeraddr");

               my $hid = $peeraddr;
               $hid =~ s/.*\.//;
               my $domain = `hostname -d | tr -d '\n'`;
               system("sed -i \'/[\t]cluster$hid.$domain\tcluster$hid #fgnode/ d\' /etc/hosts");
               system("sed -i \'/[ |\t]localhost/ i$peeraddr\tcluster$hid.$domain\tcluster$hid #fgnode\' /etc/hosts");
               system("touch $allowedmb");
            }
            rmtree("$DATA_DIR/sshkey/$peeraddr.cldsa.key.pub") if (-e "$DATA_DIR/sshkey/$peeraddr.cldsa.key.pub");
            chkPeers "chk" if ($members > 1);
         }
      }
      elsif ($cmd eq "hello" && not -e "$allowedmb") {
         if (-e "$DATA_DIR/members/$mbaddr/rsync" && $peeraddr ne $mbaddr) {
            log_info("Hello from unknown peer:$peeraddr");

            system("echo $peeraddr >> $DATA_DIR/req-join");
            rmtree("$DATA_DIR/sshkey/$peeraddr.cldsa.key.pub") if (-e "$DATA_DIR/sshkey/$peeraddr.cldsa.key.pub");
         }
      }
      elsif ($cmd eq "req-join") {
         if (-d "$DATA_DIR/members/$mbaddr" && $msg eq $mbaddr) {
            log_info("Required join from:$peeraddr");

            system("touch $DATA_DIR/re-join");
            system("touch $allowedmb.forcesync") if (-e "/var/tmp/cluster.manager" && $peeraddr ne $mbaddr);
         }
      }
      elsif ($cmd eq "force-restart" && -e "$allowedmb") {
         if (-e "$memberpath/manager") {
            log_info("Force restart from:$peeraddr");
            rmtree("/tmp/glusterfs.lock") if (-e "/tmp/glusterfs.lock");
            fwRestart;
         }
      }

   } continue {
      close $d;
   }
}

## Cluster options
foreach $argnum (0 .. $#ARGV) {
   my $clientCmd = 1;
   my $clustercmd = "$ARGV[0]";
   my $opt = "";
   $opt = "$ARGV[1]" if ($ARGV[1]);

   if($clustercmd eq "--help") {
      help;
   }
   elsif ($clustercmd eq "--daemon") {
      $daemon=1;
      log_info("Starting the ClusterManager daemon!");
      if (my $child = fork) { exit; }
      $clientCmd = 0;
   }
   elsif ($clustercmd eq "--check") {
      read_config_file;
      exit;
   }
   exit if ($clientCmd == 1);
}

read_config_file;
if ($clkey eq "") {
   print color 'bold red';
   print "ERR: Set the member password first (member_pass)!\n";
   print color 'reset';
   exit;
}

record_pid("/var/tmp/cluster.pid");

## Set the main process name
$0 = "$0 [ClusterManager]";
print ">>> FwGuardian - ClusterManager v1.0\n";
print ">>> Author: Humberto Juca (betolj\@gmail.com)\n";

## Restart daemons
$SIG{HUP} = sub {
   if (defined $serverd) {
      kill "TERM", $serverd;
      undef $serverd;
   }
   if (defined $multicast) {
      kill "TERM", $multicast;
      undef $multicast;
   }
   $serverd = tcpServer;
   $multicast = mcastServer if ($mself == 0 && $nomcast == 0);
};
kill "HUP", $$;                 # Start servers

$SIG{TERM} = sub {              # Pass on TERM signals and exit
   kill "TERM", $serverd if (defined $serverd);
   kill "TERM", $multicast if (defined $multicast);
   exit;
};

## Start server sockets if not defined
$serverd = tcpServer if (not defined $serverd);
$multicast = mcastServer if ($mself == 0 && $nomcast == 0 && not defined $multicast);


$SIG{ALRM} = sub {
   my $ALR = 5;

   if ($mself == 0) {

      # - Disable checks when build gluster confs - upto 120s
      # - Disable when starting (waitst) - 15s
      my $dochk = 1;
      if ($waitst < 4 || ($wtchk < 25 && (-e "/usr/share/fwguardian/cluster/glusterfs.done" && not -e "/tmp/glusterfs.lock"))) {
         $dochk = 0;
         $wtchk++;
         $waitst++ if ($waitst < 4);
      }
      $dochk = 0 if (-e "/var/tmp/clustersync.lock");

      use constant DESTINATION => '225.1.1.12:5858';
      my $sock = IO::Socket::Multicast->new(Proto=>'udp',PeerAddr=>DESTINATION);
      #$sock->mcast_loopback(0);

      # Send hello msg or first join (enter the cluster group)
      $wtchk = 0 if ($wtchk > 24);
      my $message = "hello $clid";
      if (-e "$DATA_DIR/allowed/$mbaddr") {
         chkPeers "chk" if ($dochk == 1);
      }
      else {
         rmtree("$DATA_DIR/master.addr") if (-e "$DATA_DIR/master.addr");
         rmtree("$DATA_DIR/cluster.clid") if (-e "$DATA_DIR/cluster.clid");
         $message = "join $clkey";
      }
      $sock->send($message);

      # Send a join request of all members to update list
      if (-e "$DATA_DIR/req-join") {
         foreach my $reqpeer (`cat $DATA_DIR/req-join`) {
            $reqpeer =~ s/\n//;
            $message = "req-join $reqpeer";
            $sock->send($message);
         }
         rmtree("$DATA_DIR/req-join");
      }
      if (-e "$DATA_DIR/re-join") {
         $message = "join $clkey";
         $sock->send($message);
         rmtree("$DATA_DIR/re-join");
      }

      # Glusterfs reconfigure when mself=0
      if ($ena_gluster == 1) {
         if (-e "/var/tmp/glusterfs.reconfigure") {
            if (-e "/var/tmp/cluster.manager") {
               if (-e "$DATA_DIR/glusterfs.replica") {
                  my $replica = `cat $DATA_DIR/glusterfs.replica | tr -d '\n'`;
                  make_glustercfg("$replica");

                  $sock->send("force-restart");
               }
               else {
                  log_info("ERR: No replica peer found (you can use --configure-cluster to reconfigure entire cluster)!");
               }
            }
            else {
               log_info("ERR: Only a manager peer is allowed to reconfigure glusterfs");
            }
            rmtree("/var/tmp/glusterfs.reconfigure");
         }
      }
   }
   else {
      # Self node control or gluster client
      if ($ena_gluster == 1 && -e "/tmp/glusterfs.lock") {
         my $fwr = 0;
         my $GL_DIR = "$FW_DIR/cluster/glusterfs/";

         # Glusterfs reconfigure when mself=1
         if (-e "/var/tmp/glusterfs.reconfigure") {
            if (-e "/var/tmp/cluster.manager") {
               make_glustercfg("$mbaddr");
               $fwr = 1;
               $syncw = 0;
            }
            else {
               log_info("ERR: Only a manager peer is allowed to reconfigure glusterfs");
            }
            rmtree("/var/tmp/glusterfs.reconfigure");
         }

         if ($fwr == 0) {
            $syncw += 5;
            if ($syncw > 25) {
               my $selfsync = 0;
               system("find $GL_DIR/cluster/$gl_group/* -type f -print 2>/dev/null | sort | md5sum \$(xargs) | sed 's/ .*\\/$gl_group\\// /' > /var/tmp/glusterfs.clfw.md5");
               if (not -e "/var/tmp/glusterfs.lcfw.md5") {
                  $selfsync = 1;
               }
               else {
                  $selfsync = `diff -q /var/tmp/glusterfs.clfw.md5 /var/tmp/glusterfs.lcfw.md5 | wc -l | tr -d '\n'`;
               }

               # Sync local directory if cluster directory was changed!
               if ($selfsync > 0 && -e "$GL_DIR/cluster/$gl_group/allow.firewall") {
                  log_info("INFO: Glusterfs changes detect... restarting firewall rules");
                  system("rsync -arlpq --delete --exclude '*~' --exclude '^.' $GL_DIR/cluster/$gl_group $GL_DIR/local/ 2>&1 >>$FW_DIR/logs/cluster.base.err");
                  system("find $GL_DIR/local/$gl_group/* -type f -print 2>/dev/null | sort | md5sum \$(xargs) | sed 's/ .*\\/$gl_group\\// /' > /var/tmp/glusterfs.lcfw.md5");
                  $fwr = 1;
               }
               $syncw = 0;
            }
         }

         # Full firewall restart
         if ($fwr == 1) {
            sleep 1;
            fwRestart;
         }
      }
   }
   alarm $ALR;
};
alarm 3;

chkPeers "flush-rsync" if ($mself == 0);

while (1) {                     # Master loop
   $id = wait;
   if (defined $serverd && $id == $serverd) {
       log_info("Cluster daemon died!");
       print "\tERR: Server daemon died!";
   } 
   elsif (defined $multicast && $id == $multicast) {
       log_info("\tMulticast cluster daemon died");
       print "\tERR: Multicast cluster daemon died!";
   }
}
