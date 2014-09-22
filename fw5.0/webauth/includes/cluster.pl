#!/usr/bin/perl

#Rev.0 - Version 5.0

# Read rsync.mapps (cluster)
sub rsynccfg {
  @srcrsync = ();
  my @auxline = ();
  my $rsgroup;

  ## Sync Peers
  @synchosts = ();
  my $DATA_DIR = "/usr/share/fwguardian/cluster";
  foreach my $peeraddr (`ls $DATA_DIR/members/ 2>/dev/null`) {
     $peeraddr =~ s/\n//;
     if ($peeraddr ne "manager") {
        my $memberpath="$DATA_DIR/members/$peeraddr";
        if (-e "$memberpath/rsync") {
           push(@synchosts, "$peeraddr") if (-d $memberpath && (not -e "$memberpath/manager"));

           if (-e "/var/tmp/cluster.forcesync" && ((-e "/var/tmp/master.fault.$peeraddr" && (not -e "$DATA_DIR/allowed/$peeraddr.forcesync")) || (-e "/var/tmp/cluster.manager" && -e "$memberpath/status.dead"))) {
              system("touch $DATA_DIR/allowed/$peeraddr.forcesync");
              system("rm -f /var/tmp/master.fault.$peeraddr");
           }
        }
     }
  }

  if (-e "$FW_DIR/cluster/rsync.mapps") {
     my $gpcfg = 0;
     open FILE, "<$FW_DIR/cluster/rsync.mapps";
     while (<FILE>) {
        if ($_ !~ /^[\s]*(#|;)/) {
           $_ =~ s/\n//;
           @auxline = ();
           ## Define sync group
           if ($_ =~ /^[\s]*group[\s]/) {
              $gpcfg = 1;
              @auxline = split(/group[\s]+/, $_);
              $rsgroup = "rsync_$auxline[1]";

              push(@srcrsync, $rsgroup) if ($rsgroup !~ /^[\s]*rsync_default([\s]*$)/);
           }
           else {
              ## Sync files by group
              my $auxparam = $_;
              $auxparam =~ s/^\s+//;
              push(@{$rsgp_syncfiles{$rsgroup}}, "$auxparam") if ($gpcfg == 1);
           }
        }
     }
     close(FILE);
  }
}

# "Update firewall files with rsync x ssh"
sub rsyncupdate {
  return if (not -e "/var/tmp/cluster.manager");

  my $syncfile = shift;
  my $synctype = shift;
  my $synccmd = shift;

  my $DATA_DIR = "/usr/share/fwguardian/cluster";
  my $syncport = `cat $DATA_DIR/ssh | tr -d '\n'`;
  $syncport = "22" if (not $syncport);

  my $sshopt = "-o \'ConnectTimeout 3\' -o \'StrictHostKeyChecking no\' -p $syncport -i $DATA_DIR/sshkey/cldsa.key";
  my $synclog = "$FW_DIR/logs/cluster_rsync.log";
  system("touch /var/tmp/cluster.forcesync") if (not -e "/var/tmp/cluster.forcesync");

  foreach my $speer (@synchosts) {
    if (-e "$DATA_DIR/members/$speer/status.ok") {
       ## Update config files
       if ($synccmd eq "change") {
          if ($syncfile eq "modules" && $synctype eq "default") {
             system("rsync -arlp --delete -e \"ssh $sshopt\" /usr/share/fwguardian/modules/ root\@$speer:/usr/share/fwguardian/modules/ 2>\&1 >> $synclog");
          }
          else {
             my $syncdir = `dirname $syncfile | tr -d '\n'`;
             system("rsync -arlp -e \"ssh $sshopt\" $syncfile root\@$speer:$syncdir 2>\&1 | tee -a $synclog");
             system("ssh $sshopt root\@$speer \"$FW_DIR/fwguardian --configure-vpnserver >/dev/null\" | tee -a $synclog") if ($synctype eq "vpnserver");
          }
       }
       else {
          ## Reload fwguardian
          if ($synctype eq "all") {
             system("ssh $sshopt root\@$speer \"$FW_DIR/fwguardian --ignore-cluster >/dev/null\" | tee -a $synclog");
             system("ssh $sshopt root\@$speer \"$FW_DIR/fwguardian --ignore-webserver >/dev/null\" | tee -a $synclog");
             system("ssh $sshopt root\@$speer \"$FW_DIR/fwguardian >/dev/null\" | tee -a $synclog");
          }
          elsif ($synctype eq "profile") {
             system("ssh $sshopt root\@$speer \"$FW_DIR/fwguardian --reload-profile $syncfile >/dev/null\" | tee -a $synclog");
          }
          else {
             system("ssh $sshopt root\@$speer \"$FW_DIR/fwguardian --reload-$synctype >/dev/null\" | tee -a $synclog");
          }

#      elsif ($synctype eq "trust") {
#         system("ssh $sshopt root\@$speer \"$FW_DIR/fwguardian --reload-trust >/dev/null \&\" | tee -a $synclog");
#      }

       }
    }
  }
}

return 1;
