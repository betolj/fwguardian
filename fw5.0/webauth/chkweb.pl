#!/usr/bin/perl
#
# (C) 2014 by Humberto L Jucá <betolj@gmail.com>
#
# This software may be used and distributed according to the terms
# of the GNU General Public License, incorporated herein by reference.
#
# webserver health checker (restart webserver if daemon crash)
#


my %proc = ();
my $pkill = 0;
my $FW_DIR = $ARGV[0];

$FW_DIR =~ s/webauth//;
my $fwg = "$FW_DIR/fwguardian";

# waiting for server forks
system("echo \"$$\" > /usr/share/fwguardian/webauth/control/chkweb.pid");
sleep 3;

while (1) {
   # Check the socket available
   $isalive=1;
   foreach my $bind (`cat $FW_DIR/webauth/webauth.conf | grep "^[\\s]*bind.\\(http\\|https\\)"`) {
      (undef, $pbind) = split /\s+/, $bind;
      $pbind =~ s/.*://;
      $isalive=`lsof -i :$pbind -n | wc -l | tr -d '\n'` if ($isalive > 0);
   }
   if ( $isalive < 1 ) {
      system("echo -e \"\n`date`\" >> /var/log/fwguardian/webcheck.log");
      system("echo -e \'\tWebserver restart\' >> /var/log/fwguardian/webcheck.log");
      system("$fwg --web-start 2>/dev/null >/dev/null");
   }

   # Kill *pseudo-zumbi* process
   foreach my $auxProc (`ps -ef | grep "webauth.mod .* \\[http\\] \\["`) {
      (undef, $pid) = split /\s+/, $auxProc;
      if (not defined $proc{$pid}) {
         $proc{$pid} = $pid;
         $plock{$pid} = 1;
      }
      else {
         foreach my $auxPid (keys %proc) {
            if ($plock{$auxPid} < 1) { 
               $pkill = 0;
               if ($proc{$auxPid} > 1000 && $proc{$auxPid} == $proc{$pid}) {
                  $pkill = $proc{$auxPid};
                  system("kill -9 $pkill 2>/dev/null");

                  system("echo \"\n`date`\" >> /var/log/fwguardian/webcheck.log");
                  system("echo \'\tKill $pkill\n\' >> /var/log/fwguardian/webcheck.log");
               }
               delete $proc{$auxPid};
            }
         }
      }
      $plock{$pid} = 0;
   }
   sleep 30;
}
