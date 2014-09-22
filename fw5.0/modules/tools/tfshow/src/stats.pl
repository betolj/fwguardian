#!/usr/bin/perl -w

# Requied Libs
#
# - You can use cpan to install all of them
#
# Require perl-NetPacket (libnet-netpacket-perl)
# Require perl-Net-Pcap (libnet-pcap-perl)
# Require (libproc-simple-perl)

use Proc::Simple;
use Time::HiRes;
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;

my $countl = 0;
my $fwinfo = "";
my @fwsrc = ();
my @fwdst = ();
my %src_len = ();
my %dst_len = ();
my %con_len = ();
my %con_kbps = ();
my %con_len_now = ();
my %con_len_old = ();

sub elapsed_kbps {
   my $con = shift;
   my $con_value = shift;

   $elapsed_con{$con} = Time::HiRes::tv_interval( $stime_con{$con} );

   if ($elapsed_con{$con} >= 1) {

      #### calc connection length increase
      $con_len_now{$con} = $con_value;
      $con_len_now{$con} = $con_value - $con_len_old{$con} if ($con_len_old{$con});
      $con_len_old{$con} = $con_len{$con};

      ### null traffic timeout (15s) 
      $con_ctmap_timeout{$con} = 0 if (!$con_ctmap_timeout{$con});

      ### connection speed
      if ($con_len_now{$con} > 0) { 
         $con_kbps{$con} = (($con_len_now{$con} * 8) / 1024);
         $con_ctmap_timeout{$con} = 0;
      }
      else {
         $con_kbps{$con}=0;
         $con_ctmap_timeout{$con}++;
      }
      $stime_con{$con} = [ Time::HiRes::gettimeofday( ) ];

      #### Med calcs
      #if (!$con_ct_kbps{$con}) {
      #   $con_ct_kbps{$con} = 0;
      #   $con_sum_kbps{$con} = 0;
      #}
      #$con_ct_kbps{$con}++;
      #$con_sum_kbps{$con} += $con_kbps{$con};
      #if ($con_ct_kbps{$con} > 1) {
      #   $con_med_kbps{$con} = $con_sum_kbps{$con} / $con_ct_kbps{$con};
      #   $con_kbps{$con} = $con_med_kbps{$con};
      #   $con_ct_kbps{$con} = 0;
      #   $con_sum_kbps{$con} = 0;
      #}

      ### Delete any connection mapping after timeout
      if ($con_ctmap_timeout{$con} > 15) {
         delete $con_ctmap_timeout{$con};
         delete $con_len{$con};
         delete $percon{$con};
         delete $con_kbps{$con};
         delete $stime_con{$con};
         delete $elapsed_con{$con};
      }
   }
}

sub show_st {

   system("clear");

   ### Sorting by lenght
   @stsrc = reverse sort { $src_len{$a} <=> $src_len{$b} } keys %src_len;
   @stdst = reverse sort { $dst_len{$a} <=> $dst_len{$b} } keys %dst_len;
   @stcon = reverse sort { $con_kbps{$a} <=> $con_kbps{$b} } keys %con_kbps;

   if ($ARGV[0] && ($ARGV[0] eq "--show")) {
     if (($ARGV[1] && ($ARGV[1] eq "source")) || !$ARGV[1]) {
       print "\nBy source:\n";
       $contst = 0;
       foreach my $src ( @stsrc ) {
          $contst++;
          $blaux = "";
          for ( my $i = length($src); $i < 15; $i++ ) { $blaux  = "$blaux "; };

          print "  $src $blaux\t\t $src_len{$src}... $persrc{$src}\%\n";
          last if ($contst > 6);
       }
     }

     if (($ARGV[1] && ($ARGV[1] eq "destination")) || !$ARGV[1]) {
       print "\nBy destination:\n";
       $contst = 0;
       foreach my $dst (@stdst ) {
         $contst++;
         $blaux = "";
         for ( my $i = length($dst); $i < 15; $i++ ) { $blaux = "$blaux "; };
         print "  $dst $blaux\t\t $dst_len{$dst}... $perdst{$dst}\%\n";
         last if ($contst > 6);
       }
     }

     if (($ARGV[1] && ($ARGV[1] eq "connection")) || !$ARGV[1]) {
       print "\nBy connection:\n";
       $contst = 0;
       $tot_kbps = 0;
       foreach my $con (@stcon) {
         $contst++;
         $blaux = "";

         for ( my $i = length($con); $i < 40; $i++ ) { $blaux = "$blaux "; };
         #print "  $con $blaux\t\t $con_len{$con} bytes... $con_kbps{$con}Kbps -  $percon{$con}\%\n";
         printf " $con $blaux\t\t %.2f Kbps ... $con_len{$con} bytes - $percon{$con}\n", $con_kbps{$con};
         $tot_kbps += $con_kbps{$con};
         last if ($contst > 16);
       }
       $tot_kbps = sprintf("%.2f", $tot_kbps);
       print "\nTOTAL: $tot_kbps\n";
    }
  }
}

sub process_pkt {
   my ($user_data, $header, $packet) = @_;

   my $ether_data = NetPacket::Ethernet::strip($packet);
   my $srcpt=""; $dstpt="";

   ### Pcap decode
   if ($ether_data) {
      my $tcp = 0;
      my $udp = 0;
      my $length = 0;
      my $flow = "";
      my $ip = NetPacket::IP->decode($ether_data);

      ### IP protocol and length
      $length = 4;
      $length = $ip->{'len'} if ($ip->{'hlen'} > 3);

      if ($ip->{'proto'} eq "6") {
         $tcp = NetPacket::TCP->decode($ip->{'data'});
         $srcpt = $tcp->{'src_port'};
         $dstpt = $tcp->{'dest_port'};
      }
      if ($ip->{'proto'} eq "17") {
         $udp = NetPacket::UDP->decode($ip->{'data'});
         $srcpt = $udp->{'src_port'};
         $dstpt = $udp->{'dest_port'};
      }

      if ($ip->{'proto'} eq "6" || $ip->{'proto'} eq "17") {
        if ($ip->{'src_ip'}) {
           $srcip = $ip->{'src_ip'};
           $srcaddr = "$srcip:$srcpt";
           $src_len{$srcip} += $length;

           $spaddr = "";
           for (my $auxip = 0; $auxip < 20 - length($srcaddr); $auxip++) {
              $spaddr = "$spaddr ";
           }
           $srcaddr = "$srcaddr $spaddr"
        }
        if ($ip->{'dest_ip'}) {
           $dstip = $ip->{'dest_ip'};
           $dstaddr = "$dstip:$dstpt";
           $dst_len{$dstip} += $length;

           $spaddr = "";
           for (my $auxip = 0; $auxip < 20 - length($dstaddr); $auxip++) {
              $spaddr = "$spaddr ";
           }
           $dstaddr = "$dstaddr $spaddr";
        }

        if ($srcaddr && $dstaddr) {        
          $flow = "$srcaddr  ->  $dstaddr\t";

          ### Length by session
          $con_len{$flow} += $length;
          $stime_con{$flow} = [ Time::HiRes::gettimeofday( ) ] if (!$stime_con{$flow});
          elapsed_kbps($flow, $con_len{$flow});
        }

        ### Source utilization
        if ($src_len{$srcip} >= $maxsrc) {
           $maxsrc = $src_len{$srcip};
           $persrc{$srcip} = "100";
        }
        else {
           while ( my ($src, $src_value) = each(%src_len) ) {
              if ($maxsrc > 0) {
                 if ($srcip eq $src) {
                    $percalc = int(($src_len{$srcip} * 100) / $maxsrc);
                    $persrc{$srcip} = "$percalc";
                 }
                 else {
                    $percalc = int(($src_value * 100) / $maxsrc);
                    $persrc{$src} = "$percalc";
                 }
              }
           }
        }

        ### Destination utilization
        if ($dst_len{$dstip} >= $maxdst) {
           $maxdst = $dst_len{$dstip};
           $perdst{$dstip} = "100"
        }
        else {
           while ( my ($dst, $dst_value) = each(%dst_len) ) {
              if ($maxdst > 0) {
                 if ($dstip eq $dst) {
                    $percalc = int(($dst_len{$dstip} * 100) / $maxdst);
                    $perdst{$dstip} = "$percalc";
                 }
                 else {
                    $percalc = int(($dst_value * 100) / $maxdst);
                    $perdst{$dst} = "$percalc";
                 }
              }
           }
        }

        ### Connection utilization
        if ($con_len{$flow} >= $maxcon) {
           $maxcon = $con_len{$flow};
           $percon{$flow} = "100";
        }
     }

     while ( my ($con, $con_value) = each(%con_len) ) {
        if  ($ip->{'proto'} eq "6" || $ip->{'proto'} eq "17") {
          if (($maxcon > 0) && ($con_len{$flow} < $maxcon)) {
             if ($con eq $flow ) {
                $percalc = int(($con_len{$flow} * 100) / $maxcon);
                $percon{$flow} = "$percalc";
             }
             else {
                $percalc = int(($con_value * 100) / $maxcon);
                $percon{$con} = "$percalc";
             }
          }
        }
        elapsed_kbps($con, $con_value);
     }
   }


   ### Diplay stats
   $stime = [ Time::HiRes::gettimeofday( ) ] if (!$stime);
   $elapsed = Time::HiRes::tv_interval( $stime );
   if ($elapsed >= 0.50) {
      show_st;
      $stime = [ Time::HiRes::gettimeofday( ) ];
   }
}

sub create_pcap {
    my $promisc = 1;
    my $snaplen = 1500;
    my $to_ms = 1;
    $dev = "";

    my($err,$net,$mask,$filter_t);

    ### Pcap filter
    my $filter = "(tcp or udp or (arp and host 0.0.0.0))";

    $dev = Net::Pcap::lookupdev(\$err);
    $dev or die "Net::Pcap::lookupdev failed.  Error was $err";
    if ( (Net::Pcap::lookupnet($dev, \$net, \$mask, \$err) ) == -1 ) {
        die "Net::Pcap::lookupnet failed.  Error was $err";
    }

    my $tpcap = Net::Pcap::open_live($dev, $snaplen, $promisc, $to_ms, \$err);
    $tpcap || die "Can't create packet descriptor.  Error was $err";

    if ( Net::Pcap::compile($tpcap, \$filter_t, $filter, 1, $net) == -1 ) {
        die "Unable to compile filter string '$filter'\n";
    }

    Net::Pcap::setfilter($tpcap, $filter_t);

    $tpcap;
}


$SIG{INT} = sub {
  $myproc->kill();
  exit;
};

### Arp tests for Loop Pcap updates
sub arptest {
  while (1) {
      $stime = [ Time::HiRes::gettimeofday( ) ] if (!$stime);
      $elapsed = Time::HiRes::tv_interval( $stime );
      if ($elapsed >= 2) {
         system("arping 0.0.0.0 -I $dev -c1 -w1 1>/dev/null 2>/dev/null \&");
         $stime = [ Time::HiRes::gettimeofday( ) ];
      }
  }
}


while ( 1 ) {
  my ($tpcap) = create_pcap();

  if (! defined $myproc || !$myproc->poll()) {
    $myproc = Proc::Simple->new();
    $myproc->start(\&arptest);
  }
  Net::Pcap::loop($tpcap, -1, \&process_pkt, 0);

  Net::Pcap::close($tpcap);
  exit 1;
}

