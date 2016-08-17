#!/usr/bin/perl
#
# FWGuardian RRD Collector
#
# - Based in
#     http://martybugs.net/linux/rrdtool/traffic.cgi
#     http://code.google.com/p/quicklook/
#

sub BEGIN {
   $ENV{PATH} = "/sbin:/bin:/usr/bin:/usr/sbin:/usr/local/etc";
}

use RRDs;

my $dbrrd = '/usr/share/fwguardian/webauth/rrd/spool';
my $imgrrd = '/usr/share/fwguardian/webauth/rrd/img';


sub CreateCpuGraph {
   # creates CPU graph
   # inputs:  $_[0]: interval (ie, day, week, month, year)
   #          $_[1]: nro processors
   my $tdate = `date | tr -d '\n'`;
   my $RRD = "MAX";
   my $xgrid = "--border";
   my $xgrid_data = "2";
   if ($_[0] eq "day") {
      $RRD = "AVERAGE";
      $xgrid = "-x";
      $xgrid_data = "MINUTE:20:HOUR:2:MINUTE:120:0:%R";
   }
   RRDs::graph "$imgrrd/$_[0].cpu.png",
	"-s -1$_[0]",
        "-e -300",
	"-t CPU usage (%) over $_[1] processor(s)",
	"--lazy",
	"--slope-mode",
	"-h", "120", "-w", "700",
        "-l 0",
        "-u 100.0",
        "$xgrid", "$xgrid_data",
        "-W '$tdate'",
#        "--font", "DEFAULT:7",
	"-a", "PNG",
	"-v Percentage",
	"DEF:cuser=$dbrrd/cpu.rrd:cuser:$RRD",
	"DEF:cnice=$dbrrd/cpu.rrd:cnice:$RRD",
	"DEF:csystem=$dbrrd/cpu.rrd:csystem:$RRD",
	"AREA:cuser#a0df05:User   \\:",
	"GPRINT:cuser:MAX:  Max\\: %6.1lf %%",
	"GPRINT:cuser:AVERAGE:\t Avg\\: %6.1lf %%",
	"GPRINT:cuser:LAST:\t Current\\: %6.1lf %%\\n",
	"STACK:csystem#ffe100:System \\:",
	"GPRINT:csystem:MAX:  Max\\: %6.1lf %%",
	"GPRINT:csystem:AVERAGE:\t Avg\\: %6.1lf %%",
	"GPRINT:csystem:LAST:\t Current\\: %6.1lf %%\\n",
	"STACK:cnice#dc3c14:Nice   \\:",
	"GPRINT:cnice:MAX:  Max\\: %6.1lf %%",
	"GPRINT:cnice:AVERAGE:\t Avg\\: %6.1lf %%",
	"GPRINT:cnice:LAST:\t Current\\: %6.1lf %%\\n";
   if ($ERROR = RRDs::error) { print "$0: unable to generate $_[0] CPU graph: $ERROR\n"; }
}

sub CreateMemGraph {
   # creates Mem graph
   # inputs:  $_[0]: interval (ie, day, week, month, year)
   #          $_[1]: total ram memory
   #          $_[2]: total swap memory
   my $tdate = `date | tr -d '\n'`;
   my $xgrid = "--border";
   my $xgrid_data = "2";
   if ($_[0] eq "day") {
      $xgrid = "-x";
      $xgrid_data = "MINUTE:20:HOUR:2:MINUTE:120:0:%R";
   }
   RRDs::graph "$imgrrd/$_[0].mem.png",
	"-s -1$_[0]",
        "-e -300",
	"-t Memory and swap usage (bytes)",
	"--lazy",
	"--slope-mode",
        "--base", "1024",
	"-h", "120", "-w", "700",
        "-l 0",
        "$xgrid", "$xgrid_data",
        "-W '$tdate'",
#        "--font", "DEFAULT:7",
	"-a", "PNG",
	"-v Bytes",
	"DEF:mused=$dbrrd/mem.rrd:mused:AVERAGE",
	"DEF:mbuffer=$dbrrd/mem.rrd:mbuffer:AVERAGE",
	"DEF:mcache=$dbrrd/mem.rrd:mcache:AVERAGE",
	"DEF:mswap=$dbrrd/mem.rrd:mswap:AVERAGE",
        "CDEF:mused_mb=mused,1024,1024,*,/",
        "CDEF:mbuffer_mb=mbuffer,1024,1024,*,/",
        "CDEF:mcache_mb=mcache,1024,1024,*,/",
        "CDEF:mswap_mb=mswap,1024,1024,*,/",
	"AREA:mused#a0df05:Memory  \\:",
	"GPRINT:mused_mb:MAX:  Max\\: %6.0lf MB",
	"GPRINT:mused_mb:AVERAGE:\t Avg\\: %6.0lf MB",
	"GPRINT:mused_mb:LAST:\t Current\\: %6.0lf MB\\n",
	"STACK:mcache#ffe100:Cached  \\:",
	"GPRINT:mcache_mb:MAX:  Max\\: %6.0lf MB",
	"GPRINT:mcache_mb:AVERAGE:\t Avg\\: %6.0lf MB",
	"GPRINT:mcache_mb:LAST:\t Current\\: %6.0lf MB\\n",
	"STACK:mbuffer#dc3c14:Buffers \\:",
	"GPRINT:mbuffer_mb:MAX:  Max\\: %6.0lf MB",
	"GPRINT:mbuffer_mb:AVERAGE:\t Avg\\: %6.0lf MB",
	"GPRINT:mbuffer_mb:LAST:\t Current\\: %6.0lf MB",
        "COMMENT:      Memory  =  $_[1] MB  \\n",
        "LINE1:mswap#808080:Swap    \\:",
        "GPRINT:mswap_mb:MAX:  Max\\: %6.0lf MB",
        "GPRINT:mswap_mb:AVERAGE:\t Avg\\: %6.0lf MB",
        "GPRINT:mswap_mb:LAST:\t Current\\: %6.0lf MB",
        "COMMENT:      Swap    =  $_[2] MB  \\n";
   if ($ERROR = RRDs::error) { print "$0: unable to generate $_[0] Memory graph: $ERROR\n"; }
}

sub CreateConnGraph {
   # creates conntrack graph
   # inputs:  $_[0]: interval (ie, day, week, month, year)
   my $tdate = `date | tr -d '\n'`;
   my $RRD = "MAX";
   my $xgrid = "--border";
   my $xgrid_data = "2";
   if ($_[0] eq "day") {
      $RRD = "AVERAGE";
      $xgrid = "-x";
      $xgrid_data = "MINUTE:20:HOUR:2:MINUTE:120:0:%R";
   }
   RRDs::graph "$imgrrd/$_[0].conntrack.png",
	"-s -1$_[0]",
        "-e -300",
	"-t Network connections (by protocol)",
	"--lazy",
	"--slope-mode",
        "--base", "1000",
	"-h", "120", "-w", "700",
        "-l 0",
        "$xgrid", "$xgrid_data",
        "-W '$tdate'",
#        "--font", "DEFAULT:7",
	"-a", "PNG",
	"-v Connections",
	"DEF:ttrack=$dbrrd/conntrack.rrd:ttrack:$RRD",
	"DEF:utrack=$dbrrd/conntrack.rrd:utrack:$RRD",
	"DEF:otrack=$dbrrd/conntrack.rrd:otrack:$RRD",
	"AREA:ttrack#a0df05:TCP     \\:",
	"GPRINT:ttrack:MAX:  Max\\: %6.0lf",
	"GPRINT:ttrack:AVERAGE:\t Avg\\: %6.0lf",
	"GPRINT:ttrack:LAST:\t Current\\: %6.0lf   Connections\\n",
	"STACK:utrack#ffe100:UDP     \\:",
	"GPRINT:utrack:MAX:  Max\\: %6.0lf",
	"GPRINT:utrack:AVERAGE:\t Avg\\: %6.0lf",
	"GPRINT:utrack:LAST:\t Current\\: %6.0lf   Connections\\n",
	"STACK:otrack#dc3c14:Other   \\:",
	"GPRINT:otrack:MAX:  Max\\: %6.0lf",
	"GPRINT:otrack:AVERAGE:\t Avg\\: %6.0lf",
	"GPRINT:otrack:LAST:\t Current\\: %6.0lf   Connections\\n";
   if ($ERROR = RRDs::error) { print "$0: unable to generate $_[0] connection graph: $ERROR\n"; }
}

sub CreateIntGraph {
   # creates graph
   # inputs: $_[0]: interface name (ie, eth0/eth1/eth2/ppp0)
   #	     $_[1]: interval (ie, day, week, month, year)
   #	     $_[2]: interface description
   my $tin = "in", $tout = "out";
   my $rxtin = "rx_tin", $txtout = "tx_tout";
   my $tdesc = "Bandwidth", $tdesc2 = "Bytes";
   my $mask = "%8.2lf KBps";
   my $tdate = `date | tr -d '\n'`;
   my $xgrid = "--border";
   my $xgrid_data = "2";
   $tbase = "1024";
   if ($_[1] eq "day") {
      $xgrid = "-x";
      $xgrid_data = "MINUTE:20:HOUR:2:MINUTE:120:0:%R";
   }
   for (my $i=0; $i<2; $i++) {
        if ($i > 0) {
           $tin="inpkt";
           $tout="outpkt";
           $tdesc = "Packets";
           $tdesc2 = $tdesc;
           $mask = "%7.0lf";
           $tbase = "1000";
           $rxtin = $tin;
           $txtout = $tout;
        }
	RRDs::graph "$imgrrd/$_[0]-$_[1].$tdesc.png",
		"-s -1$_[1]",
                "-e -180",
		"-t $tdesc traffic on $_[0] - $_[2]",
		"--lazy",
		"--slope-mode",
                "--base", "$tbase",
		"-h", "160", "-w", "700",
		"-l 0",
                "-u 0.5",
                "$xgrid", "$xgrid_data",
                "-W '$tdate'",
#                "--font", "DEFAULT:7",
		"-a", "PNG",
		"-v $tdesc2/sec",
		"DEF:$tin=$dbrrd/$_[0].rrd:$tin:AVERAGE",
		"DEF:$tout=$dbrrd/$_[0].rrd:$tout:AVERAGE",
		"CDEF:out_neg=$tout,-1,*",
                "CDEF:rx_tin=$tin,$tbase,/",
                "CDEF:tx_tout=$tout,$tbase,/",
		"AREA:$tin#32CD32:Incoming",
		"LINE1:$tin#336600",
		"GPRINT:$rxtin:MAX:  Max\\: $mask",
		"GPRINT:$rxtin:AVERAGE:\t Avg\\: $mask",
		"GPRINT:$rxtin:LAST:\t Current\\: $mask  $tdesc2/sec\\n",
		"AREA:out_neg#4169E1:Outgoing",
		"LINE1:out_neg#0033CC",
		"GPRINT:$txtout:MAX:  Max\\: $mask",
		"GPRINT:$txtout:AVERAGE:\t Avg\\: $mask",
		"GPRINT:$txtout:LAST:\t Current\\: $mask  $tdesc2/sec\\n",
		"HRULE:0#000000";
	if ($ERROR = RRDs::error) { print "$0: unable to generate $_[0] $_[1] traffic graph: $ERROR\n"; }
   }
}

sub ProcessCpu {
   # process cpu
   my $nproc = 0;
   my $cuser = 0, $cnice = 0, $csystem = 0;

   foreach my $auxcpu (`grep "^cpu" /proc/stat 2>/dev/null`) {
      chomp($auxcpu);
      $nproc++;
      if ( $nproc == 1 ) {
         my @auxcpu2 = split /\s+/, $auxcpu, 5;
         $cuser = $auxcpu2[1];
         $cnice = $auxcpu2[2];
         $csystem = $auxcpu2[3];
      }
   }
   $nproc--;

   $cuser = int($cuser);
   $cnice = int($cnice);
   $csystem = int($csystem);
   print "CPU    - User: $cuser, Nice: $cnice, System: $csystem\n";

   # If rrdtool database doesn't exist, create it
   if (not -e "$dbrrd/cpu.rrd") {
      print "creating rrd database for cpu stats...\n";
      RRDs::create "$dbrrd/cpu.rrd",
              "--step", 300,
              "DS:cuser:DERIVE:600:0:U",
              "DS:cnice:DERIVE:600:0:U",
              "DS:csystem:DERIVE:600:0:U",
	      "RRA:AVERAGE:0.5:1:288",
	      "RRA:MAX:0.5:3:672",
	      "RRA:MAX:0.5:12:744",
	      "RRA:MAX:0.5:144:730";
   }

   # Insert values into rrd
   RRDs::update "$dbrrd/cpu.rrd",
              "-t", "cuser:cnice:csystem",
              "N:$cuser:$cnice:$csystem";

   # Create CPU graphs
   &CreateCpuGraph("day", $nproc);
   &CreateCpuGraph("week", $nproc);
   &CreateCpuGraph("month", $nproc); 
   &CreateCpuGraph("year", $nproc);
}

sub ProcessMem {
   # process memory
   my %fwmemory = ();
   foreach my $auxmem (`grep "^\\(MemTotal\\|MemFree\\|Buffers\\|Cached\\|SwapTotal\\|SwapFree\\)" /proc/meminfo`) {
      chomp($auxmem);
      $auxmem =~ s/://;
      my ($auxmem, $mvalue, undef) = split /\s+/, $auxmem, 3;
      $fwmemory{$auxmem} = int($mvalue);
   }
   my $smem = int($fwmemory{'MemTotal'} / 1024);
   my $sswap = int($fwmemory{'SwapTotal'} / 1024);
   $fwmemory{'MemTotal'} -= ($fwmemory{'MemFree'} + $fwmemory{'Buffers'} + $fwmemory{'Cached'});
   $fwmemory{'SwapTotal'} -= $fwmemory{'SwapFree'};

   $fwmemory{'MemTotal'} = int($fwmemory{'MemTotal'} * 1024);
   $fwmemory{'Buffers'} = int($fwmemory{'Buffers'} * 1024);
   $fwmemory{'Cached'} = int($fwmemory{'Cached'} * 1024);
   $fwmemory{'SwapTotal'} = int($fwmemory{'SwapTotal'} * 1024);
   print "Memory - Used: $fwmemory{'MemTotal'}, Buffered: $fwmemory{'Buffers'}, Cached: $fwmemory{'Cached'}, Swaped: $fwmemory{'SwapTotal'}\n";

   # If rrdtool database doesn't exist, create it
   if (not -e "$dbrrd/mem.rrd") {
      print "creating rrd database for mem stats...\n";
      RRDs::create "$dbrrd/mem.rrd",
              "--step", 300,
              "DS:mused:GAUGE:600:0:U",
              "DS:mbuffer:GAUGE:600:0:U",
              "DS:mcache:GAUGE:600:0:U",
              "DS:mswap:GAUGE:600:0:U",
	      "RRA:AVERAGE:0.5:1:288",
	      "RRA:AVERAGE:0.5:3:672",
	      "RRA:AVERAGE:0.5:12:744",
	      "RRA:AVERAGE:0.5:144:730";
   }

   # Insert values into rrd
   RRDs::update "$dbrrd/mem.rrd",
              "-t", "mused:mbuffer:mcache:mswap",
              "N:$fwmemory{'MemTotal'}:$fwmemory{'Buffers'}:$fwmemory{'Cached'}:$fwmemory{'SwapTotal'}";

   # Create Memory graphs
   &CreateMemGraph("day", $smem, $sswap);
   &CreateMemGraph("week", $smem, $sswap);
   &CreateMemGraph("month", $smem, $sswap); 
   &CreateMemGraph("year", $smem, $sswap);
}

sub ProcessConntrack {
   # process conntrack table
   my $ctrack = 0, $ttrack = 0, $utrack = 0, $otrack = 0;

   my $conntrackc = `which conntrack | tr -d '\\n'`;
   if (-e "$conntrackc") {
      # Faster search (with conntrack tool).
      $ttrack = `$conntrackc -L conntrack -p tcp 2>/dev/null | wc -l`;
      $utrack = `$conntrackc -L conntrack -p udp 2>/dev/null | wc -l`;
   }
   else {
      # I recommend installing the conntrack tool.
      if (-e "/proc/net/ip_conntrack") {
         $ttrack = `cat /proc/net/ip_conntrack | grep "^tcp" | wc -l`;
         $utrack = `cat /proc/net/ip_conntrack | grep "^udp" | wc -l`;
      }
   }
   $ctrack = `cat /proc/sys/net/netfilter/nf_conntrack_count`;
   
   # Remove eol chars
   chomp($ctrack);
   chomp($ttrack);
   chomp($utrack);
   $otrack = $ctrack;
   $otrack -= $ttrack;
   $otrack -= $utrack;

   print "TCP connections (conntrack): $ttrack\n";
   print "UDP connections (conntrack): $utrack\n";
   print "Other connections (conntrack): $otrack\n";

   # If rrdtool database doesn't exist, create it
   if (not -e "$dbrrd/conntrack.rrd") {
      print "creating rrd database for conntrack table...\n";
      RRDs::create "$dbrrd/conntrack.rrd",
              "--step", 300,
              "DS:ttrack:GAUGE:600:0:U",
              "DS:utrack:GAUGE:600:0:U",
              "DS:otrack:GAUGE:600:0:U",
	      "RRA:AVERAGE:0.5:1:576",
	      "RRA:MAX:0.5:6:672",
	      "RRA:MAX:0.5:24:744",
	      "RRA:MAX:0.5:144:1460";
   }

   # Insert values into rrd
   RRDs::update "$dbrrd/conntrack.rrd",
              "-t", "ttrack:utrack:otrack",
              "N:$ttrack:$utrack:$otrack";

   # Create traffic graphs
   &CreateConnGraph("day");
   &CreateConnGraph("week");
   &CreateConnGraph("month"); 
   &CreateConnGraph("year");
}

sub ProcessInterface {
   # process interface
   # inputs: $_[0]: interface name (ie, eth0/eth1/eth2/ppp0)
   #	  $_[1]: interface description 

   # get network interface info
   my $in = 0, $out = 0;
   my $inpkt = 0, $outpkt = 0;
   if (-e "/sys/class/net/$_[0]/statistics/rx_bytes") {
      $in = `cat /sys/class/net/$_[0]/statistics/rx_bytes`;
      $out = `cat /sys/class/net/$_[0]/statistics/tx_bytes`;
      $inpkt = `cat /sys/class/net/$_[0]/statistics/rx_packets`;
      $outpkt = `cat /sys/class/net/$_[0]/statistics/tx_packets`;
   }
   else {
      $in = `ifconfig $_[0] |grep bytes|cut -d":" -f2 | cut -d" " -f1`;
      $out = `ifconfig $_[0] |grep bytes|cut -d":" -f3 | cut -d" " -f1`;
      $inpkt = `cat /proc/net/dev | grep $_[0] | awk '{ print \$3; }'`;
      $outpkt = `cat /proc/net/dev | grep $_[0] | awk '{ print \$11; }'`;
   }

   # Remove eol chars
   chomp($in);
   chomp($inpkt);
   chomp($out);
   chomp($outpkt);

   print "$_[0] bandwidth traffic in, out: $in, $out\n";
   print "$_[0] packets traffic in, out: $inpkt, $outpkt\n";

   # If rrdtool database doesn't exist, create it
   if (not -e "$dbrrd/$_[0].rrd") {
   	print "creating rrd database for $_[0] interface...\n";
   	RRDs::create "$dbrrd/$_[0].rrd",
   		"--step", 180,
   		"DS:in:DERIVE:360:0:U",
   		"DS:out:DERIVE:360:0:U",
   		"DS:inpkt:DERIVE:360:0:U",
   		"DS:outpkt:DERIVE:360:0:U",
   		"DS:ctrack:DERIVE:360:0:U",
   		"RRA:AVERAGE:0.5:1:480",      # 24hs = 86400 / 360
   		"RRA:AVERAGE:0.5:5:672",      # 900 / 180
   		"RRA:AVERAGE:0.5:20:744",     # 3600 / 180
   		"RRA:AVERAGE:0.5:240:730";    # 43200 / 180
   }

   # Insert values into rrd
   RRDs::update "$dbrrd/$_[0].rrd",
   	"-t", "in:out:inpkt:outpkt",
   	"N:$in:$out:$inpkt:$outpkt";

   # Create traffic graphs
   &CreateIntGraph($_[0], "day", $_[1]);
   &CreateIntGraph($_[0], "week", $_[1]);
   &CreateIntGraph($_[0], "month", $_[1]); 
   &CreateIntGraph($_[0], "year", $_[1]);
}

# Selecting the data type
foreach $argnum (0 .. $#ARGV) {
   my $rrdcmd = "$ARGV[0]";
   my $opt = "";
   $opt = "$ARGV[1]" if ($ARGV[1]);

   if ($rrdcmd eq "--system") {
      # Process CPU
      &ProcessCpu;

      # Process Memory
      &ProcessMem;

      # Process Conntrack counter
      &ProcessConntrack;
   }
   elsif ($rrdcmd eq "--interfaces") {
      # Process data for each interface (add/delete as required)
      # Example: &ProcessInterface("eth0", "local network");
      my %intdesc = ();
      if (-e "/var/tmp/interfaces") {
         open FILE, "</var/tmp/interfaces";
         while (my $iface = <FILE>) {
            if ($iface !~ /^\s*(#|$)/) {
               chomp($iface);

               my ($ifname, undef, undef, undef, undef, undef, undef, undef, undef, undef, undef, $ifdesc) = split /\s+/, $iface, 12;
               $intdesc{"$ifname"} = "$ifdesc";
            }
         }
         close (FILE);
      }
      foreach my $iface (`ls /sys/class/net | grep -v lo`) {
          chomp($iface);

          $intdesc{"$iface"} = $iface if (not $intdesc{"$iface"});
          &ProcessInterface("$iface", $intdesc{"$iface"});
      }
   }
   else {
      exit;
   }
}
