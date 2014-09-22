#!/usr/bin/perl

#Rev.1 - Version 5.0

sub json_out {
   use POSIX;
   my $total = shift;
   my $json = shift;
   my $page = shift;
   my $data = shift;
   my $totdiv = 30;
   if ($data eq "rows2") {
      $data = "rows";
      $totdiv = 15;
   }
   if ($json && $total > 0) {
      $json = qq{"$data":[$json\n]};
      if ($data eq "rows") {
         $total--;
         $totpag = $total / $totdiv;
         $totpag = ceil($totpag);
         $json = qq{{"records":"$total","page":"$page","total":"$totpag",$json}};
      }
      else {
         $json = qq{{"page":"$page","total":"$total",$json}};
      }
   }
   else {
     if ($data eq "rows") {
        $json = qq{{"records":"0","page":"1","total":"0"}};
     }
     else {
        $json = qq{{"page":"1","total":"0"}};
     }
   }
  return $json;
}

sub findId {
  my ($arr, $search_for) = @_;
  my %items = map {$_ => 1} @$arr;
  return (exists($items{$search_for}))?1:0;
}

sub getPageOpt {
  my $url = shift;
  my $page = 1;
  my $sortd = "asc";
  my $sortid = "id";
  my @dvalue = ();
  foreach my $line (split /&/, $url) {
     @dvalue = split /=/, $line;
     if ($dvalue[0] eq "page") {
        $page = $dvalue[1];
     }
     elsif ($dvalue[0] eq "sidx") {
        $sortid = $dvalue[1];
     }
     elsif ($dvalue[0] eq "sord") {
        $sortd = $dvalue[1];
     }
  }
  return "$page $sortid $sortd";
}

sub myutf8_encode {
  my $data = shift;
  my $utf8 = $data;

  utf8::decode($utf8);
  utf8::encode($utf8);
  $data = $utf8 if (utf8::valid($utf8));
  return "$data";
}

sub getCondDesc {
  my $line = shift;
  my $afCond = "none", $afDesc = "";
  if ($line =~ /[\s]desc=/) {
     (undef, $afDesc) = split /[\s]desc=/, $line;
     (undef, $afDesc) = split /[\"|\']/, $afDesc;
     $afDesc =~ s/[\"'\\]//g;
  }
  if ($line =~ /[\s]chk=/) {
     (undef, $afCond) = split /[\s]chk=/, $line;
     ($afCond, undef) = split /[\s]+/, $afCond;
     $afCond = "none" if (not $afCond || $afCond eq "");
  }
  $afDesc = myutf8_encode($afDesc);
  return "$afCond $afDesc";
}

sub getports {
   my $line = shift;
   my $proto = "any", $sproto = "";
   my $sport = "", $dport = "";
   if ($line =~ /[\s][d]*port=/) {
      (undef, $proto) = split /[\s][d]*port=/, $line;
      ($proto, undef) = split/[\s]+/, $proto;
      if (not $proto) { $proto = "any"; }
      else {
         ($proto, $dport) = split /\//, $proto;
         ($dport) = split /\s/, $dport;
      }
   }
   if ($line =~ /[\s]sport=/) {
      my (undef, $sproto) = split /[\s]sport=/, $line;
      ($sproto, undef) = split/[\s]+/, $sproto;
      if (not $sproto) { $sproto = "any"; }
      else {
         ($sproto, $sport) = split /\//, $sproto;
         ($sport) = split /\s/, $sport;
      }
      $proto = $sproto if ($proto eq "any");
   }
   $proto="$proto/$sport/$dport";
   return $proto;
}

sub get_sqlUserpl {
    use CGI qw(:standard);
    use HTTP::Response;

    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Getting SQL users
    my $sth;
    my $dbh;
    my $start = 1;
    my $sql_ok = 1;
    my $SQL = "";

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my $stid = 0;
    my $records = 0;
    my @unsortId = ();
    my %unsortData = ();

    # Json output
    my $json = undef;

    CGI::Session->name("FWGSESS");
    my $session = CGI::Session->load(undef, $read_cookie, {Directory=>'/tmp/sessions'});
    my $sqlQuery = $session->param('sqlQuery');
    $session->flush;

    if ($sqlQuery) {
      if ($sqlQuery ne "*") {
         if ($sqlQuery !~ /%/) { $sqlQuery = "= '$sqlQuery'"; }
         else { $sqlQuery = "like '$sqlQuery'"; }
         $sqlQuery = "where fg_username $sqlQuery or fg_fullname $sqlQuery or fg_email $sqlQuery";
      }
      else {
         $sqlQuery = "";
      }

      $dbh = sqladm("connect") or $sql_ok=0;
      if ($sql_ok == 1 && $dbh != -1) {
         $records = $dbh->selectrow_array("select COUNT(fg_username) as fgTotal from fgaccount $sqlQuery") || 0;
         if ($records > 0) {
            # Page limits
            $start = ($page * 15) - 15;
            $SQL = "select * from fgaccount $sqlQuery order by fg_fullname LIMIT $start, 15";
            $start++;

            $sth = $dbh->prepare("$SQL") or $sql_ok=0;
            $sth->execute or $sql_ok=0;
         }
         else {
            $sql_ok=0;
         }

         if ($sql_ok == 1) {
            $total = $start;
            while(my @COLUMNS = $sth->fetchrow_array()) {
               my %auxjson = ();
               $auxjson{'fg_username'}="", $auxjson{'fg_fullname'}="", $acLock="<font color=\'Red\'>lock</font>";
               $auxjson{'fg_haddr'}="", $auxjson{'fg_email'}="", $auxjson{'fg_NID'}="", $auxjson{'fg_phone'}="", $auxjson{'fg_phone2'}="";
               $auxjson{'fg_ctlogin'}="", $auxjson{'fg_ftlogin'}="", $auxjson{'fg_ltlogin'}="";

               for ($i=0; $i<=11; $i++) {
		 if ($sth->{NAME}->[$i] eq "fg_lock") {
		    $acLock = "unlock" if ($COLUMNS[$i] eq "0");
		 }
                 else {
                    #$COLUMNS[$i] =~ s/[^[:print:]]/_/g;
                    $COLUMNS[$i] = myutf8_encode($COLUMNS[$i]) if ($sth->{NAME}->[$i] =~ /^fg_(fullname|haddr)$/);
                    $auxjson{$sth->{NAME}->[$i]} = $COLUMNS[$i];
                 }
               }

               my $auxentry = "\"$total\", \"$auxjson{'fg_username'}\", \"$acLock\", \"$auxjson{'fg_fullname'}\", \"$auxjson{'fg_haddr'}\", \"$auxjson{'fg_email'}\", \"$auxjson{'fg_NID'}\", \"$auxjson{'fg_phone'}\", \"$auxjson{'fg_phone2'}\", \"$auxjson{'fg_ctlogin'}\", \"$auxjson{'fg_ftlogin'}\", \"$auxjson{'fg_ltlogin'}\"";
               $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
               $total++;

               # Using array and hash vars for *sort control*
               if ($sortid =~ /^fg_(username|fullname|email|NID|ltlogin)$/) {
                  push(@unsortId, $auxjson{$sortid}) if (!findId(\@unsortId, $auxjson{$sortid}));
                  push(@{$unsortData{$auxjson{$sortid}}}, $auxentry);
               }
               else {
                  push(@unsortId, $total) if (!findId(\@unsortId, $total));
                  push(@{$unsortData{$total}}, $auxentry);
                  $stid = 1;
               }
            }
         }
      }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    my @sortedId = ();
    if ($sortd eq "asc") {
       if ($stid == 0) { @sortedId = sort(@unsortId); }
       else { @sortedId = sort { $a <=> $b } @unsortId; }
    }
    else {
       if ($stid == 0) { @sortedId = reverse sort (@unsortId); }
       else { @sortedId = reverse sort { $a <=> $b } @unsortId; }
    }

    $total = $start;
    foreach (@sortedId) {
       foreach my $line (@{$unsortData{"$_"}}) {
          $line = ",\n$line" if ($total > $start);
          $json = "$json $line";
          $total++;
       }
    }
    $records++;
    $json = json_out($records, $json, $page, 'rows2');
    $res->content($json);
    return $res;
}

# Get dhcp lease data (lanlord based - http://linux.uhw.com/software/lanlord)
sub get_leasedata {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    my $lease = dhcpConf();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my $stid = 0;
    my @unsortId = ();
    my %unsortData = ();
    my @dvalue = ();
    if (-e "$lease") {
       open FILE, "<$lease";
       while (<FILE>) {
         if ($_ =~ /^[\s]*lease\s/) {
            (undef, $ipL) = split /\s/, $_;
            $clientL = 'None';
            $macL = 'None';
         }
         else {
           if ($_ !~ /^}/) {
              if ($_ =~ /^[\s]*starts\s/) {
                 (undef, undef, $sDayL,  $sDateL, $sHourL) = split /\s+/, $_;
                 $sHourL =~ s/;//;
              }
              elsif ($_ =~ /^[\s]*ends\s/) {
                 (undef, undef, $eDayL, $eDateL, $eHourL) = split /\s+/, $_;
                 $eHourL =~ s/;//;
              }
              elsif ($_ =~ /^[\s]*abandoned/) {
                 $macL = "<em>Abandoned</em>";
              }
              elsif ($_ =~ /^[\s]*binding/) {
                 (undef, undef, undef, $binding) = split /\s+/, $_ ;
              }
              elsif ($_ =~ /^[\s]*hardware\s/) {
                 (undef, undef, $macType, $macL) = split /\s+/, $_;
                 $macL =~ s/;//;
              }
              elsif ($_ =~ /^[\s]*client-hostname\s/) {
                 (undef, undef, $clientL) = split /\s+/, $_;
                 $clientL =~ s/[;"]//g;
              }
           }
           else {
             if ($binding eq "active;") {
                my $auxentry = "{\"id\":\"$total\",\"cell\":[ \"$total\", \"$ipL\", \"$clientL\", \"$sHourL - $sDateL\", \"$eHourL - $eDateL\", \"$macL\", \"$macType\" ]}";
                # Using array and hash vars for *sort control*
                my $auxdata = undef;
                if ($sortid eq "clientL") {
                   push(@unsortId, $clientL) if (!findId(\@unsortId, $clientL));
                   push(@{$unsortData{$clientL}}, $auxentry);
                }
                elsif ($sortid eq "sLease") {
                   $auxdata = "$sHourL - $sDateL";
                   push(@unsortId, $auxdata) if (!findId(\@unsortId, $auxdata));
                   push(@{$unsortData{$auxdata}}, $auxentry);
                }
                elsif ($sortid eq "eLease") {
                   $auxdata = "$eHourL - $eDateL";
                   push(@unsortId, $auxdata) if (!findId(\@unsortId, $auxdata)); 
                   push(@{$unsortData{$auxdata}}, $auxentry);
                }
                elsif ($sortid eq "ipL") {
                   push(@unsortId, $ipL) if (!findId(\@unsortId, $ipL)); 
                   push(@{$unsortData{$ipL}}, $auxentry);
                }
                else {
                   push(@unsortId, $total) if (!findId(\@unsortId, $total));
                   push(@{$unsortData{$total}}, $auxentry);
                   $stid = 1;
                }
                $total++;
             }
             $binding = "";
           }
         }
       }
       close FILE;
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    my @sortedId = ();
    if ($sortd eq "asc") {
       if ($stid == 0) { @sortedId = sort(@unsortId); }
       else { @sortedId = sort { $a <=> $b } @unsortId; }
    }
    else {
       if ($stid == 0) { @sortedId = reverse sort (@unsortId); }
       else { @sortedId = reverse sort { $a <=> $b } @unsortId; }
    }

    $total = 1;
    foreach (@sortedId) {
       foreach my $line (@{$unsortData{"$_"}}) {
          $line = ",\n$line" if ($total > 1);
          $json = "$json $line";
          $total++;
       }
    }
    $json = json_out($total, $json, "1", 'rows');
    $res->content($json);
    return $res;
}

# Get auth data (/var/log/daemon or /var/log/daemons/info.log)
sub get_authdata {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Discover Daemon log
    my $daemonfile = "/var/log/fwguardian/webstats.log";
    if (not -e "$daemonfile") {
       $daemonfile = "/var/log/syslog" if (-e "/var/log/syslog");
       $daemonfile = "/var/log/messages" if (-e "/var/log/messages");
    }

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my $stid = 0;
    my @unsortId = ();
    my %unsortData = ();

    my $count = 0, $tot_line = 0;
    open (DFILE, "tac $daemonfile|");
    while (<DFILE>) {
       my $isAdmin = 0, $isRevoke = 0, $isVia = 0;
       my $alLogin = "", $alAccount = "", $alFrom = "", $alAddress = "", $alTime = "";
       $tot_line++;

       if ($_ =~ /fwguardian.*(login .* (by|from)|(Revoke|Incorrect) .* from)/ && $tot_line < 1000) {

          $count = 0;
          my $LogAux = "";
          foreach my $LogOpt (split /\s+/, $_) {
            $count++;
            $alTime = "$alTime $LogOpt" if ($count < 4);
            if ($LogOpt eq "Admin" || $isAdmin > 0) {
               if ($isAdmin == 0) {
                  $alAccount = "<font color=\'Red\'>Admin login</font>";
                  $alFrom = "Local";
               }
               else {
                  $alLogin = $LogOpt if ($isAdmin == 3);
                  $alAddress = $LogOpt if ($isAdmin == 5);
               }
               $isAdmin++;
            } # Admin login
            elsif ($LogOpt =~ /^(Revoke|Incorrect)$/ || $isRevoke > 0) {
              if ($isRevoke == 0) {
                 if ($LogOpt eq "Revoke") {
                    $alAccount = "<font color=\'Gray\'><strong>Revoke</strong> login</font>";
                 }
                 else {
                    $alAccount = "<font color=\'Gray\'><strong>Incorrect</strong> login</font>";
                 }
                 $alFrom = "-";
              }
              else {
                 $alLogin = $LogOpt if ($isRevoke == 5);
                 $alAddress = $LogOpt if ($isRevoke == 4);
              }
              $isRevoke++;
            } # Revoke login
            else {
               if ($_ =~ /via HTTP/) {
                  if ($LogOpt eq "login" || $isVia > 0) {
                     if ($isVia == 0) {
                        $alAccount = "<font color=\'Green\'>User login</font>"; 
                        $alAddress = $LogAux;
                     }
                     else {
                        $alLogin = $LogOpt if ($isVia == 1);
                        $alFrom = $LogOpt if ($isVia == 3); 
                     }
                     $isVia++;
                  }
                  $LogAux = $LogOpt;
               }
            } # User Login
          }
          # Make json dataStore
          if ($alLogin && $alAccount) {
             if ($isVia > 0) { $alLogin = "<font color=\'Green\'>$alLogin</font>"; }
             elsif ($isRevoke > 0) { $alLogin = "<font color=\'Gray\'>$alLogin</font>"; }
             else { $alLogin = "<font color=\'Red\'>$alLogin</font>"; }
             $alLogin = "<strong>$alLogin</strong>";
             $alAddress = "<strong>$alAddress</strong>";

             my $auxentry = "\"$total\", \"$alLogin\", \"$alAccount\", \"$alFrom\", \"$alAddress\", \"$alTime\"";
             $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
             $total++;

             # Using array and hash vars for *sort control*
             if ($sortid eq "alLogin") {
                push(@unsortId, $alLogin) if (!findId(\@unsortId, $alLogin));
                push(@{$unsortData{$alLogin}}, $auxentry);
             }
             elsif ($sortid eq "alAccount") {
                push(@unsortId, $alAccount) if (!findId(\@unsortId, $alAccount));
                push(@{$unsortData{$alAccount}}, $auxentry);
             }
             elsif ($sortid eq "alAddress") {
                push(@unsortId, $alAddress) if (!findId(\@unsortId, $alAddress));
                push(@{$unsortData{$alAddress}}, $auxentry);
             }
             elsif ($sortid eq "alTime") {
                push(@unsortId, $alTime) if (!findId(\@unsortId, $alTime));
                push(@{$unsortData{$alTime}}, $auxentry);
             }
             else {
                push(@unsortId, $total) if (!findId(\@unsortId, $total));
                push(@{$unsortData{$total}}, $auxentry);
                $stid = 1;
             }
          }
       }
    }
    close (DFILE);

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    my @sortedId = ();
    if ($sortd eq "asc") {
       if ($stid == 0) { @sortedId = sort(@unsortId); }
       else { @sortedId = sort { $a <=> $b } @unsortId; }
    }
    else {
       if ($stid == 0) { @sortedId = reverse sort (@unsortId); }
       else { @sortedId = reverse sort { $a <=> $b } @unsortId; }
    }

    $total = 1;
    foreach (@sortedId) {
       foreach my $line (@{$unsortData{"$_"}}) {
          $line = ",\n$line" if ($total > 1);
          $json = "$json $line";
          $total++;
       }
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Get auth user data (/usr/share/fwguardian/webauth/control/CUR_USERS)
sub get_authuserdata {
    use CGI qw(:standard);
    use HTTP::Response;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Discover Daemon log
    my $userfile = "/usr/share/fwguardian/webauth/control/CUR_USERS";

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json output
    my $json = undef;
    my $total = 1;
    if (-e "$userfile") {
       open DFILE, "<$userfile";
       while (<DFILE>) {
          my (undef, $alLogin, $alAddress) = split /\s/, $_; 

          if ($alLogin && $alAddress) {
             $alLogin = "<strong>$alLogin</strong>";
             $alAddress = "<strong>$alAddress</strong>";
             my $auxentry = "\"$total\", \"$alLogin\", \"$alAddress\"";
             $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
             $auxentry = ",\n$auxentry" if ($total > 1);
             $json = "$json $auxentry";
             $total++;
          }
       }
       close (DFILE);
    }

    # Json content
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Get fwguardian.conf defs (global settings)
sub get_infra {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;
    read_fwcfg;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $jsct = 0;
    my $total = 1;
    my @sortedId = ();
    my @gpinfra = ("web", "network", "security", "kill", "log");

    my $gpchk = "";
    my %auxDesc = ();
    push(@{$auxDesc{'webserver'}}, ("Carrega a interface web", "Load the web interface"));
    push(@{$auxDesc{'webhealth'}}, ("Verifica se o serviço de web está online", "Checks if the web service is online"));
    push(@{$auxDesc{'ip_dynamic'}}, ("Ativa ajustes de rede para IP dinãmico", "Enable network adjustment for dynamic IP"));
    push(@{$auxDesc{'forwarding'}}, ("Ativa roteamento (Importante)", "Enable forwarding (Important)"));
    push(@{$auxDesc{'net_sharing'}}, ("Compartilha Internet (fwmasq: NAT de Saída e Proxy)", "Internet sharing (fwmasq: Source Nat and Proxy)"));
    push(@{$auxDesc{'optimize_TOS'}}, ("Ativa otimização por TOS (requerido para as próximas opções)", "Enable TOS optimization (Required for next options)"));
    push(@{$auxDesc{'violate_TOS'}}, ("Modifica o valor TOS de todos os pacotes (Desabilite para *preservar o TOS*)", "Modify TOS value of all packets (Disable to *preserve TOS*)"));
    push(@{$auxDesc{'fix_TOS'}}, ("Evita injustiça de pacotes Minimize-Delay", "Make fair Minimize-Delay packets"));
    push(@{$auxDesc{'keepalive_sessions'}}, ("Ativa controle de sessão com CONNMARK", "Enable session control with CONNMARK"));
    push(@{$auxDesc{'conntrack_bytes'}}, ("Ativa contadores nf_conntrack_acct", "Enable nf_conntrack_acct counters"));
    push(@{$auxDesc{'syn_cookie'}}, ("Ativa proteção syn_cookie", "Enable syn_cookie protection"));
    push(@{$auxDesc{'enable_tcpreset'}}, ("Responde com RST pacotes processados com REJECT", "Responds with RST packets processed with REJECT"));
    push(@{$auxDesc{'tcp_dos_protect'}}, ("Ativa proteção básica anti DOS (utiliza o modulo PSD, se existir)", "Enable basic anti DOS protection (use PSD module if exist)"));
    push(@{$auxDesc{'drop_portscan'}}, ("Ativa proteção básica contra portscan", "Enable basic portscan protection"));
    push(@{$auxDesc{'rp_filter'}}, ("Ativa proteção de caminho reverso (anti spoof - rpfilter)", "Enable reverse path protection (anti spoof - rpfilter)"));
    push(@{$auxDesc{'icmp_bogus_error'}}, ("Ignora alertas de respostas de erro icmp forjadas", "Ignore warnings for bogus ICMP error responses"));
    push(@{$auxDesc{'ignore_brd_icmp'}}, ("Ignora broadcast de pacotes icmp (echo)", "Ignore icmp broadcast (echo)"));
    push(@{$auxDesc{'send_redirects'}}, ("Permite o envio de pacotes icmp-redirect", "Allow firewall to send icmp-redirect packets"));
    push(@{$auxDesc{'secure_redirects'}}, ("Permite o recebimento de pacotes icmp-redirect de um gateway conhecido", "Allow received icmp-redirect from a known gateway)"));
    push(@{$auxDesc{'deny_icmp_redir'}}, ("Recusa mensagens de icmp-redirect", "Deny icmp-redirect messages"));
    push(@{$auxDesc{'deny_src_rt'}}, ("Recusa roteamento de origem (recomendado)", "Deny source routing (recommended)"));
    push(@{$auxDesc{'defrag'}}, ("Carrega modulo de desfragmentação ipv4 (requerido pelo comando iptables *-f*)", "Load ipv4 defrag module (required in *-f* iptables command)"));
    push(@{$auxDesc{'unclean'}}, ("Carrega modulo unclean (descarta pacotes inválidos)", "Load unclean module (drop invalid packets)"));
    push(@{$auxDesc{'kill_largeping'}}, ("Descarta pings maiores que 300 bytes (recomendado)", "Drop ping larger than 300 bytes (recommended)"));
    push(@{$auxDesc{'kill_web'}}, ("Rejeita pacotes destinados a tcp/80,443 ou 8080 (Indirect)", "Reject packets on TCP/80, 443 or 8080 (Indirect)"));
    push(@{$auxDesc{'kill_nbt'}}, ("Rejeita pacotes NBT (Compartilhamento de Arquivos)", "Reject NBT packets (File Sharing)"));
    push(@{$auxDesc{'log_martians'}}, ("Registra pacotes inválidos", "Log martian packets"));
    push(@{$auxDesc{'log_ping'}}, ("Registra todos os pacotes de ping (echo-request)", "Log all ping packets (echo-request)"));
    push(@{$auxDesc{'log_trace'}}, ("Define net.netfilter.nf_log.2 como ipt_LOG (para eventos TRACE)", "Define net.netfilter.nf_log.2 with ipt_LOG (for TRACE events)"));
    push(@{$auxDesc{'log_indirect_drop'}}, ("Registra bloqueios indiretos (por ausência de regra)", "Log indirect drops (by rule absence)"));
    push(@{$auxDesc{'log_indirect_broadcast'}}, ("Registra bloqueios indiretos de broadcast (pode resultar em flood nos logs)", "Log indirect broadcast drops (can flood your logs)"));

    foreach my $group (@gpinfra) {
       foreach my $lines (@{$infrarules{"$group"}}) {
          my $auxentry = "";

          my $opt1 = "", $opt2 = "";
          ($opt1, $opt2, undef) = split(/\s+/, $lines, 3);
          $auxentry = "\"$total\", \"$group\", \"$opt1\", \"$opt2\"";

          my $fDesc = "";
          $fDesc = $auxDesc{$opt1}[$FW_LANG] if ($auxDesc{$opt1}[$FW_LANG]);
          $auxentry = "$auxentry, \"<strong>$fDesc</strong>\"";

          $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
          push(@sortedId, $auxentry);
          $total++;
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    $total = 1;
    foreach my $line (@sortedId) {
       $line = ",\n$line" if ($total > 1);
       $json = "$json $line";
       $total++;
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Get profile/profile.def (profile rules)
sub get_ProfileRules {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $jsct = 0;
    my $total = 1;
    my @sortedId = ();
    read_profiles;

    foreach my $group (@fwltprof, @fwprof) {
       foreach my $lines (@{$profline{"$group"}}) {
          my ($pflInt, $pfIf, $proto, $pdata, $fwTarg, $pflIp, $pfIp, $pRate, $auxlines) = split(/\s+/, $lines, 9);
          my $pHash = "any", $fNew = "No", $pStr = "", $hLog = "No";

          $fwTarg="IGNORE" if ($fwTarg eq "RETURN") ;
          $proto = "src_addr" if ($proto eq "src_gplist");
          $proto = "dst_addr" if ($proto eq "dst_gplist");
          $pdata = "any" if ($proto !~ /^(tcp|udp|icmp|(src|dst)_(addr|gplist|geoip))/);
          if ($fwTarg eq "PKTLIMIT") {
             if ($auxlines =~ /flow=/) {
                (undef, $pHash) = split /flow=/, $auxlines;
                ($pHash, undef) = split /\s+/, $pHash, 2 if ($pHash ne "any");
             }
          }
          else {
             $pHash = "any";
          }

          $auxlines = " $pRate $auxlines";
          if ($auxlines =~ /[\s]string=/) {
             (undef, $pStr) = split /[\s]string=/, $auxlines;
             (undef, $pStr) = split /[\"|\']/, $pStr;
          }
          if ($auxlines && $auxlines ne "") {
             ($fCond, $fDesc) = split /\s/, getCondDesc($auxlines), 2;
          }
          else {
             $fCond = "none";
             $fDesc = "";
          }
          $fNew = "Yes" if ($auxlines =~ /[\s]new($|\s)/);
          $hLog = "Yes" if ($auxlines =~ /[\s]log($|\s)/);
          $pRate = 0 if ($pRate !~ /^[0-9]+\/([0-9]+|s|m|h|sec|minute|hour|day)($|,([0-9]+|upto|above))/);

          $group =~ s/^limit:/limit\>/;
          $group =~ s/^(mangle|vpn):/mangle\>/;
          my $auxentry = "{\"id\":\"$total\",\"cell\":[\"$total\", \"$group\", \"$pflInt\", \"$pfIf\", \"$proto\", \"$pdata\", \"$fwTarg\", \"$pflIp\", \"$pfIp\" , \"$pRate\", \"$pHash\", \"$fNew\", \"$pStr\", \"$fCond\", \"$hLog\", \"$fDesc\"]}";

          push(@sortedId, $auxentry);
          $total++;
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    $total = 1;
    foreach my $line (@sortedId) {
       $line = ",\n$line" if ($total > 1);
       $json = "$json $line";
       $total++;
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Get fwroute.nat defs (for NAT rules)
sub get_natrules {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $jsct = 0;
    my $total = 1;
    my @sortedId = ();
    read_fwnat;

    foreach my $group (@natgroup) {
       foreach my $lines (@{$natrules{"$group"}}) {
          my ($ifIn, $src, $dst, $fwTarg, $auxlines) = split(/\s+/, $lines, 5);
          my $ifOut = "any", $nIp = "none", $nOpt = "none", $nLog = "";

          ($ifIn, $ifOut) = split/->/, $ifIn;
          $ifOut = "any" if (!$ifOut);

          # Target NAT
          if ($fwTarg !~ /^(MASQ|AUTO|IGNORE)$/) {
             $nIp = "$fwTarg";
             $fwTarg = "SET";
          }

          if ($auxlines && $auxlines ne "") {
             $auxlines = " $auxlines";
             ($fCond, $fDesc) = split /\s/, getCondDesc($auxlines), 2;
          }
          else {
             $fCond = "none";
             $fDesc = "";
          }
          if ($auxlines =~ /[\s](log|log-desc)=/) {
             (undef, $nLog) = split /[\s]log=|[\s]log-desc=/, $auxlines;
             (undef, $nLog) = split /[\"|\']/, $nLog;
          }

          # Getting proto (dport or sport) def
          my ($proto, $sport, $dport) = split /\//, getports($auxlines);

          # Extra DNAT options
          if ($auxlines =~ /[\s](only-dnat|with-masq)($|[\s])/ && $group =~ /^DNAT($|\?chk=)/) {
             $nOpt = "with-masq";
             $nOpt = "only-dnat" if ($auxlines =~ /[\s]only-dnat/);
          }

          if ($group =~ /^(DNAT|SNAT|NETMAP)($|\?chk=)/) {
             $ifOut = "any" if ($group =~ /^SNAT($|\?chk=)/);
             my $auxentry = "{\"id\":\"$total\",\"cell\":[\"$total\", \"$group\", \"$ifIn\", \"$src\", \"$ifOut\", \"$dst\", \"$fwTarg\", \"$nIp\" , \"$proto\", \"$sport\", \"$dport\", \"$nOpt\", \"$fCond\", \"$nLog\", \"$fDesc\"]}";

             push(@sortedId, $auxentry);
             $total++;
          }
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    $total = 1;
    foreach my $line (@sortedId) {
       $line = ",\n$line" if ($total > 1);
       $json = "$json $line";
       $total++;
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Get vpn.conf defs (for VPN rules)
sub get_vpnrules {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;
    my $aux_vpngroup = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my @sortedId = ();
    read_fwvpn;

    foreach my $group (@vpngroup) {
       my $svcount=0;
       my %server = ();
       foreach my $lines (@{$vpnrules{"$group"}}) {
          my $allow=0;
          my $auxentry="";
          my $fDesc = "", $fCond = "none";
          if ($group =~ /^(DIRECT|IP-USERMAPS)($|\?chk=)/ && $group =~ /^($aux_vpngroup)($|\?chk=)/) {
             $allow=1;
             my $vPass = "", $vPassType="chap";
             my $dreload = "No", $ipsecp = "none", $ipsecsp = "none", $ipip = "No";
             my $opt1 = "", $opt2 = "", $opt3 = "", $opt4 = "", $dst = "", $dgd = "", $auxlines = "";
             ($opt1, $opt2, $opt3, $opt4, $dst, $dgd, $auxlines) = split(/\s+/, $lines, 7) if ($aux_vpngroup eq "DIRECT");
             ($opt1, $opt2, $opt3, $opt4, $auxlines) = split(/\s+/, $lines, 5) if ($aux_vpngroup eq "IP-USERMAPS");

             if ($auxlines && $auxlines ne "") {
                $auxlines = " $auxlines";
                ($fCond, $fDesc) = split /\s/, getCondDesc($auxlines), 2;
             }
             else {
                $fCond = "none";
                $fDesc = "";
             }

             $auxentry = "\"$total\", \"$group\", \"$opt1\", \"$opt2\", \"$opt3\", \"$opt4\"";

             # Extra VPN options
             if ($aux_vpngroup eq "DIRECT") {
                if ($opt4 eq "TUNNEL") {
                   if ($auxlines =~ /[\s]ipsec-psk=/) {
                      (undef, $ipsecp) = split /[\s]ipsec-psk=/, $auxlines;
                      (undef, $ipsecp) = split /[\"|\']/, $ipsecp;
                   }
                   if ($auxlines =~ /[\s]spi=/ && $ipsecp ne "none") {
                      (undef, $ipsecsp) = split /[\s]spi=/, $auxlines;
                      ($ipsecsp, undef) = split /\s+/, $ipsecsp;
                   }
                   $dreload = "Yes"  if ($auxlines =~ /[\s](dgd-reload)($|[\s])/);
                   $ipip = "Yes"  if ($auxlines =~ /[\s](with-ipip)($|[\s])/);
                }
                $auxentry = "$auxentry, \"$dst\", \"$dgd\", \"$dreload\", \"$ipip\", \"$ipsecp\", \"$ipsecsp\", \"$fCond\", \"$fDesc\"";
             }
             else {
                if ($auxlines =~ /[\s]passwd=/) {
                   (undef, $vPass) = split /[\s]passwd=/, $auxlines;
                   (undef, $vPass) = split /[\"|\']/, $vPass;
                }
                if ($vPass ne "" && $auxlines =~ /[\s]with-(pap|chpap)($|[\s])/) {
                   $vPassType = "chpap";
                   $vPassType = "pap" if ($auxlines =~ /[\s]with-pap($|[\s])/);
                }
                $auxentry = "$auxentry, \"$vPass\", \"$vPassType\", \"$fCond\", \"$fDesc\"";
             }
          }
          elsif ($group =~ /^(PPTP|IPSEC)-SERVER($|\?chk=)/ && $aux_vpngroup eq "server") {
             $allow=1;
             $svcount++;
             if ($svcount == 1) {
                $server{'bind'} = "0.0.0.0", $server{'ppp-local'} = "192.168.10.10", $server{'ppp-pool'} = "192.168.10.15-30";
                $server{'ms-dns'} = "192.168.10.10", $server{'ms-wins'} = "192.168.10.10", $server{'proxy-arp'} = "Yes";
                $server{'winbind-authgroup'} = "none", $server{'default'} = "No", $server{'optional-mppe'} = "No", $server{'l2tp'} = "No";
                $server{'status'} = "ERROR", $server{'peerkey'} = "psk", $server{'default-psk'} = "auto";
             }
             my ($cmdTun, $dataTun, $auxlines) = split(/\s+/, $lines, 3);
             if ($server{$cmdTun}) {
                $server{$cmdTun} = $dataTun;

                if ($auxlines && $auxlines ne "") {
                   $auxlines = " $auxlines";
                   ($fCond, undef) = split /\s/, getCondDesc($auxlines), 2;
                }
                else {
                   $fCond = "none";
                   $fDesc = "";
                }

                if ($cmdTun eq "status") {
                   my $isbind = 0;
                   $isbind = `pidof pptpd | wc -l` if ($group =~ /^PPTP/);
                   $isbind = `pidof racoon | wc -l` if ($group =~ /^IPSEC/);
                   if ($isbind > 0) {
                      my $bindchk = "Green";
                      $isbind = `netstat -ntlup | grep ':1723' | wc -l` if ($group =~ /^PPTP/);
                      $isbind = `netstat -ntlup | grep ':500' | wc -l` if ($group =~ /^IPSEC/);
                      $bindchk = "Orange" if ($isbind == 0);
                      $server{$cmdTun} = "<FONT color=\'$bindchk\'><strong>OK</strong></FONT>";
                   }
                   else {
                      $server{$cmdTun} = "<FONT color=\'Red\'><strong>ERROR</strong></FONT>";
                   }
                }
                else {
                   $server{$cmdTun} = "Yes" if ($server{$cmdTun} eq "yes" || $server{$cmdTun} eq "on");
                }
                $auxentry = "\"$total\", \"$group\", \"$cmdTun\", \"$server{$cmdTun}\", \"$fCond\"" if ($cmdTun =~ /^(status|bind|ppp-local|ppp-pool|ms-dns|ms-wins|proxy-arp|default|optional-mppe|winbind-authgroup|l2tp|peerkey|default-psk)$/);
             }
          }

          if ($allow == 1) {
             $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
             push(@sortedId, $auxentry);
             $total++;
          }
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    $total = 1;
    foreach my $line (@sortedId) {
       $line = ",\n$line" if ($total > 1);
       $json = "$json $line";
       $total++;
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Get fwroute.rules defs (for auth rules)
sub get_authmappsrules {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;
    my $aux_authgroup = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $jsct = 0;
    my $total = 1;
    my @sortedId = ();
    read_fwrules("route");

    foreach my $group (@gpset) {
       foreach my $lines (@{$gpauthrule{"$group"}}) {
          my $allow = 0;
          my $auxentry = "";
          my $auxlines = "";
          if ($group =~ /^authmaps($|\?chk=)/ && $aux_authgroup eq "authmaps") {
             $allow=1;
             my $opt1 = "", $opt2 = "", $opt3 = "";
             ($opt1, $opt2, $opt3, $auxlines) = split(/\s+/, $lines, 4);

             $auxlines = " $auxlines" if ($auxlines);
             $auxentry = "\"$total\", \"$group\", \"$opt1\", \"$opt2\", \"$opt3\"";
          }
          elsif ($group =~ /^networks($|\?chk=)/ && $aux_authgroup eq "networks") {
             $allow=1;
             my $opt1 = "", $opt2 = "any", $opt3 = "0.0.0.0/0", $ckValue = "No";
             ($opt1, $opt2, $opt3, $auxlines) = split(/\s+/, $lines, 4);

             $auxlines = " $auxlines" if ($auxlines);
             $ckValue = "Yes" if ($auxlines =~ /[\s]bypass($|[\s])/);
             $auxentry = "\"$total\", \"$group\", \"$opt1\", \"$opt2\", \"$opt3\", \"$ckValue\"";
          }

          if ($auxlines && $auxlines ne "") {
             $auxlines = " $auxlines";
             ($fCond, $fDesc) = split /\s/, getCondDesc($auxlines), 2;
          }
          else {
             $fCond = "none";
             $fDesc = "";
          }

          $auxentry = "$auxentry, \"$fCond\", \"$fDesc\"";

          if ($allow == 1) {
             $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
             push(@sortedId, $auxentry);
             $total++;
          }
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    $total = 1;
    foreach my $line (@sortedId) {
       $line = ",\n$line" if ($total > 1);
       $json = "$json $line";
       $total++;
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Get tfshape.conf defs
sub get_QosCfg {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $jsct = 0;
    my $total = 1;
    my $stid = 0;
    my @unsortId = ();
    my %unsortData = ();
    my @dvalue = ();
    read_fwqos;

    foreach my $lines (@qosset) {
       if ($lines =~ /^(\s)*set-qos(\s)/) {
          $jsct = 1;
          $lines =~ s/(\s)+/ /g;
          my $name = "";
          my $int = "";
          my $speed = "";
          my $burst = "0";
          my $type = "htb";
          my $default = "none";
          my $mirror = "none";
          my $norootclass = "No";
          my $fCond = "none";
          foreach my $auxlines (split /\s/, $lines) {
             @dvalue = split /=/, $auxlines;
             if ($jsct > 3) {
                if ($auxlines eq "set-mirror") {
                   $mirror = "set-mirror";
                }
                elsif ($auxlines eq "mirrored") {
                   $mirror = "mirrored";
                }
                elsif ($auxlines eq "no-rootclass") {
                   $norootclass = "Yes";
                }
                else {
                   if ($auxlines =~ /^(self|set)-default$/) {
                      $default = "self-default";
                      $default = "set-default" if ($auxlines eq "set-default");
                   }
                }
                if ($dvalue[1]) {
                   if ($dvalue[0] eq "type" ) {
                      $type = $dvalue[1];
                   }
                   elsif ($dvalue[0] eq "burst") {
                      $burst = $dvalue[1];
                   }
                   elsif ($dvalue[0] eq "chk") {
                      $fCond = $dvalue[1];
                   }
                }
             }
             else {
                if ($jsct == 2) {
                   $name = $auxlines;
                }
                else {
                   if ($jsct == 3) {
                      ($int, $speed) = split /:/, $auxlines;
                   }
                }
             }
             $jsct++;
          }
          if ($jsct > 2) {
             my $auxentry = "{\"id\":\"$total\",\"cell\":[\"$total\", \"$name\", \"$int\", \"$speed\", \"$burst\", \"$type\", \"$default\", \"$norootclass\", \"$mirror\", \"$fCond\"]}";

             # Using array and hash vars for *sort control*
             if ($sortid eq "ifName") {
                push(@unsortId, $name) if (!findId(\@unsortId, $name));
                push(@{$unsortData{$name}}, $auxentry);
             }
             elsif ($sortid eq "ifInt") {
                push(@unsortId, $int) if (!findId(\@unsortId, $int));
                push(@{$unsortData{$int}}, $auxentry);
             }
             elsif ($sortid eq "ifSpeed") {
                push(@unsortId, $speed) if (!findId(\@unsortId, $speed));
                push(@{$unsortData{$speed}}, $auxentry);
             }
             else {
                push(@unsortId, $total) if (!findId(\@unsortId, $total));
                push(@{$unsortData{$total}}, $auxentry);
                $stid = 1;
             }
             $total++;
          }
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    my @sortedId = ();
    if ($sortd eq "asc") {
       if ($stid == 0) { @sortedId = sort(@unsortId); }
       else { @sortedId = sort { $a <=> $b } @unsortId; }
    }
    else { 
       if ($stid == 0) { @sortedId = reverse sort (@unsortId); }
       else { @sortedId = reverse sort { $a <=> $b } @unsortId; }
    }

    $total = 1;
    foreach (@sortedId) {
       foreach my $line (@{$unsortData{"$_"}}) {
          $line = ",\n$line" if ($total > 1);
          $json = "$json $line";
          $total++;
       }
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
} 

# Get tfshape.conf defs (for egress)
sub get_QosEgress {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $jsct = 0;
    my $total = 1;
    my $stid = 0;
    my @unsortId = ();
    my %unsortData = ();
    my @dvalue = ();
    read_fwqos;

    foreach my $lines (@qosegress) {
       if ($lines =~ /^(\s)*set-egress(\s)/) {
          $jsct = 1;
          $lines =~ s/(\s)+/ /g;
          my $pclass = "";
          my $nclass = "";
          my $rate = "";
          my $ratemax = "";
          my $burst = "0";
          my $latency = "none";
          my $prio = "none";
          my $classify = "classify-rule";
          my $sfqf = "default";
          my $sfqh = "1024";
          my $pkts = "default";
          my $nfLb = "No";
          my $trackLb = "";
          my $fCond = "none";
          my $fDesc = "";
          if ($lines =~ /[\s]desc=/) {
             (undef, $fDesc) = split /[\s]desc=/, $lines;
             (undef, $fDesc) = split /[\"|\']/, $fDesc;
          }
          $nfLb = "Yes" if ($lines =~ /[\s]nf-lb($|[\s])/);
          $classify = "classify-rule";
          foreach my $auxlines (split /\s/, $lines) {
             @dvalue = split /=/, $auxlines;
             if ($jsct > 3) {
                if ($auxlines eq "mark-rule") {
                   $classify = "mark-rule";
                }
                elsif ($auxlines eq "premark-rule") {
                   $classify = "premark-rule";
                }
                elsif ($auxlines eq "postmark-rule") {
                   $classify = "postmark-rule";
                }
                elsif ($auxlines eq "tc-rule") {
                   $classify = "tc-rule";
                }
                elsif ($nfLb eq "Yes" ){
                   if ($auxlines eq "track-new") {
                      $trackLb = ",$trackLb" if ($trackLb ne "");
                      $trackLb = "track-new$trackLb";
                   }
                   elsif ($auxlines eq "track-dst") {
                      $trackLb = ",$trackLb" if ($trackLb ne "");
                      $trackLb = "track-dst$trackLb";
                   }
                   elsif ($auxlines eq "fixed") {
                      $trackLb = ",$trackLb" if ($trackLb ne "");
                      $trackLb = "fixed$trackLb";
                   }
                }

                if ($dvalue[1]) {
                   if ($dvalue[0] eq "sfq-flow") {
                      $sfqf = $dvalue[1];
                      ($sfqf, $sfqh) = split /\//, $dvalue[1], 2 if ($dvalue[1] =~ /\//);
                   }
                   elsif ($dvalue[0] eq "packets") {
                      $pkts = $dvalue[1];
                   }
                   elsif ($dvalue[0] eq "burst") {
                      $burst = $dvalue[1];
                   }
                   elsif ($dvalue[0] eq "latency") {
                      $latency = $dvalue[1];
                   }
                   elsif ($dvalue[0] eq "prio") {
                      $prio = $dvalue[1];
                   }
                   elsif ($dvalue[0] eq "chk") {
                      $fCond = $dvalue[1];
                   }
                }
             }
             else {
                if ($jsct == 2) {
                   ($pclass, $nclass) = split /->/, $auxlines, 2;
                }
                else {
                   if ($jsct == 3) {
                      ($rate, $ratemax) = split /:/, $auxlines, 2;
                   }
                }
             }
             $jsct++;
          }
          if ($jsct > 2) {
             $trackLb = "none" if ($trackLb eq "");
             my $auxentry = "{\"id\":\"$total\",\"cell\":[\"$total\", \"$pclass\", \"$nclass\", \"$rate\", \"$ratemax\", \"$burst\", \"$latency\", \"$prio\", \"$classify\", \"$sfqf\", \"$sfqh\", \"$pkts\", \"$nfLb\", \"$trackLb\", \"$fCond\", \"$fDesc\"]}";

             # Using array and hash vars for *sort control*
             if ($sortid eq "ifPClass") {
                push(@unsortId, $pclass) if (!findId(\@unsortId, $pclass));
                push(@{$unsortData{$pclass}}, $auxentry);
             }
             elsif ($sortid eq "ifNClass") {
                push(@unsortId, $nclass) if (!findId(\@unsortId, $nclass));
                push(@{$unsortData{$nclass}}, $auxentry);
             }
             elsif ($sortid eq "ifRate") {
                push(@unsortId, $rate) if (!findId(\@unsortId, $rate));
                push(@{$unsortData{$rate}}, $auxentry);
             }
             elsif ($sortid eq "ifRateMax") {
                push(@unsortId, $ratemax) if (!findId(\@unsortId, $ratemax));
                push(@{$unsortData{$ratemax}}, $auxentry);
             }
             else {
                push(@unsortId, $total) if (!findId(\@unsortId, $total));
                push(@{$unsortData{$total}}, $auxentry);
                $stid = 1;
             }
             $total++;
          }
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    my @sortedId = ();
    if ($sortd eq "asc") {
       if ($stid == 0) { @sortedId = sort(@unsortId); }
       else { @sortedId = sort { $a <=> $b } @unsortId; }
    }
    else { 
       if ($stid == 0) { @sortedId = reverse sort (@unsortId); }
       else { @sortedId = reverse sort { $a <=> $b } @unsortId; }
    }

    $total = 1;
    foreach (@sortedId) {
       foreach my $line (@{$unsortData{"$_"}}) {
          $line = ",\n$line" if ($total > 1);
          $json = "$json $line";
          $total++;
       }
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}
 
# Get tfshape.conf defs (for set-filter rules)
sub get_QosFilterRl {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $jsct = 0;
    my $total = 1;
    my $stid = 0;
    my @sortedId = ();
    read_fwqos;

    foreach my $lines (@qosrules) {
       my ($ifInt, $src, $dst, $fwTarg, $auxlines) = split(/\s+/, $lines, 5);
       my $qcbytes = "0:0", $qcpkts = "0", $qclimit = "0/32", $qlength = "0:0", $qgeoip = "any";
       my $nDpi = "none";

       if ($auxlines && $auxlines ne "") {
          $auxlines = " $auxlines";
          ($fCond, $fDesc) = split /\s/, getCondDesc($auxlines), 2;
       }
       else {
          $fCond = "none";
          $fDesc = "";
       }
       $src = "any" if ($src eq "0/0" || $src eq "");
       $dst = "any" if ($dst eq "0/0" || $dst eq "");

       # Ingress options
       my $qRate = "0Kbit";
       my $qBurst = "0";
       if ($fwTarg eq "INGRESS" || ($fwTarg =~ /^(IN|TC)-IGNORE$/ && $auxlines =~ /(^|[ |\t]*)[kmgKMG]bit( |\t|$)/)) {
          (undef, $qRate, undef) = split(/\s+/, $auxlines, 2);
          ($qRate, undef) = split /[\s]+/, $qRate;
          if ($auxlines =~ /[\s]burst=/) {
             (undef, $qBurst) = split /[\s]burst=/, $auxlines;
             ($qBurst, undef) = split /[\s]+/, $qBurst;
          }

          if ($qRate eq "") {
             $qRate = "0Kbit";
             $qBurst = "0";
          }
       }

       # Getting proto (dport or sport) def
       my ($proto, $sport, $dport) = split /\//, getports($auxlines);

       # Getting nf limits
       if ($auxlines =~ /[\s](conn(bytes|pkts|limit)|length|geoip|ndpi)=/) {
          if ($auxlines =~ /[\s]connbytes=/) {
             (undef, $qcbytes) = split /[\s]connbytes=/, $auxlines;
             ($qcbytes, undef) = split /[\s]+/, $qcbytes;
          }
          elsif ($auxlines =~ /[\s]connpkts=/) {
             (undef, $qcpkts) = split /[\s]connpkts=/, $auxlines;
             ($qcpkts, undef) = split /[\s]+/, $qcpkts;
          }
          if ($auxlines =~ /[\s]connlimit=/) {
             (undef, $qclimit) = split /[\s]connlimit=/, $auxlines;
             ($qclimit, undef) = split /[\s]+/, $qclimit;
          }
          if ($auxlines =~ /[\s]length=/) {
             (undef, $qlength) = split /[\s]length=/, $auxlines;
             ($qlength, undef) = split /[\s]+/, $qlength;
          }
          if ($auxlines =~ /[\s]geoip=/) {
             (undef, $qgeoip) = split /[\s]geoip=/, $auxlines;
             ($qgeoip, undef) = split /[\s]+/, $qgeoip;
          }
          if ($auxlines =~ /[\s]ndpi=/) {
             (undef, $nDpi) = split /[\s]ndpi=/, $auxlines;
             ($nDpi, undef) = split /[\s]+/, $nDpi;
          }
       }

       my $auxentry = "{\"id\":\"$total\",\"cell\":[\"$total\", \"$ifInt\", \"$src\", \"$dst\", \"$fwTarg\", \"$qRate\", \"$qBurst\", \"$proto\", \"$sport\", \"$dport\", \"$qcbytes\", \"$qcpkts\", \"$qclimit\", \"$qlength\", \"$qgeoip\", \"$nDpi\", \"$fCond\", \"$fDesc\"]}";

       push(@sortedId, $auxentry);
       $total++;
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    $total = 1;
    foreach my $line (@sortedId) {
       $line = ",\n$line" if ($total > 1);
       $json = "$json $line";
       $total++;
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Get tfshape.conf defs (for egressrules)
sub get_QosEgressRl {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $jsct = 0;
    my $total = 1;
    my $stid = 0;
    my @sortedId = ();
    read_fwqos;

    foreach my $qRules (@qosegress) {
       my $parent = "";
       my (undef, $group, undef) = split /\s+/, $qRules, 3;
       foreach my $lines (@{$qosegressrules{"$group"}}) {
          my ($ifInt, $src, $dst, $fwTarg, $auxlines) = split(/\s+/, $lines, 5);
          my $qcbytes = "0:0", $qcpkts = "0", $qclimit = "0/32", $qlength = "0:0", $qgeoip = "any";
          my $nDpi = "none";

          if ($auxlines && $auxlines ne "") {
             $auxlines = " $auxlines";
             ($fCond, $fDesc) = split /\s/, getCondDesc($auxlines), 2;
          }
          else {
             $fCond = "none";
             $fDesc = "";
          }
          $src = "any" if ($src eq "0/0" || $src eq "");
          $dst = "any" if ($dst eq "0/0" || $dst eq "");

          # Getting proto (dport or sport) def
          my ($proto, $sport, $dport) = split /\//, getports($auxlines);

          # Getting nf limits
          if ($auxlines =~ /[\s](conn(bytes|pkts|limit)|length|geoip|ndpi)=/) {
             if ($auxlines =~ /[\s]connbytes=/) {
                (undef, $qcbytes) = split /[\s]connbytes=/, $auxlines;
                ($qcbytes, undef) = split /[\s]+/, $qcbytes;
             }
             elsif ($auxlines =~ /[\s]connpkts=/) {
                (undef, $qcpkts) = split /[\s]connpkts=/, $auxlines;
                ($qcpkts, undef) = split /[\s]+/, $qcpkts;
             }
             if ($auxlines =~ /[\s]connlimit=/) {
                (undef, $qclimit) = split /[\s]connlimit=/, $auxlines;
                ($qclimit, undef) = split /[\s]+/, $qclimit;
             }
             if ($auxlines =~ /[\s]length=/) {
                (undef, $qlength) = split /[\s]length=/, $auxlines;
                ($qlength, undef) = split /[\s]+/, $qlength;
             }
             if ($auxlines =~ /[\s]geoip=/) {
                (undef, $qgeoip) = split /[\s]geoip=/, $auxlines;
                ($qgeoip, undef) = split /[\s]+/, $qgeoip;
             }
             if ($auxlines =~ /[\s]ndpi=/) {
                (undef, $nDpi) = split /[\s]ndpi=/, $auxlines;
                ($nDpi, undef) = split /[\s]+/, $nDpi;
             }
          }

          my ($parent, $classid) = split /\->/, $group;
          if ($parent ne "") {
             my $auxentry = "{\"id\":\"$total\",\"cell\":[\"$total\", \"$parent\", \"$classid\", \"$ifInt\", \"$src\", \"$dst\", \"$fwTarg\", \"$proto\", \"$sport\", \"$dport\", \"$qcbytes\", \"$qcpkts\", \"$qclimit\", \"$qlength\", \"$qgeoip\", \"$nDpi\", \"$fCond\", \"$fDesc\"]}";

             push(@sortedId, $auxentry);
             $total++;
          }
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    $total = 1;
    foreach my $line (@sortedId) {
       $line = ",\n$line" if ($total > 1);
       $json = "$json $line";
       $total++;
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Get tfshow bandwidth
sub get_tfdata {
    use CGI qw(:standard);
    use HTTP::Response;

    # Getting filters
    CGI::Session->name("FWGSESS");
    my $session = CGI::Session->load(undef, $read_cookie, {Directory=>'/tmp/sessions'});

    my $iface = undef;
    my $capfilter = undef;

    # Session checks
    if($session->is_expired || $session->is_empty) {
       $session->delete;
    }
    else {
       $iface = $session->param('iface');
       $capfilter = $session->param('capfilter');
    }
    $session->flush;
    $session->close;

    # Default filters
    $iface = "any" if (not $iface);
    $capfilter = "net 0.0.0.0/0" if (not $capfilter);

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = "";

    # Json header (no mandatory)
    #$res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    $json = `$FW_DIR/modules/tools/tfshow/tfshow -i $iface -f \"$capfilter\" -j 2>/dev/null` if ( -e "$FW_DIR/modules/tools/tfshow/tfshow" );
    $json = "[[\"1\",\"No data\",\"\",\"#\",\"No data\"]]" if ($json eq "");

    # Json content
    $res->content_type("text/html");
    $res->content($json);
    return $res;
}

# Getting interfaces data
sub get_interfacesJs {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;
    read_fwcfg;
    read_interfaces;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my $stid = 0;
    my @unsortId = ();
    my %unsortData = ();

    if (-e "$file_cfg{'interfaces'}") {
       foreach my $auxlines (@fwinterfaces) {
           my ($opt1, $opt2, $opt3, $opt4, $opt5, $opt6, $opt7, $opt8, $opt9, $opt10, $opt11, $fDesc) = split(/\s+/, $auxlines, 12);

           my $aux10 = $opt10;
           my $aux11 = $opt11;
           $opt10 = "No";
           $opt11 = "No";
           $opt10 = "Yes" if ($aux10 eq "1");
           $opt11 = "Yes" if ($aux11 eq "1");
           $fDesc =~ s/(\s)+$//;
           my $auxentry = "{\"id\":\"$total\",\"cell\":[\"$total\", \"$opt1\", \"$opt2\", \"$opt3\", \"$opt4\", \"$opt5\", \"$opt6\", \"$opt7\", \"$opt8\", \"$opt9\", \"$opt10\", \"$opt11\", \"$fDesc\"]}";
           $total++;

           # Using array and hash vars for *sort control*
           if ($sortid eq "$opt1") {
              push(@unsortId, $opt1) if (!findId(\@unsortId, $opt1));
              push(@{$unsortData{$opt1}}, $auxentry);
           }
           else {
              push(@unsortId, $total) if (!findId(\@unsortId, $total));
              push(@{$unsortData{$total}}, $auxentry);
              $stid = 1;
           }
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    my @sortedId = ();
    if ($sortd eq "asc") {
       if ($stid == 0) { @sortedId = sort(@unsortId); }
       else { @sortedId = sort { $a <=> $b } @unsortId; }
    }
    else {
       if ($stid == 0) { @sortedId = reverse sort (@unsortId); }
       else { @sortedId = reverse sort { $a <=> $b } @unsortId; }
    }

    $total = 1;
    foreach (@sortedId) {
       foreach my $line (@{$unsortData{"$_"}}) {
          $line = ",\n$line" if ($total > 1);
          $json = "$json $line";
          $total++;
       }
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Getting webalias data
sub get_aliasJs {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;
    read_fwcfg;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my $stid = 0;
    my @unsortId = ();
    my %unsortData = ();

    if (-e "$file_cfg{'alias'}") {
       foreach my $auxlines (@webalias) {
          my (undef, $aName, $aValue, $fDesc) = split(/\s/, $auxlines, 4);

          $fDesc =~ s/(\s)+(\#.*|webalias(\s)*$)//;
          $fDesc =~ s/(\s)+$//;
          my $auxentry = "{\"id\":\"$total\",\"cell\":[\"$total\", \"$aName\", \"$aValue\", \"$fDesc\"]}";
          $total++;

          # Using array and hash vars for *sort control*
          if ($sortid eq "aName") {
             push(@unsortId, $aName) if (!findId(\@unsortId, $aName));
             push(@{$unsortData{$aName}}, $auxentry);
          }
          elsif ($sortid eq "aValue") {
             push(@unsortId, $aValue) if (!findId(\@unsortId, $aValue));
             push(@{$unsortData{$aValue}}, $auxentry);
          }
          else {
             push(@unsortId, $total) if (!findId(\@unsortId, $total));
             push(@{$unsortData{$total}}, $auxentry);
             $stid = 1;
          }
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    my @sortedId = ();
    if ($sortd eq "asc") {
       if ($stid == 0) { @sortedId = sort(@unsortId); }
       else { @sortedId = sort { $a <=> $b } @unsortId; }
    }
    else {
       if ($stid == 0) { @sortedId = reverse sort (@unsortId); }
       else { @sortedId = reverse sort { $a <=> $b } @unsortId; }
    }

    $total = 1;
    foreach (@sortedId) {
       foreach my $line (@{$unsortData{"$_"}}) {
          $line = ",\n$line" if ($total > 1);
          $json = "$json $line";
          $total++;
       }
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Getting firewall rules (INPUT or FORWARD)
sub get_fwruleJs {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;
    my $fwtype = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # 1. fwinput or routing/fwroute.rules path
    # 2. rule file (fwtype = fwinput or routing/fwroute.rules)
    # 3. other info: @gpauthrule, @inputcomments and @routecomments

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my @sortedId = ();

    if ($fwtype eq "fwinput") {
       read_fwrules("input");
       @auxrule = @inputfw;
    }
    else {
       read_fwrules("route");
       @auxrule = @routefw;
       push(@auxrule, @gpauthfw);
    }

    foreach (@auxrule) {
        my $ruNew = "none", $ruDst="", $fwTarg="", $auxrule2="";
        my $ruGuaran = "No", $ruState = "No", $NatType = "none", $ruTrack = "Yes", $ruIfOut = "Any", $ruLog = "";
        my ($ruPol, $ruIf, $ruSrc, $auxrule2) = split(/[\s]+/, $_, 4);
        ($ruDst, $fwTarg, $auxrule2) = split(/[\s]+/, $auxrule2, 3);
        
        if ($fwtype eq "fwinput") {
           my @fwaux = ("%A", "ACCEPT", "%D", "DROP", "%R", "REJECT");
           foreach (@fwaux, @fwprof) {
              $_ =~ s/\n//;
              if ($ruDst eq $_) {
                 $auxrule2 = "$ruDst $fwTarg $auxrule2";
                 $fwTarg = $ruDst;
                 $ruDst = "any";
                 last;
              }
           }
        }
        $auxrule2 = " $auxrule2";

        # Target convert
        if ($fwTarg =~ /^%(A|D|R)$/) {
           if ($fwTarg eq "%A") { $fwTarg = "ACCEPT"; }
           elsif ($fwTarg eq "%D") { $fwTarg = "DROP"; }
           else { $fwTarg = "REJECT"; }
        }
        $fwTarg="IGNORE" if ($fwTarg eq "RETURN") ;

        # Getting options
        $ruNew = "No" if ($auxrule2 =~ /[\s]nonew([\s]*|$)/);
        $ruNew = "Yes" if ($auxrule2 =~ /[\s](new|start)([\s]*|$)/);
        if ($fwtype eq "fwroute") {
           if ($auxrule2 =~ /[\s](insert|guaranteed|stateless|masq|notrack|autosnat)([\s]*|$)/) {
              $ruGuaran = "Yes" if ($auxrule2 =~ /[\s](insert|guaranteed)([\s]*|$)/);
              $ruState = "Yes" if ($auxrule2 =~ /[\s](stateless)([\s]*|$)/);
              if ($auxrule2 =~ /[\s](masq|autosnat)([\s]*|$)/) {
                 $NatType = "MASQ";
                 $NatType = "AUTO" if ($auxrule2 =~ /[\s](autosnat)([\s]*|$)/);
              }
              $ruTrack = "No" if ($auxrule2 =~ /[\s](notrack)([\s]*|$)/);
           }
           ($ruIf, $ruIfOut) = split/->/, $ruIf;
           $ruIfOut = "any" if (!$ruIfOut);
        }
        my ($fCond, $fDesc) = split /\s/, getCondDesc($auxrule2), 2;
        (undef, $ruLog) = split /[\s]log=|[\s]log-desc=/, $auxrule2;
        (undef, $ruLog) = split /[\"|\']/, $ruLog;
        if ($ruLog) {
           $ruLog =~ s/\n//;
           $ruLog =~ s/[\"'\\]//g;
        }

        # Getting proto (dport or sport) def
        my ($proto, $sport, $dport) = split /\//, getports($auxrule2);

        if (not ($ruIf eq "set-policy" )) {
           $ruPol =~ s/:/>/;
           my $auxentry = "\"$total\",\"$ruPol\",\"$ruIf\", \"$ruSrc\"";
           if ($fwtype eq "fwroute") {
              $auxentry = "$auxentry,\"$ruIfOut\",\"$ruDst\",\"$fwTarg\",\"$proto\",\"$sport\",\"$dport\",\"$ruNew\",\"$ruGuaran\",\"$ruState\", \"$ruTrack\",\"$fCond\",\"$NatType\",\"$ruLog\",\"$fDesc\"";
           }
           else {
              $auxentry = "$auxentry,\"$ruDst\",\"$fwTarg\",\"$proto\",\"$dport\",\"$ruNew\",\"$fCond\",\"$fDesc\"";
           }
           $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
           $total++;

           push(@sortedId, $auxentry);
        }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    $total = 1;
    foreach my $line (@sortedId) {
       $line = ",\n$line" if ($total > 1);
       $json = "$json $line";
       $total++;
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Getting fwhosts data
sub get_fwhostsJs {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my $stid = 0;
    my @unsortId = ();
    my %unsortData = ();
    read_fwhosts;

    foreach my $lines (@fwhostrules) {
       my ($hName, $hSrc, $hMac, $hProf, $auxrule) = split(/[\s]+/, $lines, 5);
       my $hLog = "No", $hProtect = "No", $hNobanned = "No";
       my $hLogDesc = "";

       # Target convert
       if ($hProf =~ /^%(A|D|R)$/) {
          if ($hProf eq "%A") { $fwTarg = "ACCEPT"; }
          elsif ($hProf eq "%D") { $fwTarg = "DROP"; }
          else { $hProf = "REJECT"; }
       }

       $auxrule = " $auxrule"; 
       if ($auxrule =~ /[\s](log|protect|nobanned)([\s]*|$)/) {
          $hLog = "Yes" if ($auxrule =~ /[\s]log([\s]*|$)/);
          $hProtect = "Yes" if ($auxrule =~ /[\s]protect([\s]*|$)/);
          $hNobanned = "Yes" if ($auxrule =~ /[\s]nobanned([\s]*|$)/);
       }

       my ($fCond, $fDesc) = split /\s/, getCondDesc($auxrule), 2;
       (undef, $hLogDesc) = split /[\s]log-desc=/, $auxrule;
       (undef, $hLogDesc) = split /[\"|\']/, $hLogDesc;
       if ($hLogDesc) {
          $hLogDesc =~ s/\n//;
          $hLogDesc =~ s/[\"'\\]//g;
       }

       my $auxentry = "\"$total\", \"$hName\", \"$hSrc\", \"$hMac\", \"$hProf\", \"$hLog\", \"$hProtect\", \"$hNobanned\", \"$fCond\", \"$hLogDesc\", \"$fDesc\"";
       $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
       $total++;

       # Using array and hash vars for *sort control*
       if ($sortid eq "hName") {
          push(@unsortId, $hName) if (!findId(\@unsortId, $hName));
          push(@{$unsortData{$hName}}, $auxentry);
       }
       elsif ($sortid eq "hSrc") {
          push(@unsortId, $hSrc) if (!findId(\@unsortId, $hSrc));
          push(@{$unsortData{$hSrc}}, $auxentry);
       }
       elsif ($sortid eq "hMac") {
          push(@unsortId, $hMac) if (!findId(\@unsortId, $hMac));
          push(@{$unsortData{$hMac}}, $auxentry);
       }
       else {
          push(@unsortId, $total) if (!findId(\@unsortId, $total));
          push(@{$unsortData{$total}}, $auxentry);
          $stid = 1;
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    my @sortedId = ();
    if ($sortd eq "asc") {
       if ($stid == 0) { @sortedId = sort(@unsortId); }
       else { @sortedId = sort { $a <=> $b } @unsortId; }
    }
    else {
       if ($stid == 0) { @sortedId = reverse sort (@unsortId); }
       else { @sortedId = reverse sort { $a <=> $b } @unsortId; }
    }

    $total = 1;
    foreach (@sortedId) {
       foreach my $line (@{$unsortData{"$_"}}) {
          $line = ",\n$line" if ($total > 1);
          $json = "$json $line";
          $total++;
       }
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Getting fwmsn data
sub get_fwmsnJs {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my $stid = 0;
    my @unsortId = ();
    my %unsortData = ();
    read_fwmsn;

    foreach my $lines (@fwmsnrules) {
       my ($mSrc, $mEmail, $auxrule) = split(/[\s]+/, $lines, 3);

       my $mForce = "No", $Disa = "No";
       $auxrule = " $auxrule"; 
       $mForce = "Yes" if ($auxrule =~ /[\s]*force([\s]|$)/);
       $Disa = "Yes" if ($auxrule =~ /[\s]*disabled([\s]|$)/);
       my (undef, $fDesc) = split /\s/, getCondDesc($auxrule), 2;

       my $auxentry = "\"$total\", \"$mSrc\", \"$mEmail\", \"$mForce\", \"$Disa\", \"$fDesc\"";
       $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
       $total++;

       # Using array and hash vars for *sort control*
       if ($sortid eq "mSrc") {
          push(@unsortId, $mSrc) if (!findId(\@unsortId, $mSrc));
          push(@{$unsortData{$mSrc}}, $auxentry);
       }
       elsif ($sortid eq "mEmail") {
          push(@unsortId, $mEmail) if (!findId(\@unsortId, $mEmail));
          push(@{$unsortData{$mEmail}}, $auxentry);
       }
       else {
          push(@unsortId, $total) if (!findId(\@unsortId, $total));
          push(@{$unsortData{$total}}, $auxentry);
          $stid = 1;
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    my @sortedId = ();
    if ($sortd eq "asc") {
       if ($stid == 0) { @sortedId = sort(@unsortId); }
       else { @sortedId = sort { $a <=> $b } @unsortId; }
    }
    else {
       if ($stid == 0) { @sortedId = reverse sort (@unsortId); }
       else { @sortedId = reverse sort { $a <=> $b } @unsortId; }
    }

    $total = 1;
    foreach (@sortedId) {
       foreach my $line (@{$unsortData{"$_"}}) {
          $line = ",\n$line" if ($total > 1);
          $json = "$json $line";
          $total++;
       }
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

sub get_FeSetJS {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;
    read_fwcfg;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my $stid = 0;
    my @unsortId = ();
    my %unsortData = ();

    if (-e "$file_cfg{'webauth/filedit.conf'}") {
       open DFILE, "<$file_cfg{'webauth/filedit.conf'}";
       while (<DFILE>) {
        if ($_ !~ /^[\s]*(#|;|$)/) {
          my $feType = "textbox";
          my $feName = "", $fDesc = "", $auxrule = "";
          ($feName, $fDesc, $feType, $auxrule) = split(/[\s]+/, $_, 4);

          if ($fDesc) {
             $fDesc =~ s/\n//;
             $fDesc =~ s/[\"'\\]//g;
             $fDesc =~ s/_/ /g;
          }
          $auxrule =~ s/\n//;
          $auxrule = " $auxrule";
          my $Disa = "No";
          if ($auxrule =~ /[\s]_ignore_([\s]|$)/) {
             $Disa = "Yes";
             $auxrule =~ s/_ignore_[\s]+//;
          }
          my $feCmd = $auxrule;

          my $auxentry = "\"$total\", \"$feName\", \"$fDesc\", \"$Disa\", \"$feType\", \"$feCmd\"";
          $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
          $total++;

          # Using array and hash vars for *sort control*
          if ($sortid eq "feName") {
             push(@unsortId, $feName) if (!findId(\@unsortId, $feName));
             push(@{$unsortData{$feName}}, $auxentry);
          }
          elsif ($sortid eq "feType") {
             push(@unsortId, $feType) if (!findId(\@unsortId, $feType));
             push(@{$unsortData{$feType}}, $auxentry);
          }
          elsif ($sortid eq "Disa") {
             push(@unsortId, $Disa) if (!findId(\@unsortId, $Disa));
             push(@{$unsortData{$Disa}}, $auxentry);
          }
          else {
             push(@unsortId, $total) if (!findId(\@unsortId, $total));
             push(@{$unsortData{$total}}, $auxentry);
             $stid = 1;
          }
        }
       }
       close (DFILE);
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    my @sortedId = ();
    if ($sortd eq "asc") {
       if ($stid == 0) { @sortedId = sort(@unsortId); }
       else { @sortedId = sort { $a <=> $b } @unsortId; }
    }
    else {
       if ($stid == 0) { @sortedId = reverse sort (@unsortId); }
       else { @sortedId = reverse sort { $a <=> $b } @unsortId; }
    }

    $total = 1;
    foreach (@sortedId) {
       foreach my $line (@{$unsortData{"$_"}}) {
          $line = ",\n$line" if ($total > 1);
          $json = "$json $line";
          $total++;
       }
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

sub get_FwMasqJS {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my $stid = 0;
    my @unsortId = ();
    my %unsortData = ();
    read_fwmasq;

    foreach my $lines (@fwmasqrules) {
       my $mSrc = "", $mDefProf = "none" , $mLimProf = "none", $auxrule = "";
       my $mSrcIf = "", $mDstIf = "", $mpHttp = "", $mpPop3 = "", $mdHttp = "No", $mTrans = "No", $NatType = "MASQ";
       ($mif, $mSrc, $auxrule) = split(/[\s]+/, $lines, 3);

       $auxrule =~ s/\n//;
       $auxrule = " $auxrule";
       ($mSrcIf, $mDstIf) = split(/->/, $mif, 2);

       # Getting options
       if ($auxrule =~ /[\s](denyhttp|redirect|nomasq|autosnat)([\s]*|$)/) {
          $mdHttp = "Yes" if ($auxrule =~ /[\s]denyhttp([\s]*|$)/);
          $mTrans = "Yes" if ($auxrule =~ /[\s]redirect([\s]*|$)/);
          $NatType = "MASQ";
          $NatType = "none" if ($auxrule =~ /[\s]nomasq([\s]*|$)/);
          $NatType = "AUTO" if ($auxrule =~ /[\s]autosnat([\s]*|$)/);
       }
       (undef, $fCond) = split /[\s]chk=/, $auxrule;
       (undef, $mpHttp) = split /[\s]proxyport=/, $auxrule;
       (undef, $mpPop3) = split /[\s]p3scan=/, $auxrule;
       if ($auxrule =~ /[\s]defprof=/) {
          (undef, $mDefProf) = split /[\s]defprof=/, $auxrule;
          ($mDefProf) = split /\s/, $mDefProf if ($mDefProf);
       }
       if ($auxrule =~ /[\s]limitprof=/) {
          (undef, $mLimProf) = split /[\s]limitprof=/, $auxrule;
          ($mLimProf) = split /\s/, $mLimProf if ($mLimProf);
       }
       my ($fCond, $fDesc) = split /\s/, getCondDesc($auxrule), 2;
       ($mpHttp) = split /\s/, $mpHttp if ($mpHttp);
       ($mpPop3) = split /\s/, $mpPop3 if ($mpPop3);

       my $auxentry = "\"$total\", \"$mSrcIf\", \"$mDstIf\", \"$mSrc\", \"$mpHttp\", \"$mTrans\", \"$mdHttp\", \"$mpPop3\", \"$fCond\" , \"$mDefProf\", \"$mLimProf\", \"$NatType\", \"$fDesc\"";
       $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
       $total++;

       # Using array and hash vars for *sort control*
       if ($sortid eq "mSrc") {
          push(@unsortId, $mSrc) if (!findId(\@unsortId, $mSrc));
          push(@{$unsortData{$mSrc}}, $auxentry);
       }
       elsif ($sortid eq "mpHttp") {
          push(@unsortId, $mpHttp) if (!findId(\@unsortId, $mpHttp));
          push(@{$unsortData{$mpHttp}}, $auxentry);
       }
       elsif ($sortid eq "mpPop3") {
          push(@unsortId, $mpPop3) if (!findId(\@unsortId, $mpPop3));
          push(@{$unsortData{$mpPop3}}, $auxentry);
       }
       else {
          push(@unsortId, $total) if (!findId(\@unsortId, $total));
          push(@{$unsortData{$total}}, $auxentry);
          $stid = 1;
       }
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    my @sortedId = ();
    if ($sortd eq "asc") {
       if ($stid == 0) { @sortedId = sort(@unsortId); }
       else { @sortedId = sort { $a <=> $b } @unsortId; }
    }
    else {
       if ($stid == 0) { @sortedId = reverse sort (@unsortId); }
       else { @sortedId = reverse sort { $a <=> $b } @unsortId; }
    }

    $total = 1;
    foreach (@sortedId) {
       foreach my $line (@{$unsortData{"$_"}}) {
          $line = ",\n$line" if ($total > 1);
          $json = "$json $line";
          $total++;
       }
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Getting fwroute.tables *link* data
sub get_advLkrouteJs {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my @sortedId = ();
    read_advroute;

    foreach my $lines (@advroutelink) {
       my ($arIf, $Dst, $arGw, $arName, $arDGD, $auxrule) = split(/[\s]+/, $lines, 6);
       my $arPrio = "", $arRpdb = "default", $arFail = "none";
       my $arLbgp = "none", $arFogp = "none", $fDesc = "", $fCond = "none";

       $auxrule = " $auxrule";
       $arRpdb = "only-table" if ($auxrule =~ /[\s](onlytb|only-table)([\s]*|$)/);
       $arRpdb = "only-iproute" if ($auxrule =~ /[\s](only-iproute|nofwroute)([\s]*|$)/);
       foreach my $auxrule2 (split /\s/, $auxrule) {
          if ($auxrule2 =~ /^onfail\-/) {
             $arFail = $auxrule2;
             $arFail =~ s/onfail\-//;
          }
          elsif ($auxrule2 =~ /^prio=/) {
            (undef, $arPrio) = split /prio=/, $auxrule2;
          }
          elsif ($auxrule2 =~ /^lbgroup=/) {
            (undef, $arLbgp) = split /lbgroup=/, $auxrule2;
          }
          elsif ($auxrule2 =~ /^fogroup=/) {
            (undef, $arFogp) = split /fogroup=/, $auxrule2;
          }
          elsif ($auxrule2 =~ /^chk=/) {
            (undef, $fCond) = split /^chk=/, $auxrule2;
            $fCond = "none" if (not $fCond);
          }
       }
       (undef, $fDesc) = split /[\s]desc=/, $auxrule;
       (undef, $fDesc) = split /[\"|\']/, $fDesc;
       if ($fDesc ) {
          $fDesc =~ s/\n//;
          $fDesc =~ s/[\"'\\]//g;
       }

       my $arDefaults = "";
       if ($fCond ne "disabled") {
          $arDefaults = "green";
          $arDefaults = "red" if (-e "/tmp/tb-$arName.down" || -e "/tmp/tb-$arName.warn");
       }

       my $auxentry = "\"$total\", \"$arName\", \"$arIf\", \"$Dst\", \"$arGw\", \"$arDGD\", \"$arPrio\", \"$arRpdb\", \"$arFail\", \"$arLbgp\", \"$arFogp\", \"$fCond\", \"$fDesc\", \"$arDefaults\"";
       $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
       $total++;

       push(@sortedId, $auxentry);
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    $total = 1;
    foreach my $line (@sortedId) {
       $line = ",\n$line" if ($total > 1);
       $json = "$json $line";
       $total++;
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Getting fwroute.tables *policy* data
sub get_advRlrouteJs {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my @sortedId = ();
    read_advroute;

    foreach my $lines (@advrouterules) {
       my $arIfOut = "Any";
       my $arNat = "none";
       my ($Group, $arIf, $Src, $Dst, $arName, $auxrule) = split(/[\s]+/, $lines, 6);

       $auxrule = " $auxrule";

       ($arIf, $arIfOut) = split/->/, $arIf;
       $arIfOut = "any" if (!$arIfOut);
       if ($auxrule =~ /[\s](masq|autosnat)([\s]*|$)/) {
          $arNat = "MASQ";
          $arNat = "AUTO" if ($auxrule =~ /[\s](autosnat)([\s]*|$)/);
       }
       my ($fCond, $fDesc) = split /\s/, getCondDesc($auxrule), 2;

       # Getting proto (dport or sport) def
       my ($proto, $sport, $dport) = split /\//, getports($auxrule);

       my $arDefaults = "";
       if ($fCond ne "disabled") {
          $arDefaults = "green";
          $arDefaults = "#888888" if (-e "/tmp/tb-$arName.warn");
          $arDefaults = "red" if (-e "/tmp/tb-$arName.down");
       }
       $Src = "any" if ($Src eq "0/0");
       $Dst = "any" if ($Dst eq "0/0");
       $arIf = "any" if ($arIf eq "none");

       my $auxentry = "\"$total\", \"$Group\", \"$arIf\", \"$Src\", \"$arIfOut\", \"$Dst\", \"$arName\", \"$proto\", \"$sport\", \"$dport\", \"$fCond\", \"$arNat\", \"$fDesc\", \"$arDefaults\"";
       $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
       $total++;

       push(@sortedId, $auxentry);
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    $total = 1;
    foreach my $line (@sortedId) {
       $line = ",\n$line" if ($total > 1);
       $json = "$json $line";
       $total++;
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

# Getting cluster settings
sub get_clusterJs {
    use CGI qw(:standard);
    use HTTP::Response;
    my $url = shift;
    my $aux_clgroup = shift;

    # Define URL refresh
    $res = HTTP::Response->new();

    # Json output
    my $json = undef;

    # Getting page params
    my ($page, $sortid, $sortd) = split /\s/, getPageOpt($url);

    my $total = 1;
    my @sortedId = ();
    read_cluster;

    foreach my $lines (@{$clrules{"$aux_clgroup"}}) {
       my $auxentry="";
       my $fDesc = "", $fCond = "none";
       my $opt1 = "", $opt2 = "", $opt3 = "", $opt4 = "", $opt5="", $opt6="", $auxlines = "";
       if ($aux_clgroup eq "interface") {
          ($opt1, $opt2, $opt3, $opt4, $auxlines) = split(/\s+/, $lines, 5);
          $opt4 = "any" if ($opt1 eq "monitor");

          $auxentry = "\"$total\", \"$aux_clgroup\", \"$opt1\", \"$opt2\", \"$opt3\", \"$opt4\"";
       }
       elsif ($aux_clgroup eq "vipconf") {
          ($opt1, $opt2, $opt3, $opt4, $opt5, $opt6, $auxlines) = split(/\s+/, $lines, 7);

          $auxentry = "\"$total\", \"$aux_clgroup\", \"$opt1\", \"$opt2\", \"$opt3\", \"$opt4\", \"$opt5\", \"$opt6\"";
       }
       elsif ($aux_clgroup eq "vipaddr") {
          ($opt1, $opt2, $opt3, $auxlines) = split(/\s+/, $lines, 4);

          $auxentry = "\"$total\", \"$aux_clgroup\", \"$opt1\", \"$opt2\", \"$opt3\"";
       }


       if ($auxlines && $auxlines ne "") {
          $auxlines = " $auxlines";
          ($fCond, $fDesc) = split /\s/, getCondDesc($auxlines), 2;
       }
       else {
          $fCond = "none";
          $fDesc = "";
       }

       $auxentry = "$auxentry, \"$fCond\", \"$fDesc\"";
       $auxentry = "{\"id\":\"$total\",\"cell\":[$auxentry]}";
       push(@sortedId, $auxentry);
       $total++;
    }

    # Json header
    $res->header('Content-Type' => 'application/json');
    $res->header('Cache-Control' => 'no-cache, must-revalidate');

    # Json content
    $total = 1;
    foreach my $line (@sortedId) {
       $line = ",\n$line" if ($total > 1);
       $json = "$json $line";
       $total++;
    }
    $json = json_out($total, $json, $page, 'rows');
    $res->content($json);
    return $res;
}

return 1;
