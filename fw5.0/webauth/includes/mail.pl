#!/usr/bin/perl

#Rev.0 - Version 5.0

# Return msg in mail server timeout
sub smtpFailConn {
    my @msg = ("", "");
    $msg[0] = "Não foi possível conectar ao servidor SMTP!";
    $msg[1] = "Could not connect to SMTP server!";
    return get_forbidden("$msg[$FW_LANG]", "", "");
}

# Send mail with Net::SMTP
sub sendmail {
   my $s = shift;
   my $where = shift;
   my $peer = shift;
   my @msg = ("", "");
   my @txtvalue = ("", "");

   my @dvalue = ();
   my $res = HTTP::Response->new();

   if ($allowmail == 1) {
      foreach my $lines (split /&/, $s) {
         $lines = str_conv($lines);
         $lines =~ s/\+/ /g if ($lines =~ /\+/);
         @dvalue = split /=/, $lines;

         if ($dvalue[0] eq "name") {
            $name = $dvalue[1];
            $complet++ if ($dvalue[1]);
         }
         elsif ($dvalue[0] eq "mail") {
            $mail = $dvalue[1];
            $complet++ if ($dvalue[1]);
         }
         elsif ($dvalue[0] eq "mailmsg") {
            $mailmsg = $dvalue[1];
            $complet++ if ($dvalue[1]);
         }
      }

      # Send the mail message
      if ($complet > 2) {
         $smtp = Net::SMTP->new("$MAILSERVER", Timeout => 15);
         return smtpFailConn() unless $smtp;
         #$smtp->mail($ENV{USER});
         $smtp->mail("$mail");
         $smtp->to("$MAILACCOUNT");
         $smtp->data();
         $smtp->datasend("From: $mail\n");
         $smtp->datasend("To: $MAILACCOUNT\n");
         $smtp->datasend("Subject: Contact wifizone");
         $smtp->datasend("\n");
         $smtp->datasend("Sender\nIP - $peer\n");
         $smtp->datasend("Name - $name\n\n");
         $smtp->datasend("$mailmsg\n");
         $smtp->dataend();
         $smtp->quit;

         $msg[0] = "Email enviado com sucesso!";
         $msg[1] = "Mail sent successfully!";
         if ($where ne "admin") {
            $res = get_file("text/html", "$HTMLDIR/email_ok.html");
            ${$res->content_ref} =~ s/MESSAGE/$msg[$FW_LANG]/;
            return $res;
         }
         $txtvalue[$FW_LANG] = msgbox("info", "$msg[$FW_LANG]", "");
      }
      else {
         $txtvalue[0] = "Dados incompletos!";
         $txtvalue[1] = "Incomplet data!";
         $msg[0] = "<font color=\"red\"><i>Todos os campos são obrigatórios</i></font>";
         $msg[1] = "<font color=\"red\"><i> - All fields are required</i></font>";
         if ($where ne "admin") {
            return get_forbidden("$txtvalue[$FW_LANG]<BR /><BR />$msg[$FW_LANG]", "", "");
         }
         $txtvalue[$FW_LANG] = msgbox("denied", "$txtvalue[$FW_LANG]", "$msg[$FW_LANG]");
      }
   }
   else {
      return mailNotFound();
   }

   my $meta = "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"3;URL=/\"><META http-equiv=\"content-type\" content=\"text/html;charset=utf-8\"></head>";
   $txtvalue[$FW_LANG] = "<html>$meta<body bgcolor=\"#bec2c8\" $STYLE>$txtvalue[$FW_LANG]</body></html>";
   $res->content($txtvalue[$FW_LANG]);
   $res->content_type("text/html");
   return $res;
}

return 1;
