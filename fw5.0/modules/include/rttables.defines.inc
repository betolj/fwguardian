#!/bin/igawk
{
  if (match($1,"^(set|define|create|test-dgd|alias)")) {

    if ($1 == "alias") fwalias("make", "rttables");
    else {
       setpol_nf=0;
       setpol_rpdb=0;
       setrt_links=0;

       if ($1 == "set-policy") {
          disabled=0;
          disabledpol=0;
          disabledpol=fwalias("chkperm", "rttables");
          if (!disabledpol) {
             if ($2 == "netfilter" || $2 == "firewall") setpol_nf=1;
             else if ($2 == "iproute" || $2 == "route") {
                setpol_rpdb=1;
             }
          }
       }
       else if ($1 == "set-link") {
          fwr=0;
          setrt_links=1;
       }
       else if ($1 == "set-condition") fwalias("mkperm", "rttables");
    }

    ### Settings
    if ($1 == "set") {

      ## Network address table lookup (by source)
      if ($2 == "route.source") {
	 if ($3 == "ip") rtsrc=1;
	 if ($3 == "none") rtfoff=1;
      }

      ## LB options
      if ($2 == "lb.keepalive.timeout") gctime=$3;
      if ($2 == "lb.equalize" && ($3 == "on" || $3 == "yes")) system("touch /usr/share/fwguardian/rttables.equalize");
    }
  }
} 

