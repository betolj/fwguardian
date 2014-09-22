function tbids(tbname)
{
  ### ID for routing table
  conttbid++;
  if (conttbid==1) {
     rtcmd="tac /etc/iproute2/rt_tables | grep -v \"^#\\|^25[3-5]\" | sort -r -k1 | head -1 | cut -d\" \" -f1 | awk \"{print $1}\" | expr $(xargs) + 1 2>/dev/null";
     rtcmd | getline ID ; ID--; close(rtcmd);
  }

  ## Calc ID tables (update rt_tables iproute2 file)
  if ((ID <= 1) || !ID) ID=50;
  if ((ID >= 252) && ( ID <= 255 )) ID+=10;

  existtb="";
  rtcmd="cat /etc/iproute2/rt_tables | grep \" "tbname"\\( \\|$\\)\" | cut -d\" \" -f2 | wc -l ";
  rtcmd | getline existtb;
  close(rtcmd);

  if (existtb == 0) {
     ID++;
     rtcmd="echo "ID" "tbname" >> /etc/iproute2/rt_tables";
     system(rtcmd);
  }
}
