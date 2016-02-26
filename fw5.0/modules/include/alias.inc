function fwalias(cmd, fwmodule) {
  ### Make Alias
  if (cmd == "make") {
     alcont++; 
     aalias[alcont]=$2; avalue[alcont]=$3;
  }
  else {
    if (cmd=="chkperm" || cmd=="mkperm") {
       if (cmd=="chkperm") {
          disabled=0;
          if (match($0, "[ |\t]chk=")) {
             disabled=1;
             split($0, auxparam, "[ |\t]chk=");
             split(auxparam[2],auxparam," |\t");
             if (auxparam[1]=="disabled" || auxparam[1]=="mac-check") disabled=1;
             else {
               for (j in cndname) {
                  if (auxparam[1]==cndname[j]) {
                     if (cndtype[j]=="exist") disabled=cndresult[j];
                     break;
                  }
               }
             }
          }
          return disabled;
       }
       else {
          contcnd++;
          cndname[contcnd]=$2;
          cndtype[contcnd]=$3;
          cndresult[contcnd]=1;

          ## "exist" with cndresult 0 is "true" condition
          if ($3 == "exist") cndresult[contcnd]=system("test -f "$4);
       }
    }
    else {
      if (match(fwmodule,"^(fw(input|route))$")) {
         if (match($4,"^(%A|%D|%R)$") || match($3,"^(%A|%D|%R)$")) {
            if (match($3, "^(%A|%D|%R)$")) {
               sub("%A","ACCEPT", $3);
               sub("%D","DROP", $3);
               sub("%R","REJECT", $3);
               sub("%BP","RETURN", $3);
            }
            else {
               sub("%A","ACCEPT", $4);
               sub("%D","DROP", $4);
               sub("%R","REJECT", $4);
               sub("%BP","RETURN", $4);
           }
         }
      }

      ### Apply Alias
      if (alcont && (!match($1, "^set-") || $1 == "set-qos")) {
         if (match($1,"->")) split($1, ifdir, "->");
         else {
            ifdir[1]=$1;
            ifdir[2]="";
         }
         for (i=1; i<3; i++) {
            auxstr1[i]="";
            auxstr2[i]="";
            if (match(ifdir[i], "^!|+$")) {
               if (match(ifdir[i],"^!")) auxstr1[i]="!";
               if (match(ifdir[i],"+$")) auxstr2[i]="+";
            }
         }

         for (i in aalias) {
           # Interface aliases
           if (sub("(^!|^)"aalias[i]"($|+$)", avalue[i], ifdir[1])) ifdir[1]=auxstr1[1]""ifdir[1]""auxstr2[1];
           if (ifdir[2] != "") {
              if (sub("(^!|^)"aalias[i]"($|+$)", avalue[i], ifdir[2])) ifdir[2]=auxstr1[2]""ifdir[2]""auxstr2[2];
              if (match($1,"->")) $1=ifdir[1]"->"ifdir[2];
           }
           else $1=ifdir[1];

           stchk=2;
           maxchk=3;
           if (fwmodule == "rtnat") maxchk=5;
           else if (fwmodule == "fwmasq") maxchk=2;
           else if (fwmodule == "fwhost") {
              maxchk=2;
           }
           else if (fwmodule == "fwconf") {
              maxchk=6;
           }
           for (j=stchk; j<=maxchk; j++) {
              if (match($j, "!")) gsub("^!"aalias[i]"$", "!"avalue[i], $j);
              else gsub("^"aalias[i]"$", avalue[i], $j);

              if (fwmodule == "tfshape" && j == 3 && match($j, ":")) gsub("^"aalias[i]":", avalue[i]":", $j);
           }
         }
      }
    }
  }
}
