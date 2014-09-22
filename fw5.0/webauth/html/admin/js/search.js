
  function chksearchpol() {
    if (document.fpol.CkSearch.checked == true) {
       document.fpol.CtGP.value = "Search";
       document.fpol.pgroupls.disabled = true;
    }
    else {
      document.fpol.CtGP.value = "Create";
      document.fpol.pgroupls.disabled = false;
    }
  }

  function search(stype) {
    if (stype == "input") sdoc = document.finput.lsInput;
    else sdoc = document.froute.lsRoute; 
    var rules = sdoc.length;
    var ruleid = sdoc.selectedIndex;
    var rlsearch = document.fpol.polgroup.value;
    var selcur = sdoc;
    var policy = "";
    var lastpolicy = "";
    var arrpolicy = new Array();
    var countpol = 0;

    if (ruleid < 1 || document.fpol.CkPolAdd.checked) ruleid = 1;
    else {
      if (ruleid <= rules-1) ruleid++;
      else {
        selcur[0].selected = true;
        ruleid = 0;
      }
    }

    for ( var i = ruleid; i < rules; i++ ) {
      rlctxt  = selcur[i].value;
      tabctxt = rlctxt.substring(0,11);
      if (tabctxt == "set-policy ") policy = rlctxt.replace(/set-policy /, "");
      if (rlctxt.indexOf(rlsearch) >= 0) {
         if (document.fpol.CkPolAdd.checked) {
            if (policy != lastpolicy) {
               if (policy != "any") {
                  countpol++;
                  arrpolicy.push(policy);
                  lastpolicy = policy;
               }
            }
         }
         else {
           selcur[i].selected = true;
           break;
         }
      }
    }

    if (document.fpol.CkPolAdd.checked && rlsearch != "any") {
      sdoc.length = 1;
      if (countpol > 0) {
         for ( var i = 0; i < countpol; i++ ) {
            document.fpol.pgroupls.value = arrpolicy[i];
            initarrays();
         }
         alert("INFO: Uncheck 'add' for fine search!");
      }
      else {
         document.fpol.pgroupls.value = "any";
         initarrays();
         selcur[2].selected = true;
      }
      selcur[1] = null;
      selcur[1].selected = true;
    }
    else {
      if (i >= rules) {
        if (rlsearch == "any" && document.fpol.CkPolAdd.checked) alert("WARNING... Invalid search!");
           selcur[0].selected = true;
      }
    }
    document.fpol.polgroup.value = rlsearch;
  }

