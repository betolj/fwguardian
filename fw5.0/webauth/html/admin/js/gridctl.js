//Rev.1 - Version 5.0

// Sync for newRow and doReload
var auxNewRow = new Array();
var allGroups = new Array();
var gridGroups = new Array();
var classcolor = new Array();
var auxDoReload = 0;
var selidGrp = 0;
var selidFind = 0;

// Encode text string to HTML
function encodeHtml(encstr) {
   encstr = encstr.replace(/\"|\'/g, "");
   var encoded = escape(encstr);
   encoded = encoded.replace(/\//g,"%2F");
   encoded = encoded.replace(/\?/g,"%3F");
   encoded = encoded.replace(/=/g,"%3D");
   encoded = encoded.replace(/,/g,"%2C");
   encoded = encoded.replace(/&/g,"%26");
   encoded = encoded.replace(/@/g,"%40");
   return encoded;
}

// Check duplicated Name into alias defs
function findName(arrName, fName) {
   var findn = 0;
   for (var i=0; i < arrName.length; i++) {
       if (arrName[i] == fName) {
          findn = 1;
          i = arrName.length;
       }
   }
   return findn;
}

// Grid sel position
function setPos(gridid, selid, groups) {
   var k = ((parseInt(selid) / 16) * 350);
   gridid.closest(".ui-jqgrid-bdiv").scrollTop(k+groups);
   gridid.setSelection(selid, true);
}

// Refresh group grid
function refreshGroup(gridid, rulesGrid, num, rid) {
   scrollPosition = ((parseInt(rid) / 16) * 350);

   gridid.setGridParam({ rowNum:num });
   gridid.setGridParam({ datatype:'local', data:rulesGrid }).trigger('reloadGrid');
}

// Change group condition
function chGroupCond(gridid, rulesGrid, value) {
   var selid = gridid.jqGrid('getGridParam','selrow');
   var selcur = gridid.jqGrid('getRowData', selid);
   var gridrules = gridid.jqGrid('getDataIDs').length;
   var rules = rulesGrid.length;

   var condtype = value;
   if (condtype !== "") condtype = "?chk="+condtype;

   var curPol = selcur['Group'];
   curPol = curPol.replace(/\?chk=.*/, "");
   for (var i = 0; i < rules; i++) if (rulesGrid[i]['Group'].replace(/\?chk=.*/, "") == curPol) rulesGrid[i]['Group'] = curPol+condtype;

   if (rules === gridrules) {
      refreshGroup(gridid, rulesGrid, rulesGrid.length, selid);
      setPos(gridid, selid, getGroups(rulesGrid[selid-1], gridGroups));
   }
}

// Setting color rows
function choptions(gridid, ret, chtype) {
   var rcolor = "black";
   var fwtarg = /(%(D|R)|DROP|REJECT)/;
   var fwtrigger = /^(filter|auth)\>/;

   if (chtype === "fwmasq") {
      rcolor = (!fwtarg.test(ret['mDefProf'])) ? "black" : "red";
   }
   else if (chtype === "fwprof") {
      rcolor = (!fwtarg.test(ret['hProf'])) ? "black" : "red";
   }
   else if (chtype === "fwmsn" || chtype === "feset") {
      if (ret['Disa'] === "Yes") rcolor = "#888888";
   }
   else if (chtype == "qosqdisc") {
      rcolor = "black";
      if (ret['ifMirror'] == "mirrored") rcolor = "#800000";
   }
   else if (chtype === "qosclassrl" || chtype === "qosfilter") {
      if (ret['fwTarg'] === "FILTER" || ret['fwTarg'] === "MIRROR" || ret['fwTarg'] === "LB") rcolor = '#800000';
   }

   // Check group or rule condition
   if (ret['Group']) {
      var ckPol = /\?chk=disabled$/;
      if (ckPol.test(ret['Group'])) rcolor = "#888888"; 
   }
   if (ret['Cond'] && ret['Cond'] === "disabled") rcolor = "#888888";

   if (rcolor !== "#888888") {
      if (ret['fwTarg']) {
         rcolor = (!fwtarg.test(ret['fwTarg'])) ? "black" : "red";
         if (chtype === "fwroute" && (fwtrigger.test(ret['Group']) && ret['fwTarg'] === "FILTER")) rcolor = '#800000';
         else if (chtype === "vpndirect") {
             if (ret['fwTarg'] === "ROUTE") rcolor = '#800000';
             gridid.setCell(ret['id'],'ifTun','',{color:classcolor[ret['ifTun']], 'font-weight': 'bold'});
         }
         else if (chtype === "fwnat") {
             if (ret['fwTarg'] === "SET") gridid.setCell(ret['id'],'ntIp','',{color:'#800000', 'font-weight': 'bold'});
             else if (ret['fwTarg'] === "MASQ" || ret['fwTarg'] === "AUTO") gridid.setCell(ret['id'],'fwTarg','',{color:'#800000', 'font-weight': 'bold'});
         }
         gridid.setCell(ret['id'],'fwTarg','',{color:classcolor[ret['fwTarg']], 'font-weight': 'bold'});
      }
   }

   // Change grid colors
   gridid.jqGrid('setRowData',ret['id'],false,{color:rcolor});

   if (rcolor !== "red" && rcolor !== "#888888" && rcolor !== "#800000") {
      if (ret['Cond'] && ret['Cond'] !== "none") {
         gridid.setCell(ret['id'],'Cond', '', {color:'Red', 'font-weight': 'bold'});
         if (ret['Cond'] === "mac-check") gridid.setCell(ret['id'],'hMac','',{color:'red'});
      }
      else {
         if (ret['fwTarg']) {
            var ckTarg = /^(IGNORE|(TC|IN)-IGNORE|IPS)$/;
            if (ckTarg.test(ret['fwTarg'])) gridid.setCell(ret['id'],'fwTarg','',{color:'Red', 'font-weight': 'bold'});
         }
         if (ret['NatType'] || ret['ntOpt']) {
            if (ret['NatType'] && ret['NatType'] !== "none") gridid.setCell(ret['id'],'NatType','',{color:'#800000', 'font-weight': 'bold'});
            else if (ret['ntOpt'] !== "none") gridid.setCell(ret['id'],'ntOpt','',{color:'#800000', 'font-weight': 'bold'});
         }
      }
      if (chtype === "fwroute" || chtype === "fwinput" || chtype === "profile" || chtype === "fwprof" || chtype === "vpndirect") {
         if (fwtrigger.test(ret['Group']) || ret['fwTarg'] === "FILTER") gridid.setCell(ret['id'],'id','',{color:'#800000'});
         var rt_field = new Array("fNew","rtGuaran","rtState","rtTrack","hLog","hProtect","hNobanned","dreload","ipip");
         for (var i=0; i<rt_field.length; i++) if (ret[rt_field[i]]) {
            if (ret[rt_field[i]] === "No") gridid.setCell(ret['id'],rt_field[i],'',{color:'#800000', 'font-weight': 'bold'});
            else if (ret[rt_field[i]] === "Yes") gridid.setCell(ret['id'],rt_field[i],'',{color:'#008000', 'font-weight': 'bold'});
         }
      }
      else {
         if (chtype === "qosqdisc" || chtype === "qosclass" || chtype === "qosclassrl" || chtype === "qosfilter") {
            if (chtype === "qosqdisc" || chtype === "qosclass") {
               if (chtype === "qosqdisc") {
                   if (ret['ifNoRootCl'] === "Yes") gridid.setCell(ret['id'],'ifNoRootCl','',{color:'#800000', 'font-weight': 'bold'});
                   if (ret['ifType'] !== "htb") gridid.setCell(ret['id'],'ifType', '', {color:'#800000', 'font-weight': 'bold'});
                   gridid.setCell(ret['id'],'ifName', '', {color:classcolor[ret['ifName']], 'font-weight': 'bold'});
                   gridid.setCell(ret['id'],'ifSpeed', '', {color:classcolor[ret['ifSpeed']], 'font-weight': 'bold'});
               }
               else {
                  if (ret['ifSFQf'] !== "default") {
                     if (ret['ifSFQf'] === "disabled") gridid.setCell(ret['id'],'ifSFQf', '', {color:'Red', 'font-weight': 'bold'});
                     else gridid.setCell(ret['id'],'ifSFQf', '', {color:'#800000', 'font-weight': 'bold'});
                  }
                  if (ret['ifPkts'] !== "default" && ret['ifPkts'] !== "none") gridid.setCell(ret['id'],'ifPkts', '', {color:'#800000', 'font-weight': 'bold'});
                  if (ret['ifType'] !== "classify-rule") gridid.setCell(ret['id'],'ifType', '', {color:'#800000', 'font-weight': 'bold'});
                  if (ret['ifPClass']) {
                     if (!classcolor[ret['ifPClass']]) classcolor[ret['ifPClass']] = "#"+Math.floor((Math.random()*999999)+100000);
                     if (!classcolor[ret['ifNClass']]) classcolor[ret['ifNClass']] = "#"+Math.floor((Math.random()*999999)+100000);
                     gridid.setCell(ret['id'],'ifPClass', '', {color:classcolor[ret['ifPClass']], 'font-weight': 'bold'});
                     gridid.setCell(ret['id'],'ifNClass', '', {color:classcolor[ret['ifNClass']], 'font-weight': 'bold'});
                  }
                  if (ret['ifRate']) gridid.setCell(ret['id'],'ifRate', '', {color:classcolor[ret['ifRate']], 'font-weight': 'bold'});
                  if (ret['ifRateMax']) gridid.setCell(ret['id'],'ifRateMax', '', {color:classcolor[ret['ifRateMax']], 'font-weight': 'bold'});
               }
            }
            else {
               if (ret['fwTarg'] === "FILTER") gridid.setCell(ret['id'],'id','',{color:'#800000'});
               if (ret['qcbytes'] !== "0:0") gridid.setCell(ret['id'],'qcbytes','',{color:'#800000', 'font-weight': 'bold'});
               if (ret['qclimit'] !== "0/32") gridid.setCell(ret['id'],'qclimit','',{color:'#800000', 'font-weight': 'bold'});
               if (ret['qcpkts'] !== "0") gridid.setCell(ret['id'],'qcpkts','',{color:'#800000', 'font-weight': 'bold'});
               if (ret['qlength'] !== "0:0") gridid.setCell(ret['id'],'qlength','',{color:'#800000', 'font-weight': 'bold'});
               if (ret['qgeoip'] !== "any") gridid.setCell(ret['id'],'qgeoip','',{color:'#800000', 'font-weight': 'bold'});
               if (ret['nDpi'] !== "none") gridid.setCell(ret['id'],'nDpi','',{color:'#800000', 'font-weight': 'bold'});
            }
         }
         else {
            if (ret['arDefaults'] && (ret['arDefaults'] == "red" || ret['arDefaults'] == "green" || ret['arDefaults'] == "#888888")) {
               rcolor = ret['arDefaults'];
               gridid.setCell(ret['id'],'arName','',{color:rcolor});
               gridid.setCell(ret['id'],'arName','',{color:classcolor[ret['arName']], 'font-weight': 'bold'});
               if (ret['arDGD']) gridid.setCell(ret['id'],'arDGD','',{color:rcolor});
            }
            else if (chtype === "vpnmapps" || chtype === "vpnserver") {
               if (chtype === "vpnmapps") {
                  gridid.setCell(ret['id'],'vUser','',{color:classcolor[ret['vUser']], 'font-weight': 'bold'});
                  gridid.setCell(ret['id'],'vType','',{color:classcolor[ret['vType']], 'font-weight': 'bold'});
               }
               else {
                  gridid.setCell(ret['id'],'vOption','',{color:classcolor[ret['vOption']], 'font-weight': 'bold'});
                  if (ret['vValue'] === "No") gridid.setCell(ret['id'],'vValue','',{color:'#800000', 'font-weight': 'bold'});
                  else if (ret['vValue'] === "Yes") gridid.setCell(ret['id'],'vValue','',{color:'#008000', 'font-weight': 'bold'});
               }
            }
            else if (chtype === "infra" || chtype == "authnets") {
               if (ret['ckValue'] === "yes" || ret['ckValue'] === "Yes") gridid.setCell(ret['id'],'ckValue', '', {color:'#008000', 'font-weight': 'bold'});
               else gridid.setCell(ret['id'],'ckValue', '', {color:'#800000', 'font-weight': 'bold'});
            }
         }
      }
   }
}

// Update rulesGrid and grid rows 
function GridComplete(gridid, rulesGrid, rulesCt, save_all, chtype) {
   if (rulesCt < 1) rulesGrid.length = 0;
   var rules = rulesGrid.length;
   var gridrules = gridid.jqGrid('getDataIDs').length;

   var curGrp = "", nexGrp = "";
   var glen = 0;
   var gid = new Array();
   if (gridrules < rules) {
      gid = gridid.getDataIDs();
      glen = gid.length;
   }
   if (gridGroups && gridGroups.length > 0) gridGroups.length=0;
   for (var j=1; j<=gridrules && gridrules > 0; j++) {
       var i=j;
       if (glen > 0) i=gid[j-1];
       if (rules == gridrules && save_all == 0) var curRol = rulesGrid[i-1];
       else {
          var curRol = gridid.jqGrid('getRowData', i);
          if (save_all == 1 && rules > 0) rulesGrid[i-1] = curRol;
          else {
             if (rulesCt < 1) rulesGrid.push(curRol);
          }
       }

       if (curRol['Group']) {
          nexGrp = curGrp;
          curGrp = curRol['Group'];
          curGrp = curGrp.replace(/\?chk=.*/, "");
          if (curGrp != nexGrp) {
             gridGroups.push(curGrp);
             if ((rules == gridrules && rules > 0) || rulesCt < 1) {
                if (i == 1) allGroups.length=0;
                allGroups.push(curGrp);
             }
          }
       }
       choptions(gridid, curRol, chtype);
   }
   return rulesGrid;
}

// Check updated rows (add or edit ops)
function chkRow(gridid, auxid, rulesGrid, newRow) {
   var edited = 0;
   for (var i=0; i<newRow.length; i++) {
       var clret = gridid.jqGrid('getRowData', newRow[i]);
       if (clret.Control && clret['Control'].toString().length > 3) {
          edited = 1;
          i = newRow.length;
       }
       else {
          rulesGrid[newRow[i]-1] = clret;
          rulesGrid[newRow[i]-1]['id'] = newRow[i];
       }
   }
   if (edited == 0) {
      newRow.length = 0;
      if (auxid > 0) newRow.push(auxid);
   }
   auxNewRow = newRow;
   return edited;
}

// Change (include) selected or last row
function updRow(cmd, rulesGrid, selid, auxid, chtype, opt1) {
   if (cmd == "add") selid++;
   var datarow = "";

   // ALIAS, INTERFACE, PROFILE, FWMASQ, FWPROF, FWINPUT, FWROUTE, FWNAT, FWMSN, FESET
   // VPNSERVER, VPNDIRECT, VPNMAPPS, QOSSET, QOSCLASS, QOSFILTER, QOSCLASSRT, ADVROUTE
   if (chtype == "alias") datarow = {id:selid,aName:"",aValue:"",Desc:""};
   else if (chtype == "interface") datarow = {id:selid,opt1:"eth0",opt2:"auto",opt3:"auto",opt4:"auto",opt5:"auto",opt6:"0",opt7:"auto",opt8:"2000",opt9:"auto",opt10:"1",opt11:"0",Desc:""};
   else if (chtype == "profile") datarow = {id:selid,Group:opt1,pflInt:"to",pfIf:"any",proto:"tcp",pdata:"any",fwTarg:"ACCEPT",pflInt:"to",pfIp:"any",pRate:"0",pHash:"any",fNew:"No",pStr:"",Cond:"none",hLog:"No",Desc:""};
   else if (chtype == "fwmasq") datarow = {id:selid,mSrcIf:"",mDstIf:"",Src:opt1,mpHttp:"8080",mTrans:"No",mdHttp:"Yes",mpPop3:"",Cond:"none",mDefProf:"none",mLimProf:"none",NatType:"MASQ",Desc:""};
   else if (chtype == "fwprof") datarow = {id:selid,hName:"",Src:opt1,hMac:"detect",hProf:"ACCEPT",hLog:"No",hProtect:"No",hNobanned:"No",Cond:"none",fLog:"",Desc:""};
   else if (chtype == "fwinput") datarow = {id:selid,Group:opt1,inIf:"any",Src:"any",Dst:"any",proto:"",dport:"",fwTarg:"ACCEPT",fNew:"none",Desc:"",Cond:"none"};
   else if (chtype == "fwroute") datarow = {id:selid,Group:opt1,rtIf:"any",Src:"any",rtIfOut:"any",Dst:"any",fwTarg:"ACCEPT",proto:"",sport:"",dport:"",fNew:"none",rtGuaran:"No",rtState:"No",rtTrack:"Yes",Cond:"none",NatType:"none",fLog:"",Desc:""};
   else if (chtype == "authmapps") datarow = {id:selid,Group:opt1,aMapType:"mapuser",Src:"user",Dst:"policy",Cond:"none",Desc:""};
   else if (chtype == "authnets") datarow = {id:selid,Group:opt1,aDir:"from",aIf:"any",Dst:"",ckValue:"No",Cond:"none",Desc:""};
   else if (chtype == "fwnat") datarow = {id:selid,Group:opt1,ntIf:"any",Src:"any",ntIfOut:"any",Dst:"any",fwTarg:"SET",ntIp:"127.0.0.1",proto:"",sport:"",dport:"",ntOpt:"",Cond:"none",fLog:"",Desc:""};
   else if (chtype == "fwmsn") datarow = {id:selid,Src:opt1,mEmail:"account\@hotmail.com",Disa:"No",Desc:""};
   else if (chtype == "feset") datarow = {id:selid,feName:"/file",Desc:"file description",Disa:"No",feType:"textbox", feCmd:"none"};
   else if (chtype == "vpnserver") datarow = {id:selid,Group:opt1,vOption:"",vValue:"",Cond:"none"};
   else if (chtype == "vpnmapps") datarow = {id:selid,Group:opt1,vUser:"user1",Dst:"any",vType:"ppp",fwTarg:"SET",vPass:"",vAuth:"chap",Cond:"none", Desc:""};
   else if (chtype == "vpndirect") datarow = {id:selid,Group:opt1,ifTun:"tun0",Src:"172.16.1.1",Dst:"200.1.2.3",fwTarg:"TUNNEL",DstLAN:"any",Dgd:"none",dreload:"No",ipip:"No",ipsecp:"password",ipsecsp:"100/101",Cond:"none", Desc:""};
   else if (chtype == "clusterint") datarow = {id:selid,Group:"interface",cType:"heartbeat",ifInt:"",Src:"10.0.0.1",Dst:"any",Cond:"none",Desc:""};
   else if (chtype == "clustervip") datarow = {id:selid,Group:"vipconf",clState:"master",clVId:"",ifInt:"",clAdv:"1",clPrio:"100",clPass:"password",Cond:"none",Desc:""};
   else if (chtype == "clustervipad") datarow = {id:selid,Group:"vipaddr",ifInt:"",clVId:"",Dst:"10.0.0.1",Cond:"none",Desc:""};
   else if (chtype == "qosqdisc") datarow = {id:selid,ifName:"",ifInt:"",ifSpeed:"100Mbit",ifBurst:"0",ifType:"htb",ifDefault:"self-default",ifNoRootCl:"",ifMirror:"",Cond:"none"};
   else if (chtype == "qosclass") datarow = {id:selid,ifPClass:"",ifNClass:"",ifRate:"1Mbit",ifRateMax:"1Mbit",ifBurst:"0",ifLatency:"none",ifPrio:"none",ifType:"classify-rule",ifSFQf:"default",ifSFQh:"1024",ifPkts:"default",ifnfLb:"No",ifTrack:"none",Cond:"none",Desc:""};
   else if (chtype == "qosfilter") datarow = {id:selid,ifInt:"any",Src:"any",Dst:"any",fwTarg:"INGRESS",qRate:"0Kbit",qBurst:"0",proto:"",sport:"",dport:"",qcbytes:"0:0",qcpkts:"0",qclimit:"0/32",qlength:"0:0",qgeoip:"any",nDpi:"none",Cond:"none", Desc:""};
   else if (chtype == "qosclassrl") {
      var opt2 = opt1;
      opt1 = opt1.replace(/:.*/, "");
      opt2 = opt2.replace(/.*:/, "");
      datarow = {id:selid,Parent:opt1,Group:opt2,ifInt:"any",Src:"any",Dst:"any",fwTarg:"SHAPE",proto:"",sport:"",dport:"",qcbytes:"0:0",qcpkts:"0",qclimit:"0/32",qlength:"0:0",qgeoip:"any",nDpi:"none",Cond:"none", Desc:""};
   }
   else if (chtype == "advroute" || chtype == "advrouterl") {
      if (chtype == "advrouterl") datarow = {id:selid,Group:opt1,arIf:"",Src:"any",arIfOut:"",Dst:"any",arName:"",proto:"",sport:"",dport:"",Cond:"none",arNat:"none",Desc:""};
      else {
         var opt2 = opt1;
         opt2 = opt2.replace(/\.254$/, "\.0\/24");
         datarow = {id:selid,arIf:"",Dst:opt2,arGw:opt1,arName:"link-name",arDGD:"8.8.8.8",arPrio:"",arRpdb:"default",arFail:"none",arLbgp:"none",arFogp:"none",Cond:"none",Desc:""};
      }
   }

   if (datarow != "") {
      if (cmd == "add") rulesGrid.push(datarow);
      else rulesGrid[auxid] = datarow;
   }
}

// Update newRow
function updnewRow() {
   return auxNewRow;
}

// Update doReload
function upddoReload() {
   return auxDoReload;
}

// Update selidGrp
function updselidGrp() {
   return selidGrp;
}

// Update groups
function updGrp() {
   return allGroups;
}

// Update selidFind
function updselidFind() {
   return selidFind;
}

// Number of groups to selcur
function getGroups(seldata, gdGroups) {
   var groups=0;
   if (seldata && seldata['Group']) {
      var myGroup=seldata['Group'];
      if (gdGroups.length > 0) {
         for (var i=0; i<gdGroups.length; i++) {
            if (gdGroups[i] == myGroup) {
               groups = i;
               groups++;
               i=gdGroups.length;
            }
         }
      }
   }
   return groups;
}

// Moving rows
function chRulesGrid(rulesGrid, auxcur, auxnex) {
   // Fix ID
   var auxid = rulesGrid[auxcur]['id'];
   rulesGrid[auxcur]['id'] = rulesGrid[auxnex]['id'];
   rulesGrid[auxnex]['id'] = auxid;

   // Change rows
   var auxrow = rulesGrid[auxcur];
   rulesGrid[auxcur] = rulesGrid[auxnex];
   rulesGrid[auxnex] = auxrow;
}

// Change Groups
function chGroup(rulesGrid, curGrp, nexGrp, dirGrp) {
   var k=0, y=0, l=0;
   var grIni=-1, grEnd=0;
   var rules = rulesGrid.length;
   var auxRules = new Array();
   selidGrp = -1;

   for (var i=0; i<rules; i++) {
      var auxiGrp = rulesGrid[i]['Group'].replace(/\?chk=.*/, "");
      if (auxiGrp !== curGrp && auxiGrp !== nexGrp) {
         auxRules.push(rulesGrid[i]);
         auxRules[l]['id'] = l+1;
         l++;
      }
      else {
         // Find curGrp and copy nexGrp
         if (auxiGrp === curGrp) {
            if (grIni < 0) grIni=i;
            grEnd=i;

            // Copy nexGrp
            for (var j=i; j<rules && k==0; j++) {
               var auxjGrp = rulesGrid[j]['Group'].replace(/\?chk=.*/, "");
               if (auxjGrp === nexGrp) {
                  auxRules.push(rulesGrid[j]);
                  auxRules[l]['id'] = l+1;
                  l++;
                  if (dirGrp === "up" && selidGrp < 0) selidGrp = l;
               }
            }
            k++;
         }
         else {
           // Copy curGrp
           for (var j=grIni; j<=grEnd && y==0; j++) {
              auxRules.push(rulesGrid[j]);
              auxRules[l]['id'] = l+1;
              l++;
              if (dirGrp === "down" && selidGrp < 0) selidGrp = l;
           }
           y++;
         }
      }
   }
   if (auxRules.length == rules) rulesGrid = auxRules;
   return rulesGrid;
}

// Moveup row function
function mvUp(gridid, rulesGrid, newRow, medited, chtype, it) {
   var selid = gridid.jqGrid('getGridParam','selrow');
   var rules = rulesGrid.length;
   var selcur = gridid.jqGrid('getRowData', selid);
   var selnex = selcur;
   var doReload = 0;
   if (!it) it=1;

   // Move Group
   if (document.getElementById('mvPol') && document.getElementById('mvPol').checked == true) {
      var curGrp = "", nexGrp = "";
      if (gridGroups.length > 1) {
         if (newRow.length > 0) {
            if (chkRow(gridid, 0, rulesGrid, newRow) == 1) {
               alert(medited);
               return rulesGrid;
            }
            doReload = 1;
         }
         for (var i=0; i<gridGroups.length; i++) {
            curGrp = nexGrp;
            nexGrp = gridGroups[i];
            if (nexGrp == selcur['Group'].replace(/\?chk=.*/, "")) i = gridGroups.length;
         }
         if (curGrp && nexGrp && curGrp !== nexGrp && selid > 0) rulesGrid = chGroup(rulesGrid, curGrp, nexGrp, "up");
      }
      return rulesGrid;
   }

   if (selid > 1 && selcur) {
      if (newRow.length > 0) {
         if (chkRow(gridid, 0, rulesGrid, newRow) == 1) {
            alert(medited);
            return rulesGrid;
         }
         doReload = 1;
      }

      var gridrules = gridid.jqGrid('getDataIDs').length;
      var rid = selcur['id']-1;
      if (it > 1) it--;
      for (var i=0; i<it; i++) { 
         selnex = rulesGrid[rid-1];
         selcur = rulesGrid[rid];
         if (i == it-1 && selnex['Group'] && (selnex['Group'] != selcur['Group'])) {
            rulesGrid[rid]['Group'] = rulesGrid[rid-1]['Group'];
            doReload = 1;
         }
         else {
            var auxcur = parseInt(selcur['id'])-1;
            var auxnex = parseInt(selnex['id'])-1;
            chRulesGrid(rulesGrid, auxcur, auxnex);
            selid = selid-1;
         }
         rid--;
      }

      if (rules === gridrules) {
         refreshGroup(gridid, rulesGrid, rules, selid);

         var k = ((parseInt(selid) / 16) * 350);
         gridid.closest(".ui-jqgrid-bdiv").scrollTop(k);
         gridid.setSelection(selid, true);
      }
   }
   auxDoReload = doReload;
   return rulesGrid;
}

// Movedown row function
function mvDown(gridid, rulesGrid, newRow, medited, chtype, it) {
   var selid = gridid.jqGrid('getGridParam','selrow');
   var rules = rulesGrid.length;
   var selcur = gridid.jqGrid('getRowData', selid);
   var selnex = selcur;
   var doReload = 0;
   if (!it) it=1;

   // Move Group
   if (document.getElementById('mvPol') && document.getElementById('mvPol').checked == true) {
      var curGrp = "", nexGrp = "";
      if (gridGroups.length > 1) {
         if (newRow.length > 0) {
            if (chkRow(gridid, 0, rulesGrid, newRow) == 1) {
               alert(medited);
               return rulesGrid;
            }
            doReload = 1;
         }
         for (var i=gridGroups.length-1; i>=0; i--) {
            nexGrp = curGrp;
            curGrp = gridGroups[i];
            if (curGrp == selcur['Group'].replace(/\?chk=.*/, "")) i = -1;
         }
         if (curGrp && nexGrp && curGrp !== nexGrp && selid > 0) rulesGrid = chGroup(rulesGrid, curGrp, nexGrp, "down");
      }
      return rulesGrid;
   }

   if (selid < rules && selcur) {
      if (newRow.length > 0) {
         if (chkRow(gridid, 0, rulesGrid, newRow) == 1) {
            alert(medited);
            return rulesGrid;
         }
         doReload = 1;
      }

      var gridrules = gridid.jqGrid('getDataIDs').length;
      var rid = selcur['id']-1;
      if (it > 1) it--;
      for (var i=0; i<it; i++) { 
         selnex = rulesGrid[rid+1];
         selcur = rulesGrid[rid];
         if (i == it-1 && selnex['Group'] && (selnex['Group'] != selcur['Group'])) {
            rulesGrid[rid]['Group'] = rulesGrid[rid+1]['Group'];
            doReload = 1;
         }
         else {
            var auxcur = parseInt(selcur['id'])-1;
            var auxnex = parseInt(selnex['id'])-1;
            chRulesGrid(rulesGrid, auxcur, auxnex);
            selid++;
         }
         rid++;
      }

      if (rules === gridrules) {
         refreshGroup(gridid, rulesGrid, rules, selid);

         var k = ((parseInt(selid) / 16) * 350);
         gridid.closest(".ui-jqgrid-bdiv").scrollTop(k);
         gridid.setSelection(selid, true);
      }
   }
   auxDoReload = doReload;
   return rulesGrid;
}

// Edit grid row
function editRow(gridid, rulesGrid, newRow, medited, edalias, chtype) {
   var selid = gridid.jqGrid('getGridParam','selrow');

   if (selid && selid !== null) {
      if (chkRow(gridid, selid, rulesGrid, newRow) == 1) alert(medited);
      else {
         var clret = gridid.jqGrid('getRowData', selid);

         // FWMASQ, FWPROF, FWINPUT, FWROUTE, FWNAT, FWMSN, FESET,
         // VPNSERVER, VPNDIRECT, VPNMAPPS, SETQOS, QOSCLASS, QOSCLASSRL, QOSFILTER, ADVROUTE
         if (edalias !== "") {
            var enalias = document.getElementById('enAlias').checked;

            var flag=0;
            if (chtype === "fwmasq" || chtype === "fwprof" || chtype === "fwinput") edField='Src';
            else {
               if (chtype === "advroute" || chtype === "vpnmapps" || chtype === "authmapps" || chtype === "authnets") edField='Dst';
               else if (chtype === "qosclassrl" || chtype === "qosfilter" || chtype === "vpndirect") flag=1;
            }

            if (chtype === "advrouterl" || chtype === "fwroute" || chtype === "fwnat" || flag === 1) {
               // Group grids
               var edField1, edField2;
               edField1 = "Src";
               edField2 = "Dst";

               if (enalias) {
                  gridid.jqGrid('setColProp',edField1,{edittype:'select', editoptions:{value:edalias}});
                  gridid.jqGrid('setColProp',edField2,{edittype:'select', editoptions:{value:edalias}});
               }
               else {
                  gridid.jqGrid('setColProp',edField1,{edittype:'text', editoptions:{value:clret[edField1]}});
                  gridid.jqGrid('setColProp',edField2,{edittype:'text', editoptions:{value:clret[edField2]}});
               }
            }
            else {
               // Other grids
               if (enalias) {
                  if (chtype === "authmapps") gridid.jqGrid('setColProp',edField,{edittype:'select', editoptions:{multiple: true, size: 3, value:edalias}});
                  else gridid.jqGrid('setColProp',edField,{edittype:'select',editoptions:{value:edalias}});
               }
               else gridid.jqGrid('setColProp',edField,{edittype:'text', editoptions:{value:clret[edField]}});
            }
         }

         gridid.setSelection(selid, true);
         if (chtype === "alias") gridid.jqGrid('setColProp','aName',{editable:false});
         gridid.jqGrid('setRowData',selid,false,{color:'Navy'});
         gridid.editRow(selid, true);

         if (chtype === "alias") gridid.jqGrid('setColProp','aName',{editable:true});
      }
   }
}

// Clone a grid row
function cloneRow(gridid, rulesGrid, newRow, medited, chtype, opt1) {
   var selid = gridid.jqGrid('getGridParam','selrow');
   var gridrules = gridid.jqGrid('getDataIDs').length;
   var edited = 0;

   if (gridrules < 1 || selid === null) return rulesGrid;
   if (newRow.length > 0) edited = chkRow(gridid, selid, rulesGrid, newRow);
   if (edited == 1) alert(medited);
   else {
      var rules = rulesGrid.length;
      if (selid) {
         gridid.jqGrid('restoreRow',selid);
         var clret = gridid.jqGrid('getRowData', selid);
         var auxcur = selid - 1;
         selid++;
      }
      var i = rules;

      // Add new row at end of grid
      updRow("add", rulesGrid, gridrules, auxcur, chtype, opt1);
      gridrules++;

      // Update grid rows
      if (selid) {
         if (newRow.length > 0) chkRow(gridid, 0, rulesGrid, newRow);
         for (i=rules; i > auxcur; i--) {
             rulesGrid[i]=rulesGrid[i-1];
             rulesGrid[i]['id'] = i+1;
         }
         rulesGrid[i] = clret;

         rules++;
         if (rules === gridrules) {
            refreshGroup(gridid, rulesGrid, gridrules, selid);
            gridid.jqGrid('setRowData',selid,false,{color:'Navy'});
            setPos(gridid, selid, getGroups(rulesGrid[selid-1], gridGroups));
         }
      }
   }
   return rulesGrid;
}

// Add a new grid row
function addRow(gridid, rulesGrid, newRow, medited, chtype, opt1, edalias) {
   var edited = 0;
   var selid = gridid.jqGrid('getGridParam','selrow');
   var auxid = selid;

   if (newRow.length > 0) edited = chkRow(gridid, selid, rulesGrid, newRow);
   if (edited == 1) alert(medited);
   else {
      var auxcur = 0;
      var entxt = "";
      var gridrules = gridid.jqGrid('getDataIDs').length;

      // FWMASQ, FWPROF, FWINPUT, FWROUTE, FWNAT, FWMSN, FESET, VPNDIRECT, VPNMAPPS
      // SETQOS, QOSCLASS, QOSFILTER, QOSCLASSRL, ADVROUTE
      var edField = "";
      if (chtype === "fwmasq" || chtype === "fwprof" || chtype === "fwinput") edField = "Src";
      else {
         if (chtype === "advroute" || chtype === "vpnmapps") edField = "Dst";
      }

      if (!selid) selid = 1;
      if (selid && gridrules > 0) {
         var clret = gridid.jqGrid('getRowData', selid);
         if (auxid > 0 && edField !== "") entxt = clret[edField];

         auxcur = selid-1;
         selid++;
      }
      var rules = rulesGrid.length;

      var flag=0;
      if ((chtype === "fwmasq" || chtype === "fwmsn" || chtype === "fwprof") && entxt === "") entxt = opt1;
      else if (chtype === "qosclassrl" || chtype === "qosfilter" || chtype === "vpndirect") flag=1;

      // Add new row at end of grid
      updRow("add", rulesGrid, gridrules, auxcur, chtype, opt1);
      gridrules++;
      var i = 0;

      if (selid) {
         chkRow(gridid, selid, rulesGrid, newRow);
         if (gridrules > 1) {
            // Moving rows
            for (i=rules; i > auxcur; i--) {
                rulesGrid[i]=rulesGrid[i-1];
                rulesGrid[i]['id'] = i+1;
            }
            rulesGrid[i] = clret;
            updRow("change", rulesGrid, parseInt(auxcur)+2, parseInt(auxcur)+1, chtype, opt1);
         }
         if (rulesGrid.length == gridrules) refreshGroup(gridid, rulesGrid, gridrules, selid);

         if (edField !== "") {
            var enalias = document.getElementById('enAlias').checked;

            if (chtype === "advrouterl" || chtype === "fwroute" || chtype === "fwnat" || flag === 1) {
               // Group grids
               var edField1, edField2;
               edField1 = "Src";
               edField2 = "Dst";

               if (enalias) {
                  gridid.jqGrid('setColProp',edField1,{edittype:'select', editoptions:{value:edalias}});
                  gridid.jqGrid('setColProp',edField2,{edittype:'select', editoptions:{value:edalias}});
               }
               else {
                  gridid.jqGrid('setColProp',edField1,{edittype:'text', editoptions:{value:clret[edField1]}});
                  gridid.jqGrid('setColProp',edField2,{edittype:'text', editoptions:{value:clret[edField2]}});
               }
            }
            else {
               // Other grids
               if (enalias) gridid.jqGrid('setColProp',edField,{edittype:'select',editoptions:{value:edalias}});
               else gridid.jqGrid('setColProp',edField,{edittype:'text', editoptions:{value:entxt}});
            }
         }

         if (rulesGrid.length == gridrules) {
            gridid.jqGrid('setRowData',selid,false,{color:'Navy'});
            setPos(gridid, selid, getGroups(rulesGrid[selid-1], gridGroups));
            gridid.editRow(selid, true);
         }
      }
   }
   return rulesGrid;
}

// Clone a grid row
function delRow(gridid, rulesGrid, newRow, medited, msg) {
   var selid = gridid.jqGrid('getGridParam','selrow');
   var rules = rulesGrid.length;
   var doreload = 0;

   if (selid) {
      if (newRow.length > 0) {
         if (chkRow(gridid, 0, rulesGrid, newRow) == 1) {
            alert(medited);
            return rulesGrid;
         }
      }
      gridid.jqGrid('restoreRow',selid);
      var auxid = parseInt(selid - 1);
      var gridrules = gridid.jqGrid('getDataIDs').length;

      // Group grids
      var auxpol;
      if (rulesGrid[auxid]['Group']) auxpol = rulesGrid[auxid]['Group'];

      // Delete in main data grid
      for (var i=auxid; i<rules; i++) {
          var auxnex = parseInt(i) + 1;
          if (auxnex < rules) {
             rulesGrid[i] = rulesGrid[auxnex];
             rulesGrid[i]['id'] = auxnex;
          }
      }
      if (selid == rules) selid = rules-1;
      else {
         if (rulesGrid[auxid]['Group']) {
            if (rulesGrid[auxid]['Group'] !== auxpol && selid > 1) selid--;
         }
      }

      // remove row in rulesGrid and reload Grid
      selidFind=selid;
      rulesGrid.pop();
      gridid.jqGrid('clearGridData');
      if (rulesGrid[selid-1]['Group'] && rulesGrid[selid-1]['Group'] !== auxpol) doreload++;
      if (rules == gridrules || doreload) {
         refreshGroup(gridid, rulesGrid, rules-1, selid);
         setPos(gridid, selid, getGroups(rulesGrid[selid-1], gridGroups));
      }
   }
   else alert(msg);
   return rulesGrid;
}

// Saving all rows with ajax call
function saveAll(gridid, rulesGrid, newRow, medited, msg, chtype, getlink, postlink) {
   var flag = 0;
   var error = 0;
   var edited = "0";
   var selid = gridid.jqGrid('getGridParam','selrow');

   if (chtype === "fwinput" || chtype === "fwroute" || chtype === "profile" || chtype === "fwnat" || chtype === "qosclassrl") flag=1;
   if (newRow.length > 0 && flag == 0) edited = chkRow(gridid, 0, rulesGrid, newRow);
   if (edited == 0) {
      var rules = rulesGrid.length;
      var arrName = new Array();
      var gridData = jQuery.extend(true, {}, rulesGrid);

      if (rules < 1) {
         // ALIAS, PROFILE, FWMASQ, FWPROF, FWMSN, FWINPUT, FWROUTE, FESET, FWNAT
         // VPNSERVER, VPNDIRECT, VPNMAPPS, SETQOS, QOSCLASS, QOSFILTER, QOSCLASSRL, ADVROUTE
         updRow("add", rulesGrid, 0, 0, chtype, "");
         gridData = jQuery.extend(true, {}, rulesGrid);
         gridData[0]['Control'] = 'set';
         rulesGrid.length=0;
         rules++;
      }

      var lang="pt_BR";
      if (medited === "ERROR: There are rows in edit mode!") lang="en";

      for(var i=0; i < rules && error == 0; i++) {
         if (chtype === "fwprof") {
            // Setting default opts in first record
            if (i == 0) {
               gridData[i]['hDefaults'] = document.getElementById('hProtIf').value;
               gridData[i]['hDefaults'] = encodeHtml(gridData[i]['hDefaults']+"/"+document.getElementById('hProtDesc').value);
               if (document.getElementById('enMac').checked) gridData[0]['Control'] = "chkmac";
            }
            else gridData[i]['hDefaults'] = '';

            gridData[i]['hMac'] = encodeHtml(gridData[i]['hMac']);
         }
         else  if (chtype === "profile") {
            if (gridData[i]['pdata']) gridData[i]['pdata'] = encodeHtml(gridData[i]['pdata']);
            if (gridData[i]['pfIp']) gridData[i]['pfIp'] = encodeHtml(gridData[i]['pfIp']);
            if (gridData[i]['pRate']) gridData[i]['pRate'] = encodeHtml(gridData[i]['pRate']);
            if (gridData[i]['pHash']) gridData[i]['pHash'] = encodeHtml(gridData[i]['pHash']);
            if (gridData[i]['pStr']) gridData[i]['pStr'] = encodeHtml(gridData[i]['pStr']);
         }
         else if (chtype === "fwmasq") gridData[i]['mLimProf'] = encodeHtml(gridData[i]['mLimProf']);
         else if (chtype === "authmapps" || chtype == "authnets") {
            if (gridData[i]['aIf']) gridData[i]['aIf'] = encodeHtml(gridData[i]['aIf']);
         }
         else if (chtype === "fwnat") {
            var invtest = /^DNAT(\?chk|$)/;
            gridData[i]['ntIp'] = encodeHtml(gridData[i]['ntIp']);
            if (!invtest.test(gridData[i]['Group'])) gridData[i]['ntIfOut'] = "any";
            else {
               if (gridData[i]['fwTarg'] === "MASQ" || gridData[i]['fwTarg'] === "AUTO") {
                  error=1;
                  if (lang === "en") alert("ERROR: ID "+gridData[i]['id']+" - The AUTO or MASQ options are allowed only in SNAT policy!");
                  else alert("ERROR: ID "+gridData[i]['id']+" - As opções AUTO ou MASQ são permitidas apenas na política SNAT!");
               }
            }
         }
         else if (chtype === "vpndirect") {
            gridData[i]['ipsecp'] = encodeHtml(gridData[i]['ipsecp']);
            gridData[i]['ipsecsp'] = encodeHtml(gridData[i]['ipsecsp']);
         }
         else if (chtype === "advroute" || chtype === "advrouterl") {
            // Setting default opts in first record
            if (i == 0 && chtype !== "advrouterl") {
               gridData[i]['arDefaults'] = document.getElementById('arsrcRpdb').value;
               gridData[i]['arDefaults'] = gridData[i]['arDefaults']+" "+document.getElementById('arkalive').value;
               gridData[i]['arDefaults'] = gridData[i]['arDefaults']+" "+document.getElementById('enEqual').checked;
            }
            else gridData[i]['arDefaults'] = '';

            var invtest = /^[\s]*\!/;
            if (chtype === "advrouterl") {
               gridData[i]['Group'] = encodeHtml(gridData[i]['Group']);
               if (invtest.test(gridData[i]['Src']) || invtest.test(gridData[i]['Dst']) || invtest.test(gridData[i]['arIfOut'])) error = 1;
            }
            else {
               gridData[i]['arLbgp'] = encodeHtml(gridData[i]['arLbgp']);
               gridData[i]['arFogp'] = encodeHtml(gridData[i]['arFogp']);
            }
            if (invtest.test(gridData[i]['arIf']) || invtest.test(gridData[i]['arName']) || error == 1) {
                error=1;
                if (lang === "en") alert("ERROR: ID "+gridData[i]['id']+" - Inversion not allowed!");
                else alert("ERROR: ID "+gridData[i]['id']+" - Inversão não permitida!");
            }
         }
         else if (chtype === "qosclassrl" || chtype === "qosclass" || chtype === "qosfilter") {
            if (chtype === "qosclass") {
               gridData[i]['ifSFQf'] = encodeHtml(gridData[i]['ifSFQf']);
               gridData[i]['ifPkts'] = encodeHtml(gridData[i]['ifPkts']);
            }
            else {
               gridData[i]['qcbytes'] = encodeHtml(gridData[i]['qcbytes']);
               gridData[i]['qcpkts'] = encodeHtml(gridData[i]['qcpkts']);
               gridData[i]['qclimit'] = encodeHtml(gridData[i]['qclimit']);
               gridData[i]['qlength'] = encodeHtml(gridData[i]['qlength']);
               gridData[i]['qgeoip'] = encodeHtml(gridData[i]['qgeoip']);
               gridData[i]['nDpi'] = encodeHtml(gridData[i]['nDpi']);
            }
         }
         else if (chtype === "alias") {
            var fdName = findName(arrName, gridData[i]['aName']);
            if (fdName == 0) {
               arrName.push(gridData[i]['aName']);
               gridData[i]['aValue'] = encodeHtml(gridData[i]['aValue']);
            }
            else {
               error = 1;
               if (lang === "en") alert('ERROR: Duplicate name definition for *'+gridData[i]['aName']+'* !');
               else alert('ERRO: Definição de nome duplicada para *'+gridData[i]['aName']+'* !');
            }
         }
         else if (chtype === "interface") {
            gridData[i]['opt1'] = encodeHtml(gridData[i]['opt1']);
            gridData[i]['opt2'] = encodeHtml(gridData[i]['opt2']);
            gridData[i]['opt4'] = encodeHtml(gridData[i]['opt4']);
            gridData[i]['opt5'] = encodeHtml(gridData[i]['opt5']);
            gridData[i]['opt9'] = encodeHtml(gridData[i]['opt9']);
         }
         if (error == 0) {
            if (gridData[i]['proto'] && chtype !== "profile") {
               if (!(gridData[i]['proto'] === "tcp" || gridData[i]['proto'] === "udp" || gridData[i]['proto'] === "icmp" || gridData[i]['proto'] === "ipp2p") && ((gridData[i]['sport'] && gridData[i]['sport'] !== "") || gridData[i]['dport'] !== "")) {
                  error = 1;
                  if (lang === "en") alert("ERROR: ID "+gridData[i]['id']+" - The socket ports is allowed only for *tcp*, *udp*, *icmp* or *ipp2p*!");
                  else alert("ERRO: ID "+gridData[i]['id']+" - A definição de portas é permitida apenas para *tcp*, *udp*, *icmp* ou *ipp2p*!");
               }
               else {
                  gridData[i]['proto'] = encodeHtml(gridData[i]['proto']);
                  if (gridData[i]['sport']) gridData[i]['sport'] = encodeHtml(gridData[i]['sport']);
                  if (gridData[i]['dport']) gridData[i]['dport'] = encodeHtml(gridData[i]['dport']);
               }
            }
            else if (gridData[i]['vPass']) gridData[i]['vPass'] = encodeHtml(gridData[i]['vPass']);
            else if (gridData[i]['vValue']) gridData[i]['vValue'] = encodeHtml(gridData[i]['vValue']);

            var base_field = new Array("Src","Dst","fwTarg","Desc","fLog");
            for (var j=0; j<base_field.length; j++) if (gridData[i][base_field[j]]) gridData[i][base_field[j]] = encodeHtml(gridData[i][base_field[j]]);
         }
      }

      // POST ajax
      if (error == 0) {
         jQuery.ajax({
             url         : postlink
             ,type        : 'POST'
             ,cache       : false
             ,data        : JSON.stringify(gridData)
             ,contentType : 'application/json; charset=utf-8'
             ,async: false
             ,beforeSend: function(xhr) {
                document.getElementById('chwait').style.display = 'block';
             }
             ,success: function(data) {
                document.getElementById('chwait').style.display = 'none';
                rulesGrid[0]['Control'] = '';
                if (flag == 0) gridid.setGridParam({url:getlink, datatype:"json" }).trigger('reloadGrid');
                alert(msg);

                if (selid && selid > 0) {
                   var gridrules = gridid.jqGrid('getDataIDs').length;
                   if (gridrules < selid) selid = gridrules;

                   if (gridGroups.length > 0) setPos(gridid, selid, getGroups(rulesGrid[selid-1], gridGroups));
                   else setPos(gridid, selid, 0);
                }
             }
             ,error: function (xhr, ajaxOptions, thrownError) {
                document.getElementById('chwait').style.display = 'none';
                alert(xhr.status+" : "+thrownError);
             }
         });
      }
      else auxNewRow.length = 0;
   }
   else alert(medited);
}

// Search function
function search_Grid(dataGrid, selpos, stsearch, canAdd, stfield) {
   var rules = dataGrid.length;
   var curPol = "";
   var lastPol = "";
   var myPolicy = new Array();
   var find = 0;
   var addfind = 0;
   selpos++;
   selidFind=selpos;

   for (var i=selpos; i<rules; i++) {
       var selcur = dataGrid[i];
       if (selcur['Group']) curPol = selcur['Group'].replace(/\?chk=.*/, "");
       for (var j=0; j<stfield.length && find==0; j++) {
          if (stsearch && selcur[stfield[j]].indexOf(stsearch) >= 0) {
             if (canAdd) {
                addfind=1;
                if (curPol != lastPol) {
                   curPol = curPol.replace(/\?chk=.*/, "");
                   myPolicy.push(curPol);
                   lastPol = curPol;
                }
                if (selidFind == selpos) selidFind = selcur['id'];
             }
             else {
                find=1;
                selidFind = selcur['id'];
                break;
             }
          }
       }
   }
   if (find == 0 && addfind == 0) selidFind=0;
   return myPolicy;
}
