
function filterGrid()
{
   datagrid.filter( $('filter').value.toLowerCase() );
}
	
function clearFilter()
{
   datagrid.clearFilter();
}


function onGridSelect(evt)
{
   document.flsAccount.style.visibility = "hidden";
   document.getElementById('mygrid').style.visibility='hidden';
   document.fiaccount.style.visibility = "visible";
   document.fiaccount.style.width = "90%";
   document.fiaccount.style.align = "center";
   document.fiaccount.username.focus();
   document.fiaccount.chkLock.checked = false;
   document.fiaccount.username.value = evt.target.getDataByRow(evt.row).fg_username;
   document.fiaccount.password.value = evt.target.getDataByRow(evt.row).fg_password;
   document.fiaccount.cpassword.value = evt.target.getDataByRow(evt.row).fg_password;
   document.fiaccount.FullName.value = evt.target.getDataByRow(evt.row).fg_fullname;
   document.fiaccount.NID_RG.value = evt.target.getDataByRow(evt.row).fg_NID;
   document.fiaccount.haddr.value = evt.target.getDataByRow(evt.row).fg_haddr;
   document.fiaccount.EMail.value = evt.target.getDataByRow(evt.row).fg_email;
   document.fiaccount.Phone.value = evt.target.getDataByRow(evt.row).fg_phone;
   document.fiaccount.Phone2.value = evt.target.getDataByRow(evt.row).fg_phone2;
   if (evt.target.getDataByRow(evt.row).fg_lock == "<font color='Red'>lock</font>") document.fiaccount.chkLock.checked = true;
}
	
var cmu = [
{
   header: "login account",
   dataIndex: 'fg_username',
   dataType:'string',
   width:100
},
{
   header: "Lock",
   dataIndex: 'fg_lock',
   dataType:'string',
   width:50
},
{
   header: "Full name",
   dataIndex: 'fg_fullname',
   dataType:'string',
   width:250
},
{
   header: "Address",
   dataIndex: 'fg_haddr',
   dataType:'string',
   width:400
},
{
   header: "Email",
   dataIndex: 'fg_email',
   dataType:'string',
   width:250
},
{
   header: "Nat. Identify",
   dataIndex: 'fg_NID',
   dataType:'string',
   width:100
},
{
   header: "Phone 1",
   dataIndex: 'fg_phone',
   dataType:'string',
   width:100
},
{
   header: "Phone 2",
   dataIndex: 'fg_phone2',
   dataType:'string',
   width:100
},
{
   header: "First login",
   dataIndex: 'fg_ftlogin',
   dataType:'string',
   width:150
},
{
   header: "Last login",
   dataIndex: 'fg_ltlogin',
   dataType:'string',
   width:150
}];	
    
window.addEvent("domready", function(){

   $('filterbt').addEvent("click", filterGrid);
   $('clearfilterbt').addEvent("click", clearFilter);

   datagrid = new omniGrid('mygrid', {
     columnModel: cmu,
     url:"/admin/sqlUser.js",
     perPageOptions: [30],
     perPage:30,
     page:1,
     pagination:true,
     serverSort:false,
     showHeader:true,
     alternaterows:true,
     showHeader:true,
     sortHeader:true,
     resizeColumns:true,
     multipleSelection:false,
     // uncomment this if you want accordion behavior for every row
     /*
       accordion:true,
       accordionRenderer:accordionFunction,
       autoSectionToggle:false,
     */
     width:900,
     height: 300
   });

   datagrid.addEvent('dblclick', onGridSelect);
});

