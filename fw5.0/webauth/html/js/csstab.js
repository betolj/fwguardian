/*
    google-play-minimal-tabs-with-css3-jquery
    http://www.red-team-design.com/wp-content/uploads/2012/05/google-play-minimal-tabs-with-css3-jquery-demo.html
*/

function resetTabs(){
    $("#content > div").hide(); //Hide all content
    $("#tabs a").attr("id",""); //Reset id's      
}

var myUrl = window.location.href; //get URL
var myUrlTab = myUrl.substring(myUrl.indexOf("#"));
var myUrlTabName = myUrlTab.substring(0,4);

(function(){
    $("#content > div").hide();
    // Show first tab content
    $("#tabs li:first a").attr("id","current");
    $("#content > div:first").fadeIn();
        
    $("#tabs a").on("click",function(e) {
        e.preventDefault();
        if ($(this).attr("id") == "current") return;
        else {             
          resetTabs();
          $(this).attr("id","current");
          $($(this).attr('name')).fadeIn();
        }
    });

    for (i = 1; i <= $("#tabs li").length; i++) {
      if (myUrlTab == myUrlTabName + i) {
          resetTabs();
          $("a[name='"+myUrlTab+"']").attr("id","current");
          $(myUrlTab).fadeIn();
      }
    }
})()
