#!/usr/local/bin/phantomjs --ignore-ssl-errors=true
var DATA_STORE = "/tmp/leone-render/";

var page = require('webpage').create(),
    system = require('system'),
    t, address, mainURL;


var getFolder = function(path) {
	parts = path.split("/");
	if(path.indexOf("http://") == 0) {
		f = "http://";
	} else if(path.indexOf("https://") == 0) {
		f = "https://";
	} else {
		f = "/";
	}
	for(i = 1; i < parts.length -1; i++) {
		f += parts[i] + "/";
	}
	return f;
}


//Prevent caches from replying.
//page.customHeaders = {'Cache-Control': 'no-cache', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.43 Safari/537.31'};
page.customHeaders = {'Cache-Control': 'no-cache', 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:29.0) Gecko/20100101 Firefox/29.0'};

function pad(num, size) {
    var s = num+"";
    while (s.length < size) s = "0" + s;
    return s;
}

if (system.args.length != 2) {
    console.log('Usage: parse-page.js <URL>');
    phantom.exit(1);
} else {
    var swidth = 1920;
    var sheight = 1080;

    address = system.args[1];
    mainURL = system.args[1];

    var protocol = "";
    if(mainURL.indexOf("http") == 0) {
		protocol = "http://";
	} else if(mainURL.indexOf("https") == 0) {
		protocol = "https://";
	}

    page.viewportSize = {
		width: swidth,
		height: sheight
	};
	page.clipRect = {
		top: 0,
		left: 0,
		width: swidth,
		height: sheight
	};

    page.onResourceRequested = function(requestData, networkRequest) {
		url = requestData.url;
		// Ignore data urls
		if(url.indexOf("data:image/") == 0) {
			return;
		}
		if(url.indexOf("file://") == 0) {
				url = url.substring("file://".length, url.length);
		}
		//console.log("#url " + url);
		if(url == address) {
			//This is the main URL
			//console.log("#main url");
			console.log(mainURL);
		} else if(url.indexOf("http://") == 0 || url.indexOf("https://") == 0) {
			//This is a full URL with protocol, e.g. http://creative.360yield.com, https://creative.360yield.com
			//console.log("#full URL w/ protocol");
			console.log(url);
		} else if(url.indexOf("/") == 0) {
			//This is a relative URL, e.g. /some-page, /images/2014/img.png
			//console.log("#relative URL");
			console.log(getFolder(mainURL) + url.slice(1));
		} else {
			//This is a full URL without protocol, e.g. nn506yrbagrg.cloudfront.net
			//console.log("#full URL wo/ protocol");
			console.log(protocol + url);
		}
	};

	page.onConsoleMessage = function(msg) {
		//Do nothing
	};

	page.onError = function(msg, trace) {
		//Do nothing
	};
    page.open(address, function (status) {
        if (status !== 'success') {
        	phantom.exit(1); //Error
        } else {
	    	//Render page
		setTimeout(function() {
			phantom.exit(0);
		}, 10000);
        }

    });
}
