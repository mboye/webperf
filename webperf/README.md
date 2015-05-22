
How to run
---
**Input**  
- [Webperf configuration file](https://github.com/mboye/leone/blob/master/leone-webperf/webperf.conf) 
- List of download targets

**Download targets**  
The easiest way to create a list of download targets is to use the [parse-page.js](https://github.com/mboye/leone/tree/master/parsing-server) script. The script uses Phantomjs and you can obtain a binary for your OS at [phantomjs.org](http://phantomjs.org/download.html)

The parse-page.js script prints the absolute URL of each file requested by an actual browser during download. Phantomjs also executes javascript and the URLs of dynamically loaded files are therefore also printed.

``$ ./parse-page.js https://www.google.com/ https://www.google.com/
https://www.google.com/
https://www.google.fi/?gfe_rd=cr&ei=w59PVOXYE4qr8wfUqILQDg
https://ssl.gstatic.com/gb/images/i1_71651352.png
https://www.google.fi/logos/doodles/2014/jonas-salks-100th-birthday-5130655667060736-res.png
https://www.google.fi/logos/doodles/2014/jonas-salks-100th-birthday-5130655667060736-hp.jpg
...``

Set the value of  'test.loadURLs' to the path of the targets file in the Webperf configuration file before running the test. All Webperf options are set to 0 or "no" unless otherwise specified in the configuration file.

**Running Webperf**  
Simply createa a webperf configuration file specifying the parameters of the test and the performance metrics that should be printed at the end of the test.  
Then simply run ``./leone-webperf test.conf``


##Webperf Design
###Integration with HURL
The Webperf test relies on HURL(libhurl) to handle HTTP downloads. HURL provides a number of hooks which can be used to access data during the download process and also affect the outcome. Webperf uses the hooks to record timestamps, extract header information, and save received data.

###Integration with Leone DNS Client
Webperf utilizes the Leone DNS Client library for name resolution.
System name resolution is overridden using the HURL *DNS resolution hook*.
A common DNS cache is used for all queries and DNS metrics are extracted in the hook function ``dns_resolve_wrapper()``.
For more documentation on the DNS client see the README file the
[leone-dns-library](https://github.com/PasiSa/leone/tree/master/leone-dns-library/README.md) directory.

###DNS triggers
Since DNS resolution is only performed once per domain-name during a page download, only one of several elements sharing the same domain name will have metrics for the DNS resolution of the domain name. The other elements will include a reference (the URL hash of the element) to the element which triggered DNS resolution and therefore contains the DNS metrics.

**Element with DNS metrics**
```json
{
  "url": "http://static.bbci.co.uk/frameworks/barlesque/2.75.0/desktop/3.5/style/main.css",
  "hash": "c0fbbc07bf7f6f9086a86b50bdcd83bca839cd7e",
  "dns": {
    "queryName": "static.bbci.co.uk",
    "finalQueryName": "a1638.g.akamai.net",
    "beginResolve": 31.815000,
    "returnCode": 0,
    "networkTime": 79.615997,
    "executionTime": 177.718002,
    "queries": 1,
    "messagesSent": 1,
    "messagesReceived": 1,
    "dataSent": 35,
    "dataReceived": 447,
    "answerA": "193.166.4.70",
    "answerATTL": 20,
    "answerAAAA": "",
    "answerAAAATTL": -1,
    "answersA": 2,
    "answersAAAA": 0,
    "trace": [
      < DNS trace >
    ]
  },
  "http": {
  	< HTTP metrics >
  }
  }
}
```

**Element with a DNS trigger**  
Notice that the dns.trigger matches the hash value of the example above.
```json
{
  "url": "http://static.bbci.co.uk/frameworks/barlesque/2.75.0/desktop/3.5/img/bbccookies/cookie_prompt_sprite.png",
  "hash": "63b3cf904b5353ee3b459d0830e91c2ee7d7af14",
  "dns": {
 	"trigger": "c0fbbc07bf7f6f9086a86b50bdcd83bca839cd7e"
  },
  "http": {
  	< HTTP metrics >
  }
}
```

###Download time and other time metrics
The download time of an element is measured from the time a request is sent until the full response is received.
This is achived by using the *post-request* hook and *transfer completed* hook.


**Function attached to post-request hook**  
1. Obtain the statistics structure for the element being processed by HURL using the *tag* pointer of the HURLPath.  
2. Set the *begin_transfer* value in the statistics structure.

```c
void stat_request_sent(HURLPath *path, HURLConnection *connection) {
	ElementStat *stat = (ElementStat *) path->tag;
	log_debug(__func__, "Request sent: %s%s", connection->server->domain->domain, path->path);
	assert(stat->http != NULL);

	/* Record timestamp of when request was sent. */
	gettimeofday(&stat->begin_transfer, NULL);

	/* TODO: This might be redundant but I'm not sure. */
	gettimeofday(&stat->http->request_sent, NULL);

	assert(stat->no_hostname || (!stat->dns_trigger && stat->dns) || (stat->dns_trigger && !stat->dns));

	if (connection->reused) {
		log_debug(__func__, "Setting reused begin_connect for '%s%s'", path->server->domain->domain, path->path);
		memcpy(&stat->http->begin_connect, &connection->begin_connect, sizeof(struct timeval));
	}
}
```

**Function attached to transfer completed hook**  
1. Obtain statistics structure.  
2. Set the *end_transfer* value in the statistics structure.  
3. Calculate download time as the difference between *begin_transfer* and *end_transfer*.  
4. Save the transfer time milliseconds in the statistics structure.  
```c
void stat_transfer_complete(HURLPath *path, HURLConnection *connection, HURLTransferResult result, size_t content_length, size_t overhead) {
	struct timeval diff;
	unsigned int tcp_stats_len = sizeof(struct tcp_info);
	ElementStat *stat = (ElementStat *) path->tag;

	assert(stat->no_hostname || (!stat->dns_trigger && stat->dns) || (stat->dns_trigger && !stat->dns));

	if (stat->dns_trigger) {
		log_debug(__func__, "%s has a DNS trigger: %s", stat->url_hash, stat->dns_trigger);
	}

	/* Initialize HTTP statistics */
	if (!stat->http) {
		stat->http = calloc(1, sizeof(HTTPStat));
	}

	/* Save time of completion */
	gettimeofday(&stat->end_transfer, NULL);

	/* Calculate transfer time */
	timersub(&stat->end_transfer, &stat->begin_transfer, &diff);
	stat->http->download_time = timeval_to_msec(&diff);
    ...
```

