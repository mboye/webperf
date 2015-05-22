# Leone DNS Client

##Features
* Iterative and recursive name resolution.
* Non-persistent caching without record expiry.
* Loop detection.
* CNAME following.
* Full query/response trace.

##How to use

Before calling the main resolver function ``dns_resolve()`` DNS cache and DNS resolver state should be initialized using 
``dns_cache_init()`` and ``dns_state_init()``.

The resolver state keeps track of the messages sent and received during name resolution, and the DNS cache stored all received records in a tree structure vital to the operation of the DNS client.

```c
#include "dns_core.h"
int dns_resolve(DNSCache *cache, DNSResolverState *state, char *qname, DNSRecordType qtype, char **final_qname);
```
* ``cache``: the initialized DNS cache structure.
* ``state``: the DNS resolution state.
* ``qname``: the domain name of interest.
* ``qtype``: the record type of interest. A, AAAA, and CNAME are supported.
* ``final_qname``: pointer that will be set to the value of the last CNAME followed during resolution.

The resolver supports concurrent requests by controlling access to the DNS cache using a mutex lock.
Thus multiple calls to ``dns_resolve()`` can be made as long as different ``DNSResolverState`` structures are used.



###DNS trace
After a domain name has been resolved, the ``DNSResolverState`` structure contains all messages sent during the resolution process.
From this structure it is possible to extract details about each DNS query and response, including RTT values

##Implementation
It's a bit complicated but here is the overall design of the client.

The DNS cache is a tree structure representing the actual DNS hierarchy.  
```
<root domain>
    |-> <com> {NS of "com" is a.gtld-servers.net"}  
    |-> <net>  
          |-> <gtld-servers>  
                    |-> <a> [ A of "a.gtld-servers.net" is "1.2.3.4" ]
```

If the DNS cache consistet of the data above, the resolver would do the following for a query about "google.com":  
1. What is the authoritative name server of the "com" domain?  
1.2. Find the "com" element in the hierarchy and check its NS records. In this case the NS record tells that "a.gtld-servers.net" is an authoritative name server of the "com" domain  
2. What is the IP address of "a.gtld-servers.net"?  
2.1 Find the "a" element in the hierarchy and check if there are any A/AAAA records.  
3. Send a DNS querty to "1.2.3.4" containing a question record for "google.com".  



**In short the resolver logic can be summarized as: **  
1. Is the record we are looking for already in the cache?  
2. What is the best name server we can ask about information regarding QNAME?  
3. Have we asked this name server about QNAME before? If so we have likely entered a loop.  
3. What is the IP address of the best name server?  
4. Have we asked this server about QNAME before? If so we have likely entered a loop.  
5. Send a DNS query.  
6. If a timeout occurs try next IP address.  
7. If timeouts have occurred for all IP addresses of the best name server, try the next best name server and repeat from step 5.  
8. When a response is received, cache its records and check if we received the answer we were looking for. If the answer is a CNAME record, replace the current QNAME with the value of the CNAME.

If at any point an A/AAAA is missing for a NS record, the resolver will obtain the missing record and then continue the resolution of the previous QNAME.
