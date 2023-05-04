# webmatcher
A tool to find valid subdomains for a given domain which resolve to the provided, in-scope IP addresses. Useful on externals when you are only given public IP ranges, find loads of web services, but cannot access them as you have no knowledge of the subdomains needed for the URL.

###Basic usage
```
./webmatcher.py [scopefile] [domain]
```
The [scopefile] can contain CIDRs, IP Ranges and individual IPs.
You can also provide a list of known subdomains with -s or a subdomain wordlist to perform DNS grinding.

Uses amass and theHarvester under the hood.
