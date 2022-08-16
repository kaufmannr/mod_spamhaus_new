# mod_spamhaus_new
Apache 2.4 security: mod_spamhaus_new is an Apache module that uses DNSBL in order to block spam relay via web forms, 
preventing URL injection, block http DDoS attacks from bots and generally protecting your web service 
denying access to a known bad IP address. 

This module is based on mod_spamhaus but has been updated for actual web server configurations and to
support a list of domains, which are NOT spam blocked so customers can reach you even if they got a 
dynamic IP which is on a spam list.

Default configuration takes advantage of the Spamhaus Block List (SBL) and the Exploits Block List (XBL)
querying sbl-xbl.spamhaus.org but you can use a different DNSBL, for example local rbldnsd instance of 
sbl-xbl (increasing query performance). Spamhaus's DNSBLs are offered as a free public service for 
low-volume non-commercial use. 

To check if you qualify for free use, please see:
Spamhaus DNSBL usage criteria (https://www.spamhaus.org/organization/dnsblusage.html)

©2022 Kaufmann Automotive GmbH
https://www.kaufmann-automotive.ch
