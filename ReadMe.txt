Copyright: Copyright (C) 2008 Luca Ercoli  <luca.e [at] seeweb.it>
                         2018 Rainer Kaufmann <info [at] kaufmann-automotive.ch>

License:

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA




What's mod_spamhaus_new
=======================

mod_spamhaus_new is an Apache module that uses DNSBL in order to block spam relay via web forms, preventing URL injection, block http DDoS attacks from bots and generally protecting your web service denying access to a known bad IP address. Default configuration takes advantage of the Spamhaus Block List (SBL) and the Exploits Block List (XBL) querying sbl-xbl.spamhaus.org but you can use a different DNSB, for example local rbldnsd instance of sbl-xbl (increasing query performance). Spamhaus's DNSBLs are offered as a free public service for low-volume non-commercial use. To check if you qualify for free use, please see: Spamhaus DNSBL usage criteria (http://www.spamhaus.org/organization/dnsblusage.html)


INSTALLATION
============

Prerequisites

* Apache 2.4.X - http://www.apache.org/
Other versions may work but have not been tested


Building

If you have got the apxs2 (APache eXtenSion tool) tool installed, write the following commands
to build module:

$ tar zxvf mod_spamhaus_new-0.X.tar.gz
$ cd mod-spamhaus-new
$ make
# make install



CONFIGURATION
=============

First, you must add following command to the main config file of you're web server to load 
mod_spamhaus_new module:

LoadModule spamhaus_module   /usr/lib/apache2/modules/mod_spamhaus_new.so

(The path to mod_spamhaus_new.so depends on your apache installation)



Directives
==========

MS_Methods

    Syntax:  MS_Methods POST,PUT,OPTIONS
    Default: POST,PUT,OPTIONS
    
    The values admitted are the httpd's methods (GET,POST,etc)
    Module verify remote ip address if the method used by the user is present
    in the value passed to this variable. Methods must be comma-separated

MS_WhiteList

    Syntax:  MS_WhiteList /etc/spamhaus.wl
    Default: no value
   
    Path of whitelist file.
    After you've edit it, you mustn't reload apache. This file will be read only
    when 'data modification time' change. You can add an individual IP address or
    subnets with CIDR.

MS_UnaffectedDomains

    Syntax:  MS_UnaffectedDomains /etc/spamhaus.unaffected
    Default: no value

    Path of unaffected domains file. Format: www.example.com
    Domains listed in this file are not spamhaus-checked, so e.g. visitors can do 
    an order in an online shop or can contact you without being locked out.
    This can be helpful if you have customers that had bad luck and got a dynamic
    IP which is already in a spam-list.

MS_DNS

    Syntax:  MS_DNS sbl-xbl.spamhaus.org
    Default: sbl-xbl.spamhaus.org
           
    Name server to use for verify is an ip is blacklisted.
    Using a local rbldnsd instance of sbl-xbl, you can increase query performance

MS_CacheSize

    Syntax:    MS_CacheSize 4096
    Default:   2048
    Max value: 16384
    
    This directive can manage the number of cache entries.

MS_CacheValidity

    Syntax:    MS_CacheValidity 86400
    Default:   172800

    This directive defines the number of seconds how long cached MS_DSN entries are valid.

MS_CustomError

    Syntax:   MS_CustomError "My custom error message"
    Default:  "Access Denied! Your IP address is blacklisted because of malicious behavior in the past."

    A custom error message that allows you to replace default error message with one you create



Synopsis:
--------

<IfModule mod_spamhaus_new.c>

MS_METHODS POST,PUT,OPTIONS,CONNECT 

MS_WhiteList /etc/spamhaus.wl

MS_UnaffectedDomains /etc/spamhaus.unaffected

#MS_Dns local.rbldnsd.instance.of.sbl-xbl

MS_CacheSize 4096

#MS_CustomError "My custom error message"

</IfModule>
