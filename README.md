![license](https://img.shields.io/github/license/leinadred/CP_updatedynip_gw)
![language](https://img.shields.io/github/languages/top/leinadred/CP_updatedynip_gw)
# CP_updatedynip_gw

Script queries for a given DNS Name (i.e. DynDNS) and uses the IP to update an interoperable device object via Check Points Management API by executing "dbedit" command, as interoperable devices are not available via Management API (Or I did not find that :) ) 
Use Case is (why am I not just using a dns name?) that I have an ASA holding a Site to Site VPN with Check Point. ASA side also has a dynamically assigned public IP. With a bit of work, script can be used to do that with multiple sites/objects or to create interoperable devices batchwise.


When triggering the script with NAGIOS based system - Output:

 ![Example - Nagios Output](/nagios_updateinteroperabledevice.png)
 
 You need python interpreter (3.8 works good, 3.9 too. older should work too)
 Modules used (added manually)
  - cpapi (Check Point API SDK) (https://github.com/CheckPointSW/)
  - dns.resolver (as the name says, to resolve DNS :-) )
  

Arguments:
```sh
"--authapi", help="Authentication to API (for key auth use 'key:<apikey>' for user/pass 'up:<user>:<pass>'", required=True
 - provide how to authenticate with API server and auth informations

"--targetgw", help="Destination Gateway to install policy to (can use 'all' to install on all devices)", required=True
 - Firewalls to get the updated policy, when not set the script queries for gateways. (if only one, this is been used)

"--apiserver", help="Firewall Management Server", required=True
- Mostly IP of Firewall Management Server

"--hostobjectname", help="host object name", required=True
 - Name of the interoperable device object

"--hostname", type=str, help="Tell hostname to resolve", required=True
 - Hostname to resolve

"--scripttarget", help="target server (mostly CP Management Server?)"
 - if not set, the script queries for Check Point host objects. If more than one is found, script aborts.

"--test", help="Nur gucken, nicht anfassen // read only, no action taken"
 - Only check, if all would be good to update the interoperable device object. Returns the API query with dbedit command

"--nagios", help="Give feedback, understandable for NAGIOS systems"
 - when IP is not changed, give back "OK" state. Else return warning (in default setup does not issue notification. 
 
"--package", help="Policy Package to install - if only one package is present, we will use that!"
 - name of policy package. if not set and only one package is found, we´ll use that

"--verbose"
 - Add verbose logging
```

 Feedback or improvements are highly appreciated. Still learning :)
 
