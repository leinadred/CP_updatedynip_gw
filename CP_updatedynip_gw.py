#!/usr/bin/python3
#
# CP_updatedynip_gw
# version 0.1
#
# written by Daniel Meier (github.com/leinadred)
# January 2021
# 
import requests
from cpapi import APIClient, APIClientArgs
import os
import dns.resolver
import argparse
import logging


parser = argparse.ArgumentParser(description="Resolve Hostname to IP (and change IP of interoperable device).")
parser.add_argument("--authapi", help="Authentication to CP API (for key auth use 'key:<apikey>' for user/pass 'up:<user>:<pass>'", required=True)
parser.add_argument("--targetgw", help="Destination Gateway to install policy to (can use 'all' to install on all devices). otherwise define space separated", required=True)
parser.add_argument("--apiserver", help="Where to auth and script to", required=True)
parser.add_argument("--hostobjectname", help="host object name", required=True)
parser.add_argument("--hostname", type=str, help="Tell hostname to resolve", required=True)
parser.add_argument("--scripttarget", help="target server (mostly Firewall Management?)")
parser.add_argument("--test", help="Nur gucken, nicht anfassen // read only, no action taken",action="store_true")
parser.add_argument("--nagios", help="Give feedback, understandable for NAGIOS systems",action="store_true")
parser.add_argument("--package", help="Policy Package to install - if only one package is present, we will use that!")
parser.add_argument("--verbose", action="store_true")

args = parser.parse_args()

#################################################################################################
# CONSTANTS FOR RETURN CODES UNDERSTOOD BY NAGIOS                                               #
#################################################################################################
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

output_code=[]
output_text={}
ipsver_mgmt=()
#################################################################################################
# Adding Verbosity                                                                              #
#################################################################################################
if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
logging.debug("################## Starting - With extended Logging ##################")

#################################################################################################
# Predefining Global Variables needed in functions                                               #
#################################################################################################
resp_dnsip=""
if "key:" in args.authapi:
    authapi_key=args.authapi.split(":")[1]
elif "up:" in args.authapi:
    authapi_user=args.authapi.split(":")[1]
    authapi_pass=args.authapi.split(":")[2]

def fun_resolve():
    global resp_dnsip
    resp_dns=dns.resolver.resolve(args.hostname,'A')
    if not "CNAME" in str(resp_dns.response.answer[0].items):
        resp_dnsip=resp_dns.response.answer[0][0].address
    elif "CNAME" in str(resp_dns.response.answer[0].items):
        resp_dnsip=resp_dns.response.answer[1][0].address
    else:
        raise ("Something is wrong - please check entered data and/or debug!")
    logging.debug("Result DNS Lookup:\t"+str(resp_dnsip)+"\nDNS Response:\t"+str(resp_dns))

    return resp_dnsip
    
def fun_importCP():
    global output_code
    global output_text
    # Command to be issued on Server for altering host entry
    str_get_currip = "echo -e 'print network_objects "+args.hostobjectname+"\n-q\n' | dbedit -local |grep ipaddr:"
    str_set_newip = "echo -e 'modify network_objects "+args.hostobjectname+" ipaddr "+str(resp_dnsip)+"\n-q\n' | dbedit -local"

    client_args = APIClientArgs(server=args.apiserver, unsafe='True')
    with APIClient(client_args) as client:
        # If Error occurs due to fingerprint mismatch
        if client.check_fingerprint() is False:
            output_text.update({"Message":"Could not get the server's fingerprint - Check connectivity with the server."})
            output_code.append("UNKNOWN")
            logging.debug("UNKNOWN! Logging into SMS not successful! Please troubleshoot/debug script! "+str(output_text))
            raise SystemExit(UNKNOWN)
        # login to server:
        if authapi_key:
            login_res = client.login_with_api_key(authapi_key)
        elif authapi_user and authapi_pass:
            login_res = client.login(authapi_user, authapi_pass)
        logging.debug('API Login done: '+str(login_res))
        # when login failed
        if not login_res.success:
            output_text.update({"Message":"Login failed: "+str(login_res.error_message)})
            output_code.append("UNKNOWN")
            logging.debug("UNKNOWN! Logging into SMS not successful! Please troubleshoot/debug script! "+str(output_text))
            raise SystemExit(UNKNOWN)
        else:
            logging.debug("LogIn to API successful!")
            if not args.scripttarget:
                resp_cphosts = client.api_call("show-checkpoint-hosts")
                if resp_cphosts.data['total'] == 1:
                    args.scripttarget = resp_cphosts.data['objects'][0]['name']
                else:
                    logging.debug("No Script Target (mostly Firewall Management) defined and more than one found! User '--scripttarget'!")
                    raise SystemExit()
            if not args.targetgw:
                resp_targetgws = client.api_call("show-simple-gateways", {"limit" : 50, "offset" : 0, "details-level" : "standard"})
                n=0
                list_targetgws=[]
                while n<resp_targetgws.data['total']:
                    list_targetgws.append(resp_targetgws.data['objects'][n]['name'])
                    n=n+1
                if len(list_targetgws)>1:
                    logging.debug("No target gateway defined! Found: "+str(n)+" gateways!"+str(list_targetgws)+"! Aborting!")
                    raise SystemExit()
            elif args.targetgw == "all":
                resp_targetgw = client.api_call("show-simple-gateways", {"limit" : 50, "offset" : 0, "details-level" : "standard"})
                n=0
                list_targetgws=[]
                while n<resp_targetgw.data['total']:
                    list_targetgws.append(resp_targetgw.data['objects'][n]['name'])
                    n=n+1
                logging.debug("No target gateway defined! Found: "+str(n)+" gateways!"+str(list_targetgws)+" - will use all, as wished!")
                args.targetgw=list_targetgws
            if not args.package:
                logging.debug("No package defined, try to sort out..")
                resp_packages=client.api_call("show-packages", {"limit" : 50, "offset" : 0, "details-level" : "standard"})
                if resp_packages.data['total']==1:
                    args.package=resp_packages.data['packages'][0]['name']
                else:
                    logging.debug("multiple policy packages found, please define, which to use (--package)")
                    raise SystemExit()
            res_getcurrip = client.api_call("run-script",{"script-name":"get interoperable devices ip","script": str_get_currip,"targets" : args.scripttarget})
            resp_currentipfwm = client.api_call("show-task",{"task-id" : res_getcurrip.data['tasks'][0]['task-id'],"details-level":"full"}).data['tasks'][0]['task-details'][0]['statusDescription'].replace("ipaddr: ", "")
            if not resp_currentipfwm == resp_dnsip:
                output_text.update({"Message":"IP of "+args.hostname+" Changed"})
                output_code.append("WARNING")
                if not args.test:
                    res_ipsvergw_task = client.api_call("run-script",{"script-name":"change interoperable devices ip","script": str_set_newip,"targets" : args.scripttarget}) 
                    if res_ipsvergw_task.success is True:
                        logging.debug(client.api_call("show-task",{"task-id" : res_ipsvergw_task.data['tasks'][0]['task-id'],"details-level":"full"}).data['tasks'][0]['task-details'][0]['statusDescription'])
                        
                        res_publish = client.api_call("publish", {}).success
                        res_install = client.api_call("install-policy", {"policy-package" : args.package,  "access" : True,  "threat-prevention" : True,  "targets" : args.targetgw}).success
                        output_text.update({"Message":"object "+args.hostname+" Changed! Now Publishing("+str(res_publish)+") and Install Policy("+str(res_install)+")"})
                    else:
                        output_text.update({"Message":"IP of "+args.hostname+"Changed but was unable to edit gateway object!"})
                        output_code.append("WARNING")
                else:
                    print("would send query to API:\n'run-script',{'script-name':'change interoperable devices ip','script': "+str_set_newip+",'targets' : "+args.apiserver+"}")
            else:
                output_text.update({"Message":"IP did not change - nothing to do!"})
                output_code.append("OK")

    if not args.nagios:
        print(str(output_text)+"\n\n"+str(output_code))

    return output_text, output_code

def fun_nagiosize():
    #Primary built to centralize the "Unknown/OK/Error" Messages in one place, so the whole script is being run.
    global output_text
    global output_code
    logging.debug("Work is done - create and give feedback to Monitoring Engine: "+str(output_code)+" Message: "+str(output_text))
    if "CRITICAL" in output_code:
        print("CRITICAL! "+str(output_text))
        raise SystemExit(CRITICAL)
    elif "WARNING" in output_code:
        print("WARNING! "+str(output_text))
        raise SystemExit(WARNING)
    elif "UNKNOWN" in output_code:
        print("UNKNOWN! "+str(output_text))
        raise SystemExit(UNKNOWN)
    elif all(ele == "OK" for ele in output_code):
        print("OK! "+str(output_text))
        raise SystemExit(OK)
    else:
        print("UNKNOWN! Something went wrong, please troubleshoot/debug script! "+str(output_text))
        raise SystemExit(UNKNOWN)

if __name__ == "__main__":
    fun_resolve()
    fun_importCP()
    if args.nagios:
        fun_nagiosize()