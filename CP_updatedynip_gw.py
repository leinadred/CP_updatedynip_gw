#!/usr/bin/python3
#
# CP_updatedynip_gw
# version 1.0
#
# written by Daniel Meier (github.com/leinadred)
# January 2021
# 
import requests
from cpapi import APIClient, APIClientArgs
import os
import dns.resolver
import argparse
import argparse
import logging


parser = argparse.ArgumentParser(description="Resolve Hostname to IP (and change IP of interoperable device).")
parser.add_argument("--import", type=bool, help="Additionally import resolve result to Destination! (Currently Check Point R80.30++)")
#parser.add_argument("--help", help="Print this help")
parser.add_argument("--authapi", help="Authentication to CP API (for key auth use 'key:<apikey>' for user/pass 'up:<user>:<pass>'")
parser.add_argument("--apiserver", help="Where to auth and script to")
parser.add_argument("--scripttarget", help="target server (Firewall Management?)")
parser.add_argument("--hostobjectname", help="host object name")
parser.add_argument("--hostname", type=str, help="Tell hostname to resolve")
parser.add_argument("--test", help="Nur gucken, nicht anfassen // read only, no action taken",action="store_true")
parser.add_argument("--nagios", help="Give feedback, understandable for NAGIOS systems",action="store_true")
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
# Predfining Global Variables needed in functions                                               #
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
    logging.debug("Result DNS Lookup:\t"+resp_dnsip+"\nDNS Response:\t"+resp_dns)

    return resp_dnsip

def fun_importCP():
    global output_code
    global output_text
    # Command to be issued on Server for altering host entry
    str_get_currip = "echo -e 'print network_objects "+args.hostobjectname+"\n-q\n' | dbedit -local |grep ipaddr:"
    str_set_newip = "echo -e 'modify network_objects "+args.hostobjectname+" ipaddr "+resp_dnsip+"\n-q\n' | dbedit -local"

    client_args = APIClientArgs(server=args.apiserver, unsafe='True')
    with APIClient(client_args) as client:
        # If Error occurs due to fingerprint mismatch
        if client.check_fingerprint() is False:
            output_text.update({"Message":"Could not get the server's fingerprint - Check connectivity with the server."})
            output_code.append("UNKNOWN")
            print("UNKNOWN! Logging into SMS not successful! Please troubleshoot/debug script! "+str(output_text))
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

            res_getcurrip = client.api_call("run-script",{"script-name":"get interoperable devices ip","script": str_get_currip,"targets" : args.scripttarget})
            resp_currentipfwm = client.api_call("show-task",{"task-id" : res_getcurrip.data['tasks'][0]['task-id'],"details-level":"full"}).data['tasks'][0]['task-details'][0]['statusDescription'].replace("ipaddr: ", "")
            if not resp_currentipfwm == resp_dnsip:
                output_text.update({"Message":"IP of "+args.hostname+"Changed"})
                output_code.append("OK")
                if not args.test:
                    res_ipsvergw_task = client.api_call("run-script",{"script-name":"change interoperable devices ip","script": str_set_newip,"targets" : args.apiserver}) 
                    if res_ipsvergw_task.success is True:
                        logging.debug(client.api_call("show-task",{"task-id" : res_ipsvergw_task.data['tasks'][0]['task-id'],"details-level":"full"}).data['tasks'][0]['task-details'][0]['statusDescription'])
                    else:
                        output_text.update({"Message":"IP of "+args.hostname+"Changed but was unable to edit gateway object!"})
                        output_code.append("WARNING")
                else:
                    logging.debug("would send query to API:\n'run-script',{'script-name':'change interoperable devices ip','script': "+str_set_newip+",'targets' : "+args.apiserver+"}")
            else:
                output_text.update({"Message":"IP did not change - nothing to do!"})
                output_code.append("OK")

    if not args.nagios:
        print(output_text+"\n\n"+output_code)

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