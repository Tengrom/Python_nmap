#!/usr/bin/python

import sys, getopt
import csv
import ipaddress
import pprint
import logging
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta, tzinfo
from calendar import timegm
import time
import sys
import pysnow
import configparser
#import pymssql
halt = False
logging.basicConfig(filename='/var/log/ms17_010_SN.log',format='%(asctime)s %(message)s',level=logging.INFO)
try:
    import argparse
    import nmap
except ImportError:
    print('Missing needed module: argparse or nmap')
    halt = True
    if halt:
        sys.exit()

parser = argparse.ArgumentParser()
parser.add_argument('-i', metavar='in-file', required=True, type=argparse.FileType('rt'))

global args
args = parser.parse_args()
    
try:
    results = parser.parse_args()
    print('Input file:', results.i)
 
except IOError:
    print("Parser error")
config = configparser.ConfigParser()
#path to  config
try:
            config.read('/root/script/Auto.cfg')
except Exception as conf:
            print("error loading config : "+conf)

SNusername = config['DEFAULT']['SNuser']
SNpassword = config['DEFAULT']['SNpass']
SNinstance = config['DEFAULT']['SNinstance']

#range scan 
nm=nmap.PortScanner()
#UDP scan
nm2=nmap.PortScanner()
#TCP scan 
nm3=nmap.PortScanner()
class SMB_host:
    def __init__(self, ip):
        self.ip = ip
        self.OS=""
        self.Computer_name=""
        self.Domain=""
        self.Workgroup=""
        self.CPE=""
        self.Dialects=""
        self.SMBv1=""
    def add_OS(self, OS):
        self.OS=OS
 
    def add_Computer_name(self, Computer_name):
        self.Computer_name=Computer_name

    def add_Domain(self, Domain):
        self.Domain=Domain
    
    def add_Workgroup(self, Workgroup):
        self.Workgroup=Workgroup

    def add_CPE(self, CPE):
        self.CPE=CPE
    
    def add_Dialects(self, Dialects):
        self.Dialects=Dialects
	
    def add_SMBv1(self, SMBv1):
        self.SMBv1=SMBv1

def servicenow(Hostname,IP,Site,Domain,Workgroup,OS):
    c = pysnow.Client(instance=SNinstance, user=SNusername, password=SNpassword)
    # First checking if there is already ticket for that hostname
    incident = c.resource(api_path='/table/incident')
    qb='problem_id='+config['SN_wannacry']['problem_id']+'^short_descriptionLIKE '+Hostname+' ^ORdescriptionLIKE '+Hostname+' '
    response = incident.get(query=qb)
    flag_closed=False
    flag_reopen=False
    flag_active=False
    # Create new one or reopen old one

    short_describtion="Vulnerability  for WannaCry  for IP: "+IP+" , Site: "+Site+" , Computer Name: "+Hostname +" , Domain or workgoup: "+Domain+Workgroup+" , OS :"+OS
    describtion="Computer is vulnerable."
    new_record = {
                'short_description': short_describtion,
                'description': describtion,
                #'assignment_group':'0f47328314ac0100c464ca1c2a709885',
                'caller_id': config['SN_wannacry']['caller_id'],
                'category':  config['SN_wannacry']['category'],
		'priority':'3 - Moderate',
		'problem_id': config['SN_wannacry']['problem_nb']
		
                }
    if response.all():
        for respons in response.all():
            if respons['state'] == "6":
                flag_reopen=True
                reopen_ticket=respons['number']
            elif respons['state'] == "7":
                flag_closed=True
            else:
                flag_active=True
                ticket_number=respons['number']
                print(respons['state']+" "+respons['number'])
        if not flag_active and flag_reopen :
             
            r = c.query(table='incident', query={'number': reopen_ticket})
            ticket_number=reopen_ticket
            result = r.update({'work_notes': 'Host still vulnerable please patch again and clean', 'close_code': '', 'state': '2'})
            print("Ticket "+result['number']+" state was successfully changed to "+result['state'])

            
        elif not flag_active and flag_closed:  
            result = incident.create(payload=new_record)
            print("Ticket already closed new ticket createt "+result['number'])

            ticket_number=result['number']
    
    
    else:
        result = incident.create(payload=new_record)
        print("New ticket  createt "+result['number'])
        ticket_number=result['number']
    return ticket_number
		
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000
period = datetime.utcnow() - timedelta(days=30)
def filetime_to_dt(ft):
            return datetime.utcfromtimestamp((ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
        #print("yes")



        

#print(row[1]+" "+row[2]+" "+row[5]+" "+value)

def smb_info_parser(nmap_results,host_ip):
    output_list=[]
    test=nmap_results._scan_result['scan'][host]['hostscript']
    Network_class=SMB_host(host_ip)
    output_list.append(Network_class)
    
    for output in test:
        if output['id'] == "smb-os-discovery":
            OS_re = re.compile('(?<=OS:).*')
            OS = OS_re.search(output['output'])
            if OS:
                OS=OS.group().strip()
                Network_class.add_OS(OS)
            Computer_name_re=re.compile('(?<=Computer name:).*')
            Computer_name = Computer_name_re.search(output['output'])
            if Computer_name:
                Computer_name=Computer_name.group().strip()
                Network_class.add_Computer_name(Computer_name)
            Workgroup_re=re.compile('(?<=Workgroup:).*')
            Workgroup = Workgroup_re.search(output['output'])
            if Workgroup:
                Workgroup=Workgroup.group().strip()
                Network_class.add_Workgroup(Workgroup)
            Domain_name_re=re.compile('(?<=Domain name:).*')
            Domain_name = Domain_name_re.search(output['output'])
            if Domain_name:
                Domain_name=Domain_name.group().strip()
                Network_class.add_Domain(Domain_name)
            OS_CPE_re=re.compile('(?<=OS CPE:).*')
            OS_CPE = OS_CPE_re.search(output['output'])
            if OS_CPE:
                OS_CPE=OS_CPE.group().strip()
                Network_class.add_CPE(OS_CPE)
        elif output['id'] == "smb-protocols":
            dialects_re =  re.compile('\d\.\d\d')
            dialects = dialects_re.findall(output['output'])
            if dialects:
                dialects='/'.join(dialects)
                Network_class.add_Dialects(dialects)
            if "SMBv1" in output['output']:
                Network_class.add_SMBv1("Enabled")

    return output_list


counter=1
counter_test=1
counter_rescan=1
counter_str=""
Check_read = "READ"
logging.info("scan started")
with results.i as f:
        for line in f:

            #Starting scan for 445 and 139 smb ports
            nm.scan(line,'445,139',"-sS")
            for host in nm.all_hosts():
                testhost=nm._scan_result['scan'][host]
                r2=nm._scan_result['scan'][host]['status']['state']
                r3=nm._scan_result['scan'][host]['tcp'][445]['state']
                r4=nm._scan_result['scan'][host]['tcp'][139]['state']
                # when scanning large subnets, some ack can miss and it is marking open ports us filtered, need to scan againg it per ip is working fine
                if r2=="up" and (r3 == "filtered" or r4 == "filtered") :
                    if not (r3 == "open" or r4 == "open"):
                        nm3=nmap.PortScanner()
                        if r3 == "open" :
                            port = 445
                        else:
                            port = 139
                        port_str=str(port)
                        nm3.scan(host,port_str,"-sS")
                        test_scan_finished=nm3.all_hosts()
                        test_scan_finished_len=len(test_scan_finished)
						# Check if the server has not been switched off in the middle of scan 
                        if test_scan_finished_len==0:
                            logging.info(host+",Scan_error,"+port_str)

                        elif r2=="up":
                            r3=nm3._scan_result['scan'][host]['tcp'][port]['state']
                        if r3=="open":
                            counter_rescan=counter_rescan+1
                        counter_rescan_str=str(counter_rescan)
						#if ports are open start smb discovery  script						
                if r2=="up" and (r3 == "open" or r4 == "open"):
                    if r3 == "open" :
                        port_str = "445"
                    else:
                        port_str = "139"
                    counter_test=counter_test+1
                    nm2.scan(host,port_str,"--script smb-vuln-ms17-010")
                    
                    #nm2.scan(host,port_str,"--script smb-os-discovery.nse,smb-protocols.nse ")
                    test_scan_finished=nm2.all_hosts()
                    test_scan_finished_len=len(test_scan_finished)
					# Check if the host has not been  switched off in the middle of scan 
                    if test_scan_finished_len==0:
                        logging.info(host+",Scan_error,"+port_str)

                    else:
                        output_scan=nm2._scan_result['scan'][host]
                         
                        output_scan=str(output_scan)
                        #check if script smb discovery script  list was able to got any info 
                        scan_results_test="VULNERABLE"
                        if scan_results_test in output_scan:
                            VULNERABLE="VULNERABLE"
                        else:
                            VULNERABLE="CLEAN"
                        nm2.scan(host,port_str,"--script smb-os-discovery.nse")
                        test_scan_finished=nm2.all_hosts()
                        test_scan_finished_len=len(test_scan_finished)
                                    # Check if the host has not been  switched off in the middle of scan 
                        if test_scan_finished_len==0:
                            logging.info(host+",Scan_error,"+port_str)

                        else:
                            output_scan=nm2._scan_result['scan'][host]
                     
                            output_scan=str(output_scan)
                            #check if script smb discovery script  list was able to got any info 
                            scan_results_test="hostscript"
                            if scan_results_test in output_scan:

                                output=smb_info_parser(nm2,host)
                                counter_str=str(counter)
                                for lists in output:
                                    sites_results=""

                                    host_list=lists.ip+","+sites_results+","+VULNERABLE+",,,"+lists.Computer_name+","+lists.OS+","+lists.Domain+","+lists.Workgroup+","+lists.CPE+"\n"
                                    
                                    #logging.info(host_list)
                                    

                                    counter=counter+1
                                    hostname=lists.Computer_name
                                    IP=lists.ip
                                    OS=lists.OS
                                    Domain=lists.Domain
                                    Workgroup=lists.Workgroup
                            else:
                                if "." in host:
                                    IP=host
                                elif "." in line:
                                    IP=line
                                sites_results=""
                                smb_info="no_smb_info"
                                line=line.rstrip()
                                logging.info(host+","+sites_results+","+VULNERABLE+",,,"+line+","+smb_info)

                        if VULNERABLE=="VULNERABLE":
                            if not hostname:
                                hostname=host
                                IP=host
                                OS=""
                                Domain=""
                                Workgroup=""
                            if sites_results:
                                Site=""
                            else:
                                Site=""
                            ticket_number=servicenow(hostname,IP,Site,Domain,Workgroup,OS)
                            
                            logging.info("Vulnerable host: "+IP+" "+Site+" "+hostname+" "+str(ticket_number))
logging.info("scan completed")
results.i.close()


