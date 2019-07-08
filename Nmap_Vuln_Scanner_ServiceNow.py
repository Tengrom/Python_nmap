#!/usr/bin/python
'''
    Discovery devices using nmap and scaning them using nmap script to check if are vulnerable,
if devices is vulnerable script will gather SMB info about OS and domain . After detection of vulnerable device script will check if there is ticket in SeviceNow , if not it will create new one or if ticket has been resolved it will reopen it . 
Errors and script infos are recorded in /var/log/nmap_vuln_sn.log

Steps:
    1. Scanning of subnets or IPs from file for open interesting port
    2. Rescanning when there are probability of missing packets
    3. Checking if device is vulnerable using nmap scripts in provided file
    4. Gathering more information about device using nmap script port is opened and device is vulnerable.
    5. After detection of vulnerable device script will check if there is ticket in SeviceNow , if not it will create new one or if ticket has been resolved it will reopen it . 
    6. Results are recorded in csv 
    

Usage:
    Nmap_Vuln_Scanner_ServiceNow.py [-h] -i in-subnets_list_csv -l in-vuln_list_csv -o out-file

    Example of subnets_list_csv:

        10.10.10.10
        192.168.0.0/24

    Example of vuln_list_csv with structure,
    <port to scan>,<path to metasploit module>,< cve or ms in module name>:
        
        139;445,smb-vuln-ms17-010,ms17-010

    Before use: create configuration file in /root/script/Auto.cfg:
    Default part of config contain credentionals to ServiceNow, second(nmap) details to create ticket in ServiceNow

        [DEFAULT]
        SNuser = some_one 
        SNpass = strong_password_complex
        SNinstance = devsomething
        [nmap]
        problem_id = 5bc1c9b44f9e2w22cb22w2ww2210c73e
        caller_id = 5we222bf5d22www2d412eb53d22f2de2
        category = Virus / Malware
        problem_nb = PRB2222222
        assignment_group = 0f47328314ww0100w464ww1w2w709885



'''
from __future__ import print_function
import sys
import re
import csv
import logging
import time
import configparser


# stworzenie polaczenia
LOG_FILE_PATH = '/var/log/nmap_vuln_sn.log'
logging.basicConfig(filename=LOG_FILE_PATH, format='%(asctime)s %(message)s', level=logging.INFO)
HALT = False
try:
    import argparse
    import nmap
    import pysnow

except ImportError:
    print('Missing needed module: argparse or nmap')
    HALT = True
    if HALT:
        sys.exit()

PARSER = argparse.ArgumentParser()
PARSER.add_argument('-i', metavar='in-subnets_list_csv', required=True, type=None)
PARSER.add_argument('-l', metavar='in-vuln_list_csv', required=True, type=argparse.FileType('rt'))

PARSER.add_argument('-o', metavar='out-file', required=True, type=argparse.FileType('wt'))


ARGS = PARSER.parse_args()
try:
    GLOBAL_RESULTS_PARSER = PARSER.parse_args()
    print('Input file:', GLOBAL_RESULTS_PARSER.i)
    print('Input vfile:', GLOBAL_RESULTS_PARSER.l)
    print('Output file:', GLOBAL_RESULTS_PARSER.o)
except IOError:
    print("Parser error")


CONFIG = configparser.ConfigParser()
#path to  config
try:
    CONFIG.read('/root/script/Auto.cfg')
except Exception as conf:
    print("error loading config : "+conf)

SN_USERNAME = CONFIG['DEFAULT']['SNuser']
SN_PASSWORD = CONFIG['DEFAULT']['SNpass']
SN_INSTANCES = CONFIG['DEFAULT']['SNinstance']

def servicenow(computer_hostname, computer_ip, computer_domain, computer_workgroup, computer_os):
    '''
    Function is checking if there is already ticket for device if now create new one. If ticket is resolve it will reopen it if device is still vulnerable
    '''
    pysnow_c = pysnow.Client(instance=SN_INSTANCES, user=SN_USERNAME, password=SN_PASSWORD)
    # First checking if there is already ticket for that hostname
    incident = pysnow_c.resource(api_path='/table/incident')
    query_pysnow = 'problem_id='+CONFIG['nmap']['problem_id']+'^short_descriptionLIKE '+computer_hostname+' ^ORdescriptionLIKE '+computer_hostname+' '
    response = incident.get(query=query_pysnow)
    short_describtion = "Vulnerability  for WannaCry  for IP: "+computer_ip+" , Computer Name: "+computer_hostname +" , Domain or workgoup: "+computer_domain+computer_workgroup+" , OS :"+computer_os
    describtion = "Computer is vulnerable. "
    new_record = {
        'short_description': short_describtion,
        'description': describtion,
        'assignment_group':CONFIG['nmap']['assignment_group'],
        'caller_id': CONFIG['nmap']['caller_id'],
        'category':  CONFIG['nmap']['category'],
        'priority':'3 - Moderate',
        'problem_id': CONFIG['nmap']['problem_nb']}
    flag_closed = False
    flag_reopen = False
    flag_active = False
    # Create new one or reopen old one
    if response.all():
        for respons in response.all():
            if respons['state'] == "6":
                flag_reopen = True
                reopen_ticket = respons['number']
            elif respons['state'] == "7":
                flag_closed = True
            else:
                flag_active = True
                ticket_number = respons['number']
                print(respons['state']+" "+respons['number'])
        if not flag_active and flag_reopen:

            pysnow_query = pysnow_c.query(table='incident', query={'number': reopen_ticket})
            ticket_number = reopen_ticket
            result = pysnow_query.update({'work_notes': 'Host still vulnerable please patch again and clean', 'close_code': '', 'state': '2'})
            print("Ticket "+result['number']+" state was successfully changed to "+result['state'])


        elif not flag_active and flag_closed:
            result = incident.create(payload=new_record)
            print("Ticket already closed new ticket createt "+result['number'])

            ticket_number = result['number']


    else:
        result = incident.create(payload=new_record)
        print("New ticket  createt "+result['number'])
        ticket_number = result['number']
    return ticket_number


GLOBAL_COUNTER_RESCAN = 0
#Port can change


class SMBHost:
    '''
    Class to contain parsered information from nmap smb-os-discovery script
    '''
    def __init__(self, data):
        self.local_ip = data
        self.computer_os = ""
        self.computer_name = ""
        self.computer_domain = ""
        self.workgroup_host = ""
        self.os_cpe = ""
        self.smb_dialects = ""
        self.smb_1 = ""
    def add_os(self, data):
        '''
        Contain information about device OS
        '''
        self.computer_os = data
    def add_computer_name(self, data):
        '''
        Contain information about device name
        '''
        self.computer_name = data
    def add_domain(self, data):
        '''
        Contain information about device AD domain
        '''
        self.computer_domain = data
    def add_workgroup(self, data):
        '''
        Contain information about device Workgroup
        '''
        self.workgroup_host = data
    def add_cpe(self, data):
        '''
        Contain information about device OS CPE
        '''
        self.os_cpe = data
    def add_dialects(self, data):
        '''
        Contain information about device SMB Dialects
        Not used in script, for future use
        '''
        self.smb_dialects = data
    def add_smbv1(self, data):
        '''
        Contain information about if device use  SMBv1
        Not used in script, for future use
        '''
        self.smb_1 = data

def smb_info_parser(host_ip, nm2):
    '''
    Function is parsing interesting data like OS , Domain ...
    from output of smb-os-discovery nmap script to SMBHost class
    '''
    output_list = []
    local_scan_results = nm2._scan_result['scan'][host_ip]['hostscript']
    network_class = SMBHost(host_ip)
    output_list.append(network_class)

    for local_output in local_scan_results:
        if local_output['id'] == "smb-os-discovery":
            regex = re.compile('(?<=OS:).*')
            computer_os = regex.search(local_output['output'])
            if computer_os:
                computer_os = computer_os.group().strip()
                network_class.add_os(computer_os)
            regex = re.compile('(?<=Computer name:).*')
            computer_name = regex.search(local_output['output'])
            if computer_name:
                computer_name = computer_name.group().strip()
                network_class.add_computer_name(computer_name)
            regex = re.compile('(?<=Workgroup:).*')
            workgroup_host = regex.search(local_output['output'])
            if workgroup_host:
                workgroup_host = workgroup_host.group().strip()
                network_class.add_workgroup(workgroup_host)
            regex = re.compile('(?<=Domain name:).*')
            domain_name = regex.search(local_output['output'])
            if domain_name:
                domain_name = domain_name.group().strip()
                network_class.add_domain(domain_name)
            regex = re.compile('(?<=OS CPE:).*')
            os_cpe = regex.search(local_output['output'])
            if os_cpe:
                os_cpe = os_cpe.group().strip()
                network_class.add_cpe(os_cpe)
        elif local_output['id'] == "smb-protocols":
            regex = re.compile('\d\.\d\d')
            dialects = regex.findall(local_output['output'])
            if dialects:
                dialects = '/'.join(dialects)
                network_class.add_dialects(dialects)
            if "SMBv1" in local_output['output']:
                network_class.add_smbv1("Enabled")

    return output_list


def nmap_scan(ip_to_check, vuln_name):
    '''
    scaning nmap to gather information about hosts
    '''
    nm2 = nmap.PortScanner()
    print("Start SMB scan".center(190, "-"))
    nm2.scan(ip_to_check, "445,139", "--script smb-os-discovery.nse")
    test_scan_finished = nm2.all_hosts()
    test_scan_finished_len = len(test_scan_finished)
    # Check if the host has not been  switched off in the middle of scan
    if test_scan_finished_len == 0:
        to_file = ip_to_check+","+str(vuln_name)+",Scan_error \n"
        GLOBAL_RESULTS_PARSER.o.write(to_file)
        print(to_file)
    else:
        output_scan = nm2._scan_result['scan'][ip_to_check]
        output_scan = str(output_scan)
        #check if script smb discovery script  list was able to got any info
        scan_results_test = "hostscript"
        if scan_results_test in output_scan:
            local_output = smb_info_parser(ip_to_check, nm2)
            for lists in local_output:
                host_list = lists.local_ip+","
                host_list = host_list+str(vuln_name)+","
                host_list = host_list+lists.computer_name+","
                host_list = host_list+lists.computer_os+","
                host_list = host_list+lists.computer_domain+","
                host_list = host_list+lists.workgroup_host+","
                host_list = host_list+lists.os_cpe+"\n"
                print(host_list)
                GLOBAL_RESULTS_PARSER.o.write(host_list)
                ticket_number = servicenow(lists.computer_name, lists.local_ip, lists.computer_domain, lists.workgroup_host, lists.computer_os)
                logging.info("Vulnerable host: "+str(lists.local_ip)+" "+lists.computer_name+" "+str(ticket_number))
        else:
            print(ip_to_check+","+str(vuln_name)+",no_smb_info")
            to_file = ip_to_check+","+str(vuln_name)+",no_smb_info \n"
            GLOBAL_RESULTS_PARSER.o.write(to_file)
            ticket_number = servicenow(ip_to_check, ip_to_check, "", "", "")
            logging.info("Vulnerable host: "+ip_to_check+" "+ip_to_check+" "+str(ticket_number))
    print("End SMB scan ".center(190, "-"))

def nmap_sync_scan(local_line, local_row):
    '''
    Fast syn scan to check if provided port is open, if it is open start msf vuln scan
    '''
    global GLOBAL_COUNTER_RESCAN
    #sync scan
    port_filtered = ""
    port_str = ""
    local_nm = nmap.PortScanner()
    #TCP rescan
    local_nm3 = nmap.PortScanner()
    #script vuln check
    local_nm2 = nmap.PortScanner()
    print("Start scanning".center(190, "="))
    print('{:^190}'.format(local_line))
    print("==============".center(190, "="))
    if ";" in local_row[0]:
        local_row[0] = local_row[0].replace(";", ",")
    #Starting scan for 445 and 139 smb ports
    local_nm.scan(local_line, local_row[0], "-sS")
    for host in local_nm.all_hosts():
        host_str = str(host)
        host_status = local_nm._scan_result['scan'][host_str]['status']['state']
        host_tcp = local_nm._scan_result['scan'][host]['tcp']
        for port_nr in host_tcp:
            port_state = local_nm._scan_result['scan'][host]['tcp'][port_nr]['state']
            if port_state == "open":
                port_str = str(port_nr)
            if port_state == "filtered":
                port_filtered = str(port_nr)
	# when scanning large complex subnets, some ack can miss and it is marking open ports us filtered, need to scan againg it per ip is working fine. In normal enviroment it can be removed
       	if host_status == "up" and port_filtered != "" and port_str == "":
            for port_nr in host_tcp:
                port_nr_str = str(port_nr)
                port_state = local_nm._scan_result['scan'][host]['tcp'][port_nr]['state']
                if port_state == "filtered":
                    local_nm3.scan(host, port_nr_str, "-sS")
                    test_scan_finished = local_nm3.all_hosts()
                    test_scan_finished_len = len(test_scan_finished)
                    # Check if the server has not been switched off in the middle of scan
                    if test_scan_finished_len == 0:
                        logging.info(host+",Scan_error,"+port_nr_str)
                    else:
                        r4_rescan = local_nm3._scan_result['scan'][host]['tcp']

                        if port_nr_str in str(r4_rescan):
                            port_state = local_nm3._scan_result['scan'][host]['tcp'][port_nr]['state']
                            if port_state == "open":
                                port_str = str(port_nr)
                                print("rescanned "+str(host) +" "+port_str)
                                GLOBAL_COUNTER_RESCAN = GLOBAL_COUNTER_RESCAN+1 
        #if ports are open start smb discovery  scripit
        print(host+","+host_status+","+port_state+",")
        if host_status == "up" and port_state == "open":
            local_nm2.scan(host, port_str, "--script "+local_row[1])
            test_scan_finished = local_nm2.all_hosts()
            test_scan_finished_len = len(test_scan_finished)
            if test_scan_finished_len == 0:
                logging.info(host+",Scan_error,"+port_str)
            else:
                output_scan = local_nm2._scan_result['scan'][host]
                output_scan = str(output_scan)
		#check if script smb discovery script  list was able to got any info
                scan_results_test = "VULNERABLE"
                if scan_results_test in output_scan:
                    logging.info(" Vulnerable host  : %s", host_str)
                    try:
                        nmap_scan(host, local_row[2])
                    except Exception as nmap_error:
                        logging.error("error  nmap scan: %s  %s ", str(nmap_error), host_str)
                        print('\x1b[0;31;40m'+"ERROR NMAP SCAN : "+str(nmap_error)+'\x1b[0m')
logging.info("Scan started")
HEAD_LINE = "IP,vulnerable service,computer_name,OS,Domain,workgroup_host,CPE\n"
GLOBAL_RESULTS_PARSER.o.write(HEAD_LINE)
LINES = csv.reader(GLOBAL_RESULTS_PARSER.l, delimiter=',', quotechar='|')
for row in LINES:
    print("=".center(190, "="))
    print(("Start scan using nmap  module "+row[1]).center(190, "="))
    FILE_SUBNETS = open(GLOBAL_RESULTS_PARSER.i)
    with FILE_SUBNETS as f:
        for line in f:
            nmap_sync_scan(line, row)
print("Successfully rescans:")
print(GLOBAL_COUNTER_RESCAN)
GLOBAL_RESULTS_PARSER.o.close()
FILE_SUBNETS.close()
GLOBAL_RESULTS_PARSER.l.close()
logging.info("Scan ended")
