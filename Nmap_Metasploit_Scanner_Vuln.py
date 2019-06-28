#!/usr/bin/python3
'''
    Discovery devices using nmap and scaning them using Metasploit vulnerability scanner ,
if devices is vulnerable script will gather SMB info about OS and domain .
List of IP are recorded in metasploit DB.
Errors and script infos are recorded in /var/log/msf_rdp_vuln.log

Steps:
    1. Scanning of subnets or IPs from file for open interesting port
    2. Rescanning when there are probability of missing packets
    3. Checking if device is vulnerable using Metasploit modules listed in provided file
    4. Gathering more information about device using nmap script port is opened and device is vulnerable.
    5. Results are recorded in Metasploit DB and in provided output file

Usage:
    Nmap_Metasploit_Scanner_Vuln.py [-h] -i in-subnets_list_csv -l in-vuln_list_csv -o out-file

    Example of subnets_list_csv:

        10.10.10.10
        192.168.0.024

    Example of vuln_list_csv with structure,
    <port to scan>,<path to metasploit module>,< cve or ms in module name>:

        3389,auxiliary/scanner/rdp/cve_2019_0708_bluekeep,CVE-2019-0708
        445,auxiliary/scanner/smb/smb_ms17_010,MS17-010

    To be sure that module will be discovered by script run:
    'search path:auxiliary/scanner/rdp/cve_2019_0708_bluekeep type:auxiliary name:CVE-2019-0708'
    in metasploit console

    Script is using that library "https://github.com/DanMcInerney/pymetasploit3"

    Before use: run metasploit and check if db is connected in metasploit:

        db_status

    if db is connected to msf run msfrpcd:

        msfrpcd -P yourpassword -S

    password type in the script in variable MSF_PASSWD
'''
from __future__ import print_function
import sys
import re
import csv
import logging
import time
from pymetasploit3.msfrpc import MsfRpcClient

MSF_PASSWD = ""

# stworzenie polaczenia
LOG_FILE_PATH = '/var/log/msf_rdp_vuln.log'
logging.basicConfig(filename=LOG_FILE_PATH, format='%(asctime)s %(message)s', level=logging.INFO)
HALT = False
try:
    import argparse
    import nmap
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

GLOBAL_COUNTER_RESCAN = 0
#Port can change
GLOBAL_C = MsfRpcClient(MSF_PASSWD, port=55552)

def msf_init():
    '''
    create console to interact with MSF and checking if msf is connected to DB
    '''
    local_console_number = GLOBAL_C.consoles.console().cid
    busy_value = GLOBAL_C.consoles.console(local_console_number).is_busy()
    while busy_value is True:
        busy_value = GLOBAL_C.consoles.console(local_console_number).is_busy()
    console_output = GLOBAL_C.consoles.console(local_console_number).read()
    while not console_output['data']:
        console_output = GLOBAL_C.consoles.console(local_console_number).read()
    GLOBAL_C.consoles.console(local_console_number).write('db_status')
    busy_value = GLOBAL_C.consoles.console(local_console_number).is_busy()
    while busy_value is True:
        busy_value = GLOBAL_C.consoles.console(local_console_number).is_busy()
    console_output = GLOBAL_C.consoles.console(local_console_number).read()
    if "Connected to msf" in str(console_output):
        logging.info("DB connected do msf ")
    else:
        local_console_number = False
        GLOBAL_C.consoles.destroy(local_console_number)
        print('\x1b[0;31;40m'+"ERROR DB not connected to MSF "'\x1b[0m')

        logging.error("error DB not connected to MSF ")

    return local_console_number

GLOBAL_CONSOLE_NUMBER = msf_init()
if not GLOBAL_CONSOLE_NUMBER:
    print("ERROR DB not connected to MSF please check connection to DB and restart MSGRPC and then run script".center(190, "!"))
    sys.exit()

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
            regex = re.compile('(?<=Workgroup_host:).*')
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

def vuln_check(vuln):
    '''
    checking if path , vuln name is correct from provided csv
    '''
    GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).write('search path:'+vuln[1]+' type:auxiliary '+'name:'+vuln[2])
    busy_value = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).is_busy()
    while busy_value is True:
        busy_value = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).is_busy()
    console_output = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).read()
    results_vuln_check = bool(console_output['data'])
    return results_vuln_check


def msf_scan(ip_to_check, row_i):
    '''
    starting msf vuln scan
    '''
    ip_to_check_str = str(ip_to_check)
    print("Start Metasploit".center(190, "-"))
    local_output = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).write('use '+row_i[1])
    local_output = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).write('set rport '+row_i[0])
    local_output = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).write('set rhosts '+ip_to_check)
    #Check that RPC will return confirmation that set has been applied
    scan_end = True
    scan_end_int = 0
    while scan_end is True:
        local_output = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).read()
        if ip_to_check in str(local_output):
            scan_end = False
        time.sleep(1)
        scan_end_int = scan_end_int + 1
        if scan_end_int > 900:
            scan_end = False
            logging.error("error  set rhosts time out  : %s", ip_to_check_str)
    local_output = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).write('run')
    #Waiting until scan will finished
    busy_value = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).is_busy()
    while busy_value is True:
        busy_value = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).is_busy()
        time.sleep(5)
    scan_end = True
    host_vulnerable = False
    scan_end_int = 0
    while scan_end is True:
        local_output = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).read()
        if "Auxiliary module execution completed" in str(local_output):
            scan_end = False
        time.sleep(1)
        scan_end_int = scan_end_int + 1
        if scan_end_int > 900:
            scan_end = False
            logging.error("error  msf scan time out  : %s ", ip_to_check_str)
    # checking if host is in vulns table
    local_output = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).write('vulns '+ip_to_check_str)
    busy_value = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).is_busy()
    while busy_value is True:
        busy_value = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).is_busy()
    results_vulns = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).read()
    while not results_vulns['data']:
        results_vulns = GLOBAL_C.consoles.console(GLOBAL_CONSOLE_NUMBER).read()
    if ip_to_check in str(results_vulns) and row_i[2] in str(results_vulns):
        host_vulnerable = True
        print('\x1b[1;33;41m'+"HOST "+ip_to_check_str+" VULNERABLE"+'\x1b[0m')
    else:
        print('\x1b[0;32;40m'+"Host "+ip_to_check_str+" clean"+'\x1b[0m')
    print("Metasploit SCAN fnished".center(190, "-"))
    return host_vulnerable



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
        else:
            print(ip_to_check+","+str(vuln_name)+",no_smb_info")
            to_file = ip_to_check+","+str(vuln_name)+",no_smb_info \n"
            GLOBAL_RESULTS_PARSER.o.write(to_file)
    print("End SMB scan ".center(190, "-"))


def nmap_sync_scan(local_line, local_row):
    '''
    Fast syn scan to check if provided port is open, if it is open start msf vuln scan
    '''
    global GLOBAL_COUNTER_RESCAN
    #sync scan
    local_nm = nmap.PortScanner()
    #TCP rescan
    nm3 = nmap.PortScanner()
    print("Start scanning".center(190, "="))
    print('{:^190}'.format(local_line))
    print("==============".center(190, "="))

    #Starting scan for 445 and 139 smb ports
    local_nm.scan(local_line, local_row[0], "-sS")
    for host in local_nm.all_hosts():
        host_str = str(host)
        host_status = local_nm._scan_result['scan'][host]['status']['state']
        port_statu = local_nm._scan_result['scan'][host]['tcp'][int(local_row[0])]['state']
        # when scanning large complex subnets, some ack can miss and it is marking open ports us filtered, need to scan againg it per ip is working fine. In normal enviroment it can be removed
        if host_status == "up" and port_statu == "filtered":
            if not port_statu == "open":
                port = int(local_row[0])
                port_str = str(port)
                nm3.scan(host, port_str, "-sS")
                test_scan_finished_len = len(nm3.all_hosts())
                # Check if the server has not been switched off in the middle of scan
                if test_scan_finished_len == 0:
                    GLOBAL_RESULTS_PARSER.o.write(host+",Scan_error,"+port_str+" \n")
                elif host_status == "up":
                    port_statu = nm3._scan_result['scan'][host]['tcp'][port]['state']
                if port_statu == "open":
                    GLOBAL_COUNTER_RESCAN = GLOBAL_COUNTER_RESCAN+1
         #if ports are open start smb discovery  scripit
        print(host+","+host_status+","+port_statu+",")
        if host_status == "up" and port_statu == "open":
            try:
                host_vulnerable = msf_scan(host, local_row)
            except Exception as msf_error:
                logging.error(" error  msf scan : %s  %s ", str(msf_error), host_str)
                host_vulnerable = False
                print('\x1b[0;31;40m'+"ERROR MSF SCAN : "+str(msf_error)+'\x1b[0m')

            if host_vulnerable:
                logging.info(" Vulnerable host  : %s", host_str)
                try:
                    nmap_scan(host, local_row[2])
                except Exception as nmap_error:
                    logging.error("error  nmap scan: %s  %s ", str(nmap_error), host_str)
                    print('\x1b[0;31;40m'+"ERROR NMAP SCAN : "+str(msf_error)+'\x1b[0m')

logging.info("Scan started")
HEAD_LINE = "IP,vulnerable service,computer_name,OS,Domain,workgroup_host,CPE\n"
GLOBAL_RESULTS_PARSER.o.write(HEAD_LINE)
LINES = csv.reader(GLOBAL_RESULTS_PARSER.l, delimiter=',', quotechar='|')
for row in LINES:
    print("=".center(190, "="))
    print(("Start scan using MSF module "+row[1]).center(190, "="))
    vuln_check_r = vuln_check(row)
    if vuln_check_r:
        FILE_SUBNETS = open(GLOBAL_RESULTS_PARSER.i)
        with FILE_SUBNETS as f:
            for line in f:
                nmap_sync_scan(line, row)
    else:
        print('\x1b[0;31;40m'+"Path to Metasploit scanner module  is wrong or it is not auxiliry scanner or provided vuln name is not in module name "+'\x1b[0m')
GLOBAL_C.consoles.destroy(GLOBAL_CONSOLE_NUMBER)
DESTROY_OUTPUT = GLOBAL_C.consoles.list
print("Successfully rescans:")
print(GLOBAL_COUNTER_RESCAN)
GLOBAL_RESULTS_PARSER.o.close()
FILE_SUBNETS.close()
GLOBAL_RESULTS_PARSER.l.close()
logging.info("Scan ended")
