#!/usr/bin/python
import sys, getopt
import re
import requests
from pymetasploit3.msfrpc import MsfRpcClient
import time
import csv
import ipaddress
import multiprocessing
import logging
import time

ip = "127.0.0.1"
user = "msf"
passwd = ""
halt = False

# stworzenie polaczenia

logging.basicConfig(filename='/var/log/msf_rdp_vuln_threads.log',format='%(asctime)s %(message)s',level=logging.INFO)
halt = False

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
parser.add_argument('-o', metavar='out-file', required=True, type=argparse.FileType('wt'))

global args
args = parser.parse_args()
    
try:
    results = parser.parse_args()
    print('Input file:', results.i)
    print('Output file:', results.o)
 
except IOError:
    print("Parser error")

#results.o.write(head_line)

c = MsfRpcClient(passwd,port=55552)
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

def smb_info_parser(nmap_results,host_ip):
    output_list=[]
    test=nmap_results._scan_result['scan'][host_ip]['hostscript']
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
def msf_init():
    console_number = c.consoles.console().cid
    
    print(console_number)
    busy_value = c.consoles.console(console_number).is_busy()


    while busy_value is True:
        busy_value = c.consoles.console(console_number).is_busy()

    console_output = c.consoles.console(console_number).read()
    print(console_output['data'])
    print("results check")
    while console_output['data'] is "":
                console_output = c.consoles.console(console_number).read()
    print(console_output)
    output = c.consoles.list
    print("-------console list-----------")
    print(output)
    return console_number

def msf_scan(ip_to_check,console_number):
    print("-------------------------start metasploit------------------------")
    output = c.consoles.console(console_number).write('use auxiliary/scanner/rdp/cve_2019_0708_bluekeep')
    output = c.consoles.console(console_number).write('set rhosts '+ip_to_check)
    print(output)
    #Check that RPC will return confirmation that set has been applied
    Scan_end = True
    Scan_end_int = 0
    while Scan_end is True: 
        
        output = c.consoles.console(console_number).read()
        if ip_to_check in str(output):
            Scan_end = False
        time.sleep(1) 
        Scan_end_int = Scan_end_int + 1
        if Scan_end_int > 900:
            Scan_end = False
            logging.info("proces: "+str(process_name)+" error  set rhosts time out  : "+str(ip_to_check))
            try:
                output = c.consoles.destroy(console_number)
                console_number = msf_init()
            except Exception as msf_init_error:
                logging.info("proces: "+str(process_name)+" error msf re-init console : "+str(msf_init_error))


    print(output)
    output = c.consoles.console(console_number).write('run')
    print("SCAN started")
    #Waiting until scan will finished 
    time.sleep(2) 
    busy_value = c.consoles.console(console_number).is_busy()
    print(busy_value)
    while busy_value is True:
        busy_value = c.consoles.console(console_number).is_busy()
        time.sleep(5)
    Scan_end = True
    Host_Vulnerable = False
    Scan_end_int = 0

    while Scan_end is True:
        output = c.consoles.console(console_number).read()
        if "The target is vulnerable" in str(output):
            Host_Vulnerable = True
        if "Auxiliary module execution completed" in str(output):
            Scan_end = False
        time.sleep(1)
        Scan_end_int = Scan_end_int + 1
        if Scan_end_int > 900:
            Scan_end = False
            logging.info("proces: "+str(process_name)+" error  msf scan time out  : "+str(ip_to_check))
            try:
                output = c.consoles.destroy(console_number)
                console_number = msf_init()

            except Exception as msf_init_error:
                logging.info("proces: "+str(process_name)+" error msf re-init console : "+str(msf_init_error))
    print(output)
    print("--------------imsf   SCAN fnished-----------")
    # checking if host is in vulns table 
    return Host_Vulnerable
def nmap_scan(ip_to_check):
    print("-------------------------start smb scan ----------------------")
    print("VULNERABLE")
    nm2.scan(ip_to_check,"445,139","--script smb-os-discovery.nse")
    test_scan_finished=nm2.all_hosts()
    test_scan_finished_len=len(test_scan_finished)
                # Check if the host has not been  switched off in the middle of scan 
    if test_scan_finished_len==0:
        to_file = ip_to_check+",RDP,Scan_error \n"
        l = file_contents[1]
        l.append(to_file)
        file_contents[1] = l
        print(to_file)
    else:
        output_scan=nm2._scan_result['scan'][ip_to_check]
 
        output_scan=str(output_scan)
        #check if script smb discovery script  list was able to got any info 
        scan_results_test="hostscript"
        if scan_results_test in output_scan:
            output=smb_info_parser(nm2,ip_to_check)
            for lists in output:
                host_list=lists.ip+",RDP,"+lists.Computer_name+","+lists.OS+","+lists.Domain+","+lists.Workgroup+","+lists.CPE+"\n"
                print(host_list)
                l = file_contents[1]
                l.append(host_list)
                file_contents[1] = l
                #results_write.write(host_list) 
        else:
            print(ip_to_check+",RDP,no_smb_info") 
            to_file = ip_to_check+",RDP,no_smb_info \n"
            l = file_contents[1]
            l.append(to_file)
            file_contents[1] = l
            print(to_file)
    print("---------------------end scan --------------------------------")


def metasploit(process_name,tasks,result_multi,results_write):
    # stworzenie consoli
    print('[%s] evaluation routine starts' % process_name)
    DB_check = True
    try: 
        console_number = msf_init()
    except Exception as msf_init_error:
        logging.info("proces: "+str(process_name)+" error  msf init : "+str(msf_init_error))


    while True:
        new_value = tasks.get()
        print("---------task check")
        print(new_value)
        if type(new_value) == int:
            #print('[%s] evaluation routine quits' % process_name)
            try:
                output = c.consoles.destroy(console_number)
                output = c.consoles.list

            except Exception as msf_init_error:
                logging.info("proces: "+str(process_name)+" error  destroy console : "+str(msf_init_error))
            print("-------console list-----------")
            print(output)
            result_multi.put(-1)
            logging.info("proces: "+str(process_name)+" termineted : ")
            break
        else:
            ip_to_check=new_value
            try:
                Host_Vulnerable = msf_scan(ip_to_check,console_number)
            except Exception as msf_error:
                logging.info("proces: "+str(process_name)+" error  msf scan   : "+str(msf_error)+"  "+str(ip_to_check))
                Host_Vulnerable = False
            if Host_Vulnerable:
                logging.info("proces: "+str(process_name)+" Vulnerable host  : "+str(ip_to_check))

                try:
                    nmap_scan(ip_to_check)
                except Exception as nmap_error:
                    logging.info("proces: "+str(process_name)+" error  nmap scan   : "+str(nmap_error)+"  "+str(ip_to_check))
logging.info("Scan started")
# Define IPC manager
manager = multiprocessing.Manager()
# Define a list (queue) for tasks and computation results
tasks = manager.Queue()
result_multi = manager.Queue()
# Create process pool , it can be increased or deacresed 
num_processes = 10
pool = multiprocessing.Pool(processes=num_processes)
processes = []

file_contents=manager.dict()
file_contents[1]=[]
for i in range(num_processes):
# Set process name
    process_name = 'P%i' % i
    # Create the process, and connect it to the worker function
    new_process = multiprocessing.Process(target=metasploit, args=(process_name,tasks,result_multi,file_contents))

    # Add new process to the list of processes
    processes.append(new_process)
    # Start the process
    new_process.start()
    # Fill task queue

counter=1
counter_test=1
counter_rescan=1
counter_str=""
Check_read = "READ"
#results.o.write(head_line)

with results.i as f:
        for line in f:
            print("=======================================")
            print(line)
            print("=======================================")

            #Starting scan for 445 and 139 smb ports
            nm.scan(line,'3389',"-sS")
            for host in nm.all_hosts():
                testhost=nm._scan_result['scan'][host]
                r2=nm._scan_result['scan'][host]['status']['state']
                r3=nm._scan_result['scan'][host]['tcp'][3389]['state']
                # when scanning large subnets, some ack can miss and it is marking open ports us filtered, need to scan againg it per ip is working fine
                if r2=="up" and r3 == "filtered"  :
                    if not r3 == "open" :
                        nm3=nmap.PortScanner()
                        port = 3389
                        port_str=str(port)
                        nm3.scan(host,port_str,"-sS")
                        test_scan_finished=nm3.all_hosts()
                        test_scan_finished_len=len(test_scan_finished)
						# Check if the server has not been switched off in the middle of scan 
                        if test_scan_finished_len==0:
                            results.o.write(host+",Scan_error,"+port_str+" \n")
                        elif r2=="up":
                            r3=nm3._scan_result['scan'][host]['tcp'][port]['state']
                        if r3=="open":
                            counter_rescan=counter_rescan+1
                        counter_rescan_str=str(counter_rescan)
                        print(host+" rescanned "+counter_rescan_str)
				#if ports are open start smb discovery  script						
                print(host+","+r2+","+r3+",")
                if r2=="up" and r3 == "open":
                    print("----sent   host for scan ----")
                    tasks.put(host,file_contents)

for i in range(num_processes):
        tasks.put(-1)						
       
num_finished_processes = 0
        
while True:
    new_result = result_multi.get()
    if new_result == -1:
        num_finished_processes += 1
        if num_finished_processes == num_processes:
            break
        else:
            # Output result
            print('Process closed ')



head_line="IP,vulnerable service,Computer_name,OS,Domain,Workgroup,CPE\n"
results.o.write(head_line)
print(file_contents)
for item in file_contents[1]:
    results.o.write(item)
print("Number of host from with one has been received smb info:")
print(counter)
print("Number host with open smb ports:")
print(counter_test)
print("Successfully rescans:")
print(counter_rescan)
results.o.close()
results.i.close()

logging.info("Scan ended")

