#!/usr/bin/python
import sys, getopt
import re
import requests
from pymetasploit3.msfrpc import MsfRpcClient
import time



ip = "127.0.0.1"
user = "msf"
passwd = ""
halt = False

# Creating connection to RPC
c = MsfRpcClient(passwd,port=55552)
# Creating consoles
console_number = c.consoles.console().cid
print(console_number)
busy_value = c.consoles.console(console_number).is_busy()


while busy_value is True:
    busy_value = c.consoles.console(console_number).is_busy()
    print(busy_value)

results = c.consoles.console(console_number).read()
print(results['data'])
print("results check")
while results['data'] is "":
            results = c.consoles.console(console_number).read()
print(results)


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
head_line="IP,vulnerable service,Computer_name,OS,Domain,Workgroup,CPE\n"
results.o.write(head_line)

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
                    print("-------------------------start metasploit------------------------")
                    output = c.consoles.console(console_number).write('use auxiliary/scanner/rdp/cve_2019_0708_bluekeep')
                    output = c.consoles.console(console_number).write('set rhosts '+host)
                    print(output)
                    #Check that RPC will return confirmation that set has been applied
                    Scan_end = True
                    while Scan_end is True: 
                        output = c.consoles.console(console_number).read()
                        if host in str(output):
                            Scan_end = False
                    print(output)
                    output = c.consoles.console(console_number).write('run')
                    print(output)
                    output = c.consoles.console(console_number).read()
                    print(output)
                    print("SCAN started")
		    #Waiting until scan will finished 
                    time.sleep(2) 
                    busy_value = c.consoles.console(console_number).is_busy()
                    print(busy_value)
                    while busy_value is True:
                        busy_value = c.consoles.console(console_number).is_busy()
                        time.sleep(5)
                    
                    Scan_end = True
                    while Scan_end is True: 
                        output = c.consoles.console(console_number).read()
                        if "Auxiliary module execution completed" in str(output):
                            Scan_end = False
                    print(output)
                    print("SCAN fnished")
                    # checking if host is in vulns table 
                    output = c.consoles.console(console_number).write('vulns '+host)
                    print(output)
                    busy_value = c.consoles.console(console_number).is_busy()
                    while busy_value is True:
                        busy_value = c.consoles.console(console_number).is_busy()
                    results_vulns = c.consoles.console(console_number).read()
                    print("output")
                    while results_vulns['data'] is "":
                        results_vulns = c.consoles.console(console_number).read()
                    print(results_vulns)
                    if host in str(results_vulns):
                            print("-------------------------start smb scan ----------------------")

                            print("VULNERABLE")
                            nm2.scan(host,"445,139","--script smb-os-discovery.nse")
                            test_scan_finished=nm2.all_hosts()
                            test_scan_finished_len=len(test_scan_finished)
					# Check if the host has not been  switched off in the middle of scan 
                            if test_scan_finished_len==0:
                                results.o.write(host+",Scan_error,"+port_str+" \n")
                                print(host+","+port_str+",Scan_error") 
                            else:
                                output_scan=nm2._scan_result['scan'][host]
                         
                                output_scan=str(output_scan)
                                #check if script smb discovery script  list was able to got any info 
                                scan_results_test="hostscript"
                                if scan_results_test in output_scan:

                                    output=smb_info_parser(nm2,host)
                                    counter_str=str(counter)
                                    for lists in output:
                                        host_list=lists.ip+",RDP,"+lists.Computer_name+","+lists.OS+","+lists.Domain+","+lists.Workgroup+","+lists.CPE+"\n"
                                        print(host_list)
                                        results.o.write(host_list) 
                                        counter=counter+1
                                else:
                                    print(host+",RDP,no_smb_info") 
                                    results.o.write(host+",RDP,no_smb_info \n")
                            print("---------------------end scan --------------------------------")
                   
                    print(counter_str+","+host)

output = c.consoles.destroy(console_number)

print("Number of host from with one has been received smb info:")
print(counter)
print("Number host with open smb ports:")
print(counter_test)
print("Successfully rescans:")
print(counter_rescan)
results.o.close()
results.i.close()


