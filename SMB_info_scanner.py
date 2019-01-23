#!/usr/bin/python
# Author: Piotr Kaminski
#Linkedin: www.linkedin.com/in/piotr-kaminski-1336b012
# Date: 2018-04-26
import sys, getopt
import re


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
parser.add_argument('-u', metavar='Username', action='store' , dest='username', help='Username what will be used to discovery and accessing SMB . By defult it is guest username' )
parser.add_argument('-p', metavar='Password', action='store' , dest='password', help='Password what will be used to discovery and accessing SMB . By defult it is empty' )

global args
args = parser.parse_args()
    
try:
    results = parser.parse_args()
    print('Input file: ' + str(results.i))
    print('Output file: ' + str(results.o))
 
except IOError as msg:
    parser.error(str(msg))


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
head_line="IP,Computer_name,OS,Domain,Workgroup,CPE,SMB_Dialects_Versions,SMBv1_enabled\n"
results.o.write(head_line)

with results.i as f:
        for line in f:
            print("=======================================")
            print(line)
            print("=======================================")

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
                            results.o.write(host+",Scan_error,"+port_str+" \n")
                        elif r2=="up":
                            r3=nm3._scan_result['scan'][host]['tcp'][port]['state']
                        if r3=="open":
                            counter_rescan=counter_rescan+1
                        counter_rescan_str=str(counter_rescan)
                        print(host+" rescanned "+counter_rescan_str)
						#if ports are open start smb discovery  script						
                print(host+","+r2+","+r3+","+r4+",")
                if r2=="up" and (r3 == "open" or r4 == "open"):
                    print("---------------------start scan --------------------------------")
                    if r3 == "open" :
                        port_str = "445"
                    else:
                        port_str = "139"
                    counter_test=counter_test+1
                    if args.username==None or args.password==None:
                        nm2.scan(host,port_str,"--script smb-os-discovery.nse,smb-protocols.nse ")
                    else:
                        nm2.scan(host,port_str,"--script smb-os-discovery.nse,smb-protocols.nse --script-args 'smbuser="+args.username+",smbpass="+args.password+"' ")
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
                               host_list=lists.ip+","+lists.Computer_name+","+lists.OS+","+lists.Domain+","+lists.Workgroup+","+lists.CPE+","+lists.Dialects+","+lists.SMBv1+"\n"
                               print(host_list)
                               results.o.write(host_list)
                               counter=counter+1
                        else:
                            print(host+",no_smb_info"+port_str) 
                            results.o.write(host+",no_smb_info,"+port_str+"\n")
                    print(counter_str+","+host+","+port_str)
                    print("---------------------end scan --------------------------------")
print("Number of host from with one has been received smb info:")
print(counter)
print("Number host with open smb ports:")
print(counter_test)
print("Successfully rescans:")
print(counter_rescan)
results.o.close()
results.i.close()


