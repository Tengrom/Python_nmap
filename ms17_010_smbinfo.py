#!/usr/bin/python
import sys, getopt



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
    Check_for_attributes=('OS:','Computer name:','Domain name:','Workgroup','CPE:','dialects:','SMBv1')
    Network_class=SMB_host(host_ip)
    output_list.append(Network_class)
    for output in test:
        test_output=str(output)
        part22=test_output.split("\\n")
        for parts in part22:
            if any(attrib in parts for attrib in Check_for_attributes):
                if (Check_for_attributes[0] in parts):
                    parts_split=parts.split(":")
                    OS_part=parts_split[1].strip()
                    Network_class.add_OS(OS_part)
               
                elif (Check_for_attributes[1] in parts):
                    parts_split=parts.split(":")
                    Computer_name_part=parts_split[1].strip()
                    Network_class.add_Computer_name(Computer_name_part)
                    
                elif (Check_for_attributes[2] in parts):
                    parts_split=parts.split(":")
                    Domain_part=parts_split[1].strip()
                    Network_class.add_Domain(Domain_part)
                    
                elif (Check_for_attributes[3] in parts):
                    parts_split=parts.split(":")
                    Workgroup_part=parts_split[1].strip()
                    Network_class.add_Workgroup(Workgroup_part)
       
                elif (Check_for_attributes[4] in parts):
                    parts_split=parts.split(":",1)
                    CPE_part=parts_split[1].strip()
                    Network_class.add_CPE(CPE_part)
                
                elif (Check_for_attributes[5] in parts):
                    output_str=str(output)
                    #print(output_str)

                    Dialects_part_fin=""
                    parts_split=output_str.split(":")
                    #print(parts_split)
                    Dialects_part=parts_split[2].split("'")
                    Dialects_small_part=Dialects_part[0].split("\\n")
                    for dialect_parts in Dialects_small_part:
                        if Check_for_attributes[6] in dialect_parts:
                            dialect_parts_split=dialect_parts.split(",")
                            Dialects_part_fin=Dialects_part_fin+dialect_parts_split[0]

                        else:
                            Dialects_part_fin=Dialects_part_fin+dialect_parts

                    Network_class.add_Dialects(Dialects_part_fin)
		    
                elif (Check_for_attributes[6] in parts):
                    #print(parts)
                    Network_class.add_SMBv1("Enabled")
    return output_list
counter=1
counter_test=1
counter_rescan=1
counter_str=""
Check_read = "READ"
head_line="IP,ms17_010_vulnerable,Computer_name,OS,Domain,Workgroup,CPE\n"
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
                    nm2.scan(host,port_str,"--script smb-vuln-ms17-010")
                    
                    #nm2.scan(host,port_str,"--script smb-os-discovery.nse,smb-protocols.nse ")
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
                        scan_results_test="VULNERABLE"
                        if scan_results_test in output_scan:

                            nm2.scan(host,port_str,"--script smb-os-discovery.nse")
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
                                        host_list=lists.ip+",VULNERABLE,"+lists.Computer_name+","+lists.OS+","+lists.Domain+","+lists.Workgroup+","+lists.CPE+"\n"
                                        print(host_list)
                                        results.o.write(host_list) 
                                        counter=counter+1
                                else:
                                    print(host+",VULNERABLE,no_smb_info"+port_str) 
                                    results.o.write(host+",VULNERABLE,no_smb_info,"+port_str+" \n")
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


