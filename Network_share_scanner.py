#!/usr/bin/python
# Author: Piotr Kaminski
#Linkedin: www.linkedin.com/in/piotr-kaminski-1336b012
# Date: 2018-04-26
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
parser.add_argument('-u', metavar='Username', action='store' , dest='username', help='Username what will be used to discovery and accessing network share . By defult it is guest username' )
parser.add_argument('-p', metavar='Password', action='store' , dest='password', help='Password what will be used to discovery and accessing network share . By defult it is empty' )
parser.add_argument('-o2', metavar='out-file-files_folders-list', type=argparse.FileType('wt'), help='Chose output file where script will list max 8 files or folders from discovered network shares')

global args
args = parser.parse_args()
    
try:
    results = parser.parse_args()
    print('Input file:', results.i)
    print('Output file:', results.o)
    print('Output file for files and folders in share:', results.o2)
except:
    parser.error(str(msg))


#range scan 
nm=nmap.PortScanner()
#UDP scan
nm2=nmap.PortScanner()
#TCP scan 
nm3=nmap.PortScanner()
class Network_share:
    def __init__(self, name):
        self.name = name
        self.anon_access=""
        self.user_access=""
        self.path=""
        self.comment=""
        self.share_type=""
        
    def add_anon_access(self, anon_access):
        self.anon_access=anon_access
 
    def add_user_access(self, user_access):
        self.user_access=user_access

    def add_path(self, path):
        self.path=path
    
    def add_comment(self, comment):
        self.comment=comment

    def add_type(self, share_type):
        self.share_type=share_type
  

def files_folders_parser(nmap_results):
    output_list=[]
    test=nmap_results._scan_result['scan'][host]['hostscript']
    not_files_or_folders=('{\'output\':','maxfiles limit reached','FILENAME',' \'smb-ls\'}')
    for output in test:
        test_output=str(output)
        part22=test_output.split("\\n")
        for parts in part22:
            if not any(attrib in parts for attrib in not_files_or_folders):
                if parts!="":
                    output_list.append(parts)
    return output_list



def Network_share_parser(nmap_results):
    output_list=[]
    id_str_check="'id'"
    test=nmap_results._scan_result['scan'][host]['hostscript']
    Check_for_attributes=('Type:','warning:','Anonymous access:','Current user access:','Comment:','Users:','Max Users:','Path:','account_used:','{\'output\':')
    #Check_share_type=('Not a file share','STYPE_IPC_HIDDEN')
    for output in test:
        test_output=str(output)
        part22=test_output.split("\\n")
        for parts in part22:
            if any(attrib in parts for attrib in Check_for_attributes):
                if (Check_for_attributes[3] in parts):
                    parts_split=parts.split(":")
                    Current_user_access=parts_split[1].strip()
                    if id_str_check in Current_user_access:
                        id_str_check_split=Current_user_access.split(",")
                        Current_user_access=id_str_check_split[0]
                    Network_class.add_user_access(Current_user_access)
               
                elif (Check_for_attributes[2] in parts):
                    parts_split=parts.split(":")
                    Anonymous_access=parts_split[1].strip()
                    
                    if id_str_check in Anonymous_access:
                        id_str_check_split=Anonymous_access.split(",")
                        Anonymous_access=id_str_check_split[0]

                    Network_class.add_anon_access(Anonymous_access)
                    
                elif (Check_for_attributes[4] in parts):
                    parts_split=parts.split(":")
                    Comment=parts_split[1].strip()
                    Network_class.add_comment(Comment)
                    
                elif (Check_for_attributes[7] in parts):
                    parts_split=parts.split(":",1)
                    Path=parts_split[1].strip()
                    Network_class.add_path(Path)
       
                elif (Check_for_attributes[0] in parts):
                    parts_split=parts.split(":")
                    Type=parts_split[1].strip()
                    Network_class.add_type(Type)
            else:
                parts_split=parts.split(":")
                Share_name=parts_split[0].strip()
                Network_class=Network_share(Share_name)
                output_list.append(Network_class)

    return output_list
counter=0
counter_test=0
counter_rescan=0
counter_rescan_str=""
counter_open_share=0
counter_str=""
Check_share_type=('Not a file share','STYPE_IPC_HIDDEN')
Check_read = ('READ','WRITE')
head_line="IP,Share_name,Current_user_access,Anonymous_access,Path,Type,Comment,Detected files (max 10)\n"
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
                # scanning large subnets scans some ack packed are missing and it is marking open ports us filtered, need to scan againg it per ip is working fine
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
			# Check if the host has not been  switched off in the middle of scan 
                        if test_scan_finished_len==0:
                            results.o.write("e,"+host+","+port_str+",Scan_error,\n")
                        elif r2=="up":
                            r3=nm3._scan_result['scan'][host]['tcp'][port]['state']
                        if r3=="open":
                            counter_rescan=counter_rescan+1
                            counter_rescan_str=str(counter_rescan)
                print(host+ " rescanned "+counter_rescan_str)
                print(host+","+r2+","+r3+","+r4+",")
				#if ports are open start network share list script
                if r2=="up" and (r3 == "open" or r4 == "open"):
                    print("---------------------start script scan--------------------------")
                    if r3 == "open" :
                        port_str = "445"
                    else:
                        port_str = "139"
                    counter_test=counter_test+1
                    if args.username==None or args.password==None:
                        nm2.scan(host,port_str,"-script smb-enum-shares.nse")
                    else:
                        nm2.scan(host,port_str,"-script smb-enum-shares.nse --script-args 'smbuser="+args.username+",smbpass="+args.password+"' ")
                    test_scan_finished=nm2.all_hosts()
                    test_scan_finished_len=len(test_scan_finished)
		    # Check if the host has not been  switched off in the middle of scan 
                    if test_scan_finished_len==0:
                        results.o.write("e,"+host+","+port_str+",Scan_error,\n")
                    else:
                        vulnerable=nm2._scan_result['scan'][host]
                    
                        vulnerable=str(vulnerable)
                        #check if script network share list was able to got any info 
                        vulnerable_test="hostscript"
                        if vulnerable_test in vulnerable:
                            counter=counter+1
                            output=Network_share_parser(nm2)
                            counter_str=str(counter)
                            for lists in output:
                            
                                counter_share=0
				# If there is read file share , check is there are accesible files
                                if lists.share_type not in  Check_share_type: 
                                    
                                    if Check_read[0] in lists.user_access or Check_read[1] in lists.user_access:
                                        Access=True
                                    elif Check_read[0] in lists.anon_access or Check_read[1] in lists.anon_access:
                                        Access=True
                                    else:
                                        Access=False
						
                                    if Access:
                                        if args.username==None or args.password==None:
                                            nm2.scan(host,port_str,"-script smb-ls.nse --script-args share="+lists.name)
                                        else:
                                            nm2.scan(host,port_str,"--script smb-ls.nse  --script-args 'smbuser="+args.username+",smbpass="+args.password+"',share="+lists.name)
                                        test_scan_finished=nm2.all_hosts()
                                        test_scan_finished_len=len(test_scan_finished)
					# if the server will be switched off 
                                        if test_scan_finished_len==0:
                                            results.o.write("e,"+host+","+port_str+",Scan_error,\n")
                                        else:
                                            vulnerable=nm2._scan_result['scan'][host]
                                            vulnerable=str(vulnerable)
                                            #check if script files and folder list got any info     
                                            vulnerable_test="FILENAME"
                                            if vulnerable_test in vulnerable:
                                                counter_open_share=counter_open_share+1
                                                output2=files_folders_parser(nm2)
                                                for lists2 in output2:                                   
                                                    if results.o2 != None:
                                                        print(lists2)
                                                        results.o2.write(host+","+lists.name+","+lists2+"\n")
                                                        counter_share=counter_share+1

                                    counter_share_str=str(counter_share)
                                    Network_share_list_to_file=host+","+lists.name+","+lists.user_access+","+lists.anon_access+","+lists.path+","+lists.share_type+","+lists.comment+","+counter_share_str+"\n"
                                    print(Network_share_list_to_file)
                                    results.o.write(Network_share_list_to_file)
                                        
                        else:
                            results.o.write(host+",no_smb_info,\n")
                    print(counter_str+","+host+","+port_str )
                    print("---------------------end script scan --------------------------")
print("Number of host from with one has been received smb info:")
print(counter)
print("Number host with open smb ports:")
print(counter_test)
print("Successfully rescans:")
print(counter_rescan)
print("Open shares:")
print(counter_open_share)
results.o.close()
results.i.close()


