#!/usr/bin/python
# Author: Piotr Kaminski
#Linkedin: www.linkedin.com/in/piotr-kaminski-1336b012
# Date: 2018-04-26

import sys
import nmap
import socket


halt = False

try:
    import argparse
except ImportError:
    print('Missing needed module: argparse')
    halt = True
    if halt:
        sys.exit()

parser = argparse.ArgumentParser()

parser.add_argument('-i', metavar='in-file', required=True, type=argparse.FileType('rt'))
parser.add_argument('-o', metavar='out-file', required=True, type=argparse.FileType('wt'))

try:
    results = parser.parse_args()
    print 'Input file:', results.i
    print 'Output file:', results.o
except IOError, msg:
    parser.error(str(msg))
#subnets or ip to sca n 
nm=nmap.PortScanner()
#UDP scan
nm2=nmap.PortScanner()
#TCP scan 
nm3=nmap.PortScanner()

#part of code from cisco talos https://raw.githubusercontent.com/Cisco-Talos/smi_check/master/smi_check.py

def vuln_check(IP):

    CONN_TIMEOUT = 10

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(CONN_TIMEOUT)

    try:
        conn.connect((IP, 4786))
    except socket.gaierror:
        print('[ERROR] Could not resolve hostname. Exiting.')
        sys.exit()
    except socket.error:
        print('[ERROR] Could not connect to '+IP)
        print('[INFO] Either Smart Install feature is Disabled, or Firewall is blocking port {0}')
        print('[INFO] Is not affected '+IP)
        sys.exit()

    if conn:
        req = '0' * 7 + '1' + '0' * 7 + '1' + '0' * 7 + '4' + '0' * 7 + '8' + '0' * 7 + '1' + '0' * 8
        resp = '0' * 7 + '4' + '0' * 8 + '0' * 7 + '3' + '0' * 7 + '8' + '0' * 7 + '1' + '0' * 8
        conn.send(req.decode('hex'))

        while True:
            try:
                data = conn.recv(512)
                if (len(data) < 1):
                    print('[INFO] Smart Install Director feature active on '+IP)
                    print('[INFO] is not affected '+IP)
                    return "False"
                    break
                elif (len(data) == 24):
                    if (data.encode('hex') == resp):
                        print('[INFO] Smart Install Client feature active on '+IP)
                        print('[INFO] is affected '+IP)
                        return "Vulnerable"
                        break
                    else:
                        print('[ERROR] Unexpected response received, Smart Install Client feature might be active on '+IP)
                        print('[INFO] Unclear whether is affected or not '+IP)
                        return "Maybe"
                        break
                else:
                    print('[ERROR] Unexpected response received, Smart Install Client feature might be active on '+IP)
                    print('[INFO] Unclear whether {0} is affected or not '+IP)
                    return "Maybe"
                    break
            except socket.error:
                print('[ERROR] No response after {0} seconds (default connection timeout)'.format(CONN_TIMEOUT))
                print('[INFO] Unclear whether {0} is affected or not'+IP)
                return "Maybe"
                break

            except KeyboardInterrupt:
                print('[ERROR] User ended script early with Control + C')
                break
    conn.close()
# -- end talos script
def parser_cisco_snmp(nmap_results):
    #checking if got all snmp info
    test=nmap_results._scan_result['scan'][host]['udp'][161]    
    test=str(test)
    sysdescr="snmp-sysdescr"
    info="snmp-info"
    
    if sysdescr in test:
        #if all snmp info is then parse
	sysdescr=nmap_results._scan_result['scan'][host]['udp'][161]['script']['snmp-sysdescr']
        split=sysdescr.split(",")
        check1="Software"
        check2="Version"
        for splits in split:
            if check1 in splits:
                part1=splits
            if check2 in splits:
                part2=splits
        part22=part2.split("\n")
        part2=part22[0]
        output_parser=","+host+","+part1+","+part2
    elif info in test:
	sysdescr=nmap_results._scan_result['scan'][host]['udp'][161]['script']['snmp-info']
        sysdescr_list=sysdescr.splitlines()
        output_parser=","+host+","+sysdescr_list[1]+",no_version_info"

    else:
        output_parser=","+host+",NO_snmp_info,no_version_info"
    print(output_parser+"\n")
    return output_parser
counter=1
counter_test=1
counter_rescan=1

with results.i as f:
    for line in f:
            print("Start scanning: " + line)
            #Starting scan for 4786 SIE port on cisco devices
            nm.scan(line,'4786',"-sS")
            for host in nm.all_hosts():
                testhost=nm._scan_result['scan'][host]
                r2=nm._scan_result['scan'][host]['status']['state']
                r3=nm._scan_result['scan'][host]['tcp'][4786]['state']
                # when scanning large subnets, some ack can get lost and it is marking open ports us filtered, need to scan againg it per ip is working fine
                if r2=="up" and r3=="filtered":
                    nm3=nmap.PortScanner()
                    nm3.scan(host,'4786',"-sS")
                    test_scan_finished=nm3.all_hosts()
                    test_scan_finished_len=len(test_scan_finished)
                    if test_scan_finished_len==0:
                        results.o.write("e,"+host+",Scan_error,\n")
                    else:
                        r3=nm3._scan_result['scan'][host]['tcp'][4786]['state']
                        if r3=="open":
                            counter_rescan=counter_rescan+1
                            print("Success rescanned")
                        else:
                            print("ports filtered "+host)
                if r3=="open":
                    vulne_checked=vuln_check(host)
                    if vulne_checked=="Vulnerable" or vulne_checked=="Maybe":
                        counter_test=counter_test+1
	                #start scan to get more detailed informaiton about target
                        udpr=nm2.scan(host,'161',"-sU -sC ")
                        udp_status=nm2._scan_result['scan'][host]['udp'][161]['state']
                        if udp_status=="open":
                            output=parser_cisco_snmp(nm2)
                            counter_str=str(counter)
                            results.o.write(counter_str+output+","+vulne_checked+"\n")
                            counter=counter+1
                        else:
                            counter_str=str(counter)
                            results.o.write(counter_str+","+host+",Blocked_port_161,,"+vulne_checked+"\n")
                            counter=counter+1
                    else:
                        results.o.write("x,"+host+",Not_Vulnerable \n")

print(counter)
print(counter_test)
print(counter_rescan)
results.o.close()
results.i.close()

