#!/usr/bin/python
import sys, getopt
import nmap
if len (sys.argv) != 3:
    print "Usage: python <input file name> <output file name>"
    sys.exit (1)
inputfile=sys.argv[1]
outputfile=sys.argv[2]
fileout=open(outputfile,"w")
#range scan 
nm=nmap.PortScanner()
#UDP scan
nm2=nmap.PortScanner()
#TCP scan 
nm3=nmap.PortScanner()
def parser_cisco_SIE(nmap_results):
    error=0
    #checking if got all snmp info
    test=nmap_results._scan_result['scan'][host]['udp'][161]    
    test=str(test)
    sysdescr="snmp-sysdescr"
    info="snmp-info"
    errorcheck1=sysdescr in test
    errorcheck2=info in test
    
    if errorcheck1:
		sysdescr=nmap_results._scan_result['scan'][host]['udp'][161]['script']['snmp-sysdescr']
        split=sysdescr.split(",")
        check1="Software"
        check2="Version"
        for splits in split:
            if_check1=check1 in splits
            if_check2=check2 in splits
            if if_check1:
                part1=splits
            if if_check2:
                part2=splits
        part22=part2.split("\n")
        part2=part22[0]
        output_parser=" , "+host+" , "+part1+" , "+part2+"\n"
    elif errorcheck2:
		sysdescr=nmap_results._scan_result['scan'][host]['udp'][161]['script']['snmp-info']
        sysdescr_list=sysdescr.splitlines()
        output_parser=" , "+host+" , "+sysdescr_list[1]+" , no_version_info \n"

    else:
        output_parser=" , "+host+" , NO_snmp_info , no_version_info \n"
    print(output_parser+"\n")
    return output_parser
counter=1
counter_test=1
counter_rescan=1
print(inputfile)
fileout.write(inputfile+"\n")
with open(inputfile) as f:
        for line in f:
            print(line)
            #Starting scan for 4786 SIE port on cisco devices
            nm.scan(line,'4786',"-sS")
            for host in nm.all_hosts():
                testhost=nm._scan_result['scan'][host]
                r2=nm._scan_result['scan'][host]['status']['state']
                r3=nm._scan_result['scan'][host]['tcp'][4786]['state']
                # scanning large subnets scans some ack packed are missing and it is marking open ports us filtered, need to scan againg it per ip is working fine
                if r2=="up" and r3=="filtered":
                    nm3=nmap.PortScanner()
                    nm3.scan(host,'4786',"-sS")
                    test_scan_finished=nm3.all_hosts()
                    test_scan_finished_len=len(test_scan_finished)
                    if test_scan_finished_len==0:
                        #print(testhost)
                        #print("error")
                        #print(nm3.csv())
                        fileout.write("e , "+host+" , Scan_error , \n")
                        #print("error_end")
                    elif r2=="up":
                        r3=nm3._scan_result['scan'][host]['tcp'][4786]['state']
                        if r3=="open":
                            counter_rescan=counter_rescan+1

					   #print("Successfully rescanned "+host)
                    else:
                        print(nm3._scan_result['scan'][host])
                       
                    #print("----")
                if r3=="open":
                    counter_test=counter_test+1
                    #print(counter_test)
                    udpr=nm2.scan(host,'161',"-sU -sC snmp-info.nse")
                    udp_status=nm2._scan_result['scan'][host]['udp'][161]['state']
                    if udp_status=="open":
                        output=parser_cisco_SIE(nm2)
                        counter_str=str(counter)
                        fileout.write(counter_str+output)
                        counter=counter+1
                    else:
                        fileout.write("x , "+host+" , Blocked_port_161 , \n")
print(counter)
print(counter_test)
print(counter_rescan)
fileout.close()


