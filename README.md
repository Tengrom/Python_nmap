# Python_nmap
Script has been  write to provide clear reporting output, without needed to parser or formating it after scan finished. Script also improve realiabity by devided it for the scan phases:

1. Global scans of interesting port
2. Rescaning when there are probility of missing packets
3. Checking if switch is vulnerable using Talos Cisco code :https://github.com/Cisco-Talos/smi_check
4. Gathering more information about device when port is opened and device is vulnerable.


Usage:

 cisco_SIE_Scan.py [-h] [-i in-file with subnets or IPs] [-o out-file]

Output:

1 , 192.168.1.11 , C2960S Software (C2960S-UNIVERSALK9-M) , Version 12.2(55)SE7 , Vulnerable

2 , 192.168.1.12 , C2960X Software (C2960X-UNIVERSALK9-M) , Version 15.0(2a)EX5 , Vulnerable

3 , 192.168.1.13 , C2960X Software (C2960X-UNIVERSALK9-M) , Version 15.2(2)E3 , Vulnerable
