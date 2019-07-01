# Python nmap

Scripts has been write to provide clear report, without needed to parser or formatting it after scan finished. Script also improve reliability  by scan phases and some other additional functions.

List of scripts:
1.	cisco_SIE_Scan.py - Discovery Cisco Smart Installer vulnerability and gathering SNMP info from vulnerable device.
2.	SMB_info_scanner.py - Discovery devices with open 445 and 139 ports and gathering OS and SMB protocols info.
3.	Network_share_scanner.py - Discovery device with open 445 and 139 ports listing all shares on device and listing max 10 files from each discovered share.
4.	nmap_vuln_scanner_ServiceNow.py - Discovery devices vulnerable for selected nmap script for example ms17_010 (Wannacry) and gathering SMB info about OS and domain . Script is checking if there is already open  ticket for that host in ServiceNow  if not, it will create new.
5.	Nmap_Metasploit_Scanner_Vuln.py - Discovery devices using nmap and scaning them using Metasploit vulnerability scanner ,
if devices is vulnerable script will gather SMB info about OS and domain .
List of vulnerable  IP are recorded in metasploit DB.
6.	Nmap_Metasploit_Scanner_Vuln_Threads.py  - Quick scanner to discovery devices by scanning of subnets or IPs from file  and scanning them against vulns for example like  CVE-2019-0708 "BlueKeep" using Metasploit scanner "cve_2019_0708_bluekeep" if devices is vulnerable script will gather  SMB info about OS and domain .Script is using multiple  threads to speed up scan . Lists of vulnerable devices are recorded in csv file . 


=========================

Script #1 : cisco_SIE_Scan.py


1. Scanning for open interesting port
2. Rescanning when there are probability of missing packets
3. Checking if switch is vulnerable using Talos Cisco code :https://github.com/Cisco-Talos/smi_check
4. Gathering more information about device when port is opened and device is vulnerable.


Usage:

 cisco_SIE_Scan.py [-h] [-i in-file with subnets or IPs] [-o out-file]

Output:

	1 , 192.168.1.11 , C2960S Software (C2960S-UNIVERSALK9-M) , Version 12.2(55)SE7 , Vulnerable

	2 , 192.168.1.12 , C2960X Software (C2960X-UNIVERSALK9-M) , Version 15.0(2a)EX5 , Vulnerable

	3 , 192.168.1.13 , C2960X Software (C2960X-UNIVERSALK9-M) , Version 15.2(2)E3 , Vulnerable




===========================

Script #2: SMB_info_scanner.py

1. Scanning for open interesting port
2. Rescanning when there are probability of missing packets
3. Gathering SMB information about device when port is opened.

Usage:

SMB_info_scanner.py [-h] -i in-file -o out-file [-u Username] [-p Password]

Output:

	IP , Computer_name , OS , Domain , Workgroup , CPE , SMB_Dialects , SMBv1_enabled

	192.168.1.103 , Server1 , Windows Server 2003 3790 Service Pack 2 (Windows Server 2003 5.2) ,  , Home\\x00 , cpe:/o:microsoft:windows_server_2003::sp2 ,      NT LM 0.12 (SMBv1) [dangerous , Enabled

	192.168.1.105 , host1 , Windows XP (Windows 2000 LAN Manager) ,  , Home\\x00 , cpe:/o:microsoft:windows_xp::- ,      NT LM 0.12 (SMBv1) [dangerous , Enabled

	192.168.1.106 , host2 , Windows XP (Windows 2000 LAN Manager) ,  , Home\\x00 , cpe:/o:microsoft:windows_xp::- ,      NT LM 0.12 (SMBv1) [dangerous , Enabled

	192.168.1.112 , host3 , Windows XP (Windows 2000 LAN Manager) ,  , Home\\x00 , cpe:/o:microsoft:windows_xp::- ,      NT LM 0.12 (SMBv1) [dangerous , Enabled

	192.168.1.40 , Server2 , Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1) , home.local.intra ,  , cpe:/o:microsoft:windows_server_2008::sp1 ,      NT LM 0.12 (SMBv1) [dangerous    2.02    2.10 , Enabled

===========================

Script#3: Network_share_Scanner.py

1. Global scans of interesting port
2. Rescaning when there are probility of missing packets
3. Gathering list of network  shares on device
4. Gathering list of file accessible on accessible  share 

Usage:

Network_share_scanner.py [-h] -i in-file -o out-file [-u Username]  [-p Password]  [-o2 out-file-files_folders-list]

Output:

	out-file:

	IP , Share_name , Current_user_access , Anonymous_access , Path , Type , Comment , Detected files (max 10)

	192.168.1.132 , \\\\192.168.1.132\\ADMIN$ , <none> , <none> ,  , STYPE_DISKTREE_HIDDEN , Remote Admin , 0

	192.168.1.132 , \\\\192.168.1.132\\C$ , <none> , <none> ,  , STYPE_DISKTREE_HIDDEN , Default share , 0
	
	192.168.1.132 , \\\\192.168.1.132\\Documents , READ , <none> ,  , STYPE_DISKTREE ,  , 0

	192.168.1.83 , \\\\192.168.1.83\\ADMIN$ , <none> , <none> ,  , STYPE_DISKTREE_HIDDEN , Remote Admin , 0

	192.168.1.83 , \\\\192.168.1.83\\C$ , <none> , <none> ,  , STYPE_DISKTREE_HIDDEN , Default share , 0

	192.168.1.83 , \\\\192.168.1.83\\Public_share , READ , <none> ,  , STYPE_DISKTREE ,  , 10
	


	out-file-files_folders-list:
	
	192.168.1.83 , \\\\192.168.1.83\\Public_share , <DIR>  2014-03-31 03:41:27  .

	192.168.1.83 , \\\\192.168.1.83\\Public_share , <DIR>  2014-03-31 03:41:27  ..

	192.168.1.83 , \\\\192.168.1.83\\Public_share , <DIR>  2017-10-16 04:08:28  Monthly Inventory Report - test

	192.168.1.83 , \\\\192.168.1.83\\Public_share , <DIR>  2017-10-16 05:02:28  Monthly Inventory Report - test\\Mails

	192.168.1.83 , \\\\192.168.1.83\\Public_share , <DIR>  2017-10-16 05:06:41  Monthly Inventory Report - test\\MATERIAL

	192.168.1.83 , \\\\192.168.1.83\\Public_share , <DIR>  2017-10-16 04:08:42  Monthly Inventory Report - test\\ACCESS DATABASE

	192.168.1.83 , \\\\192.168.1.83\\Public_share , <DIR>  2017-10-16 05:06:43  Monthly Inventory Report - test\\Old 

	192.168.1.83 , \\\\192.168.1.83\\Public_share , <DIR>  2014-08-25 06:59:33  US

	192.168.1.83 , \\\\192.168.1.83\\Public_share , <DIR>  2014-09-03 03:42:17  US\\test

	192.168.1.83 , \\\\192.168.1.83\\Public_share , <DIR>  2014-12-29 02:19:52  US\\test all	
===========================

Script#4: nmap_vuln_scanner_ServiceNow.py

1. Scanning for open interesting port
2. Rescanning when there are probability of missing packets
3. Checking if device  is vulnerable using nmap script for example smb-vuln-ms17-010, to change it just type another nse script name 
4. Gathering more information about device when port is opened and device is vulnerable.
5. Checking if there is already open ticket for discovered host in ServiceNow using "Pysnow".
6. If there isn't any ticket it create new one

Before usage Auto.cfg configuration file need to be created conating those informations:

	[DEFAULT]
	SNuser =
	SNpass =
	[SN_wannacry]
	problem_id =
	caller_id =
	category =
	problem_nb =
	[nmap]
	port_scan = 445,139
	vuln_script = smb-vuln-ms17-010


===========================

Script#5: Nmap_Metasploit_Scanner_Vuln.py 

Discovery devices using nmap and scaning them using Metasploit vulnerability scanner , if devices is vulnerable script will gather SMB info about OS and domain . List of IP are recorded in metasploit DB. Errors and script infos are recorded in /var/log/msf_vuln.log
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
        192.168.0.0/24

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



===========================

Script#6:  Nmap_Metasploit_Scanner_Vuln_Threads.py

Quick multithread scanner. Discovery devices using nmap and scaning them using Metasploit vulnerability scanner ,
if devices is vulnerable script will gather SMB info about OS and domain.
Errors and script infos are recorded in /var/log/msf_rdp_vuln_threads.log


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
        192.168.0.0/24

Example of vuln_list_csv with structure,

	<port to scan>,<path to metasploit module>,< cve or ms in module name>:
        3389,auxiliary/scanner/rdp/cve_2019_0708_bluekeep,CVE-2019-0708
        445,auxiliary/scanner/smb/smb_ms17_010,MS17-010

To be sure that module will be discovered by script run:

	'search path:auxiliary/scanner/rdp/cve_2019_0708_bluekeep type:auxiliary name:CVE-2019-0708'

in metasploit console

Script is using that library "https://github.com/DanMcInerney/pymetasploit3"

Before use: run metasploit and msfrpc :


	msfrpcd -P yourpassword -S

password type in the script in variable MSF_PASSWD	



Multiprocessing was based on very good described blog : "https://stackabuse.com/parallel-processing-in-python/"




