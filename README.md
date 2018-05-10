# Python_nmap
Scripts has been  write to provide clear reporting output, without needed to parser or formating it after scan finished. Script also improve realiabity by devided it for the scan phases.

List of scripts:
1. cisco_SIE_Scan.py
2. SMB_info_scanner.py

===================================================================================================
Script: cisco_SIE_Scan.py


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




===================================================================================================
Script: SMB_info_scanner.py

1. Global scans of interesting port
2. Rescaning when there are probility of missing packets
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


