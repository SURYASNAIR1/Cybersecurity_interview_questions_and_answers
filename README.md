# Nmap
Nmap --> Network Mapping

Open source tool 

Used for network scanning, security auditing and vulnerability assessment

Nmap identifies hosts and services on a network and security issues. It sends packets to target hosts and analyse responses

Size of nmap --> 5 to 1024 bytes

We can use nmap without root option for that use -e 

NSE stands for Nmap Scripting Engine, a powerful engine that allows users to extend the functionality of Nmap by writing their scripts. 

Output format in nmap:  Normal output ( -oN ), XML output ( -oX ), Grepable output ( -oG ) and Script kiddie ( -oS )

To scan a network: $nmap -sn <target>

To scan a target from a file: $nmap -iL <target-file>

To perform a UDP scan: -sU 

To perform a TCP connect scan: -sT

To identify the version and name of the services running on the scanned ports: -sV

To specify the number of top ports to be scanned: --top-ports

Scan a target: nmap -sC <target>

Scan a target using TCP SYN scan: -sS

TCP scan: nmap -sT

UDP scan: nmap -sU

Print a summary while sending and receving packets: #nmap --packet-trace -n -sn

Scan IPV6 target: $ nmap -6 -O <target>

Update nmap database: $nmap --script-updatedb

nmap aggressive detection: $nmap -A <target>

Aggressive Detection command enables OS detection (-O), script scanning (-sC), version detection (-sV),  and traceroute (--traceroute)

Slowest and fastest scan in nmap: -T0 as the slowest and –T5 as the fastest.

Nmap is in which OSI layer: Transport Layer

To write nmap: C, C++, Python, Lua

Scan a target from specific interface: #nmap -e <interface> <target>

Components of nmpa: source IP, destination IP, source port and destination port

Scan Types in Nmap- TCP Connect Scans ( -sT ), SYN “Half-open” Scans ( -sS ), UDP Scans ( -sU ), TCP Null Scans ( -sN ), TCP FIN Scans ( -sF ) and TCP Xmas Scans ( -sX ) 

OS Fingerprinting: Identifies what operating system is running on a given host based on analysing the host’s responses to various network probes.

Nmap is a port scanner that identifies open ports. At the same time, Wireshark is a protocol analyser that helps security engineers to read the structure of different packets.

The attacker sends a packet to the target without any flags set within it. The target will be confused and will not respond. This will indicate the port is open on the target. If the target responds with an RST packet, the port is closed.
