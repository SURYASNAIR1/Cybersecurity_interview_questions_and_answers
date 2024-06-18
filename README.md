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

*Other scans in nmap:* 

1. UDP Scans (-sU): Used to discover open UDP ports and services. UDP scans are less reliable due to the lack of a three-way handshake.

2. NULL Scan (-sN): Sends packets with no flags set to determine port status. If a port is closed, it responds with an RST packet.

3. FIN Scan: Similar to NULL scan but sends packets with only the FIN flag set.

4. XMAS Scan: Sends packets with FIN, URG, and PUSH flags set. Useful for detecting open ports.

Slowest and fastest scan in nmap: -T0 as the slowest and –T5 as the fastest.

Nmap is in which OSI layer: Transport Layer

To write nmap: C, C++, Python, Lua

Scan a target from specific interface: #nmap -e <interface> <target>

Components of nmpa: source IP, destination IP, source port and destination port

Scan Types in Nmap- TCP Connect Scans ( -sT ), SYN “Half-open” Scans ( -sS ), UDP Scans ( -sU ), TCP Null Scans ( -sN ), TCP FIN Scans ( -sF ) and TCP Xmas Scans ( -sX ) 

OS Fingerprinting: Identifies what operating system is running on a given host based on analysing the host’s responses to various network probes.

Nmap is a port scanner that identifies open ports. At the same time, Wireshark is a protocol analyser that helps security engineers to read the structure of different packets.

The attacker sends a packet to the target without any flags set within it. The target will be confused and will not respond. This will indicate the port is open on the target. If the target responds with an RST packet, the port is closed.

# Firewall

Firewalls can be classified into several types:

1. Packet-Filtering Firewalls: These inspect packets at the network layer and make filtering decisions based on predefined rules (e.g., IP addresses, ports).

2.  Stateful Inspection Firewalls: These monitor the state of active connections and make decisions based on the state and context of the traffic.

3.  Proxy Firewalls: These act as intermediaries between end users and the services they access, inspecting traffic at the application layer.

4.  Next-Generation Firewalls (NGFW): These combine traditional firewall capabilities with advanced features like deep packet inspection, intrusion prevention systems (IPS), and application awareness.

# Threat, vulnerability and risk 

Threat: A threat refers to a malicious act or circumstance that can cause harm to an IT system. It includes actions like computer viruses, Denial of Service (DoS) attacks, data breaches, and even dishonest employees.

Vulnerability: A weakness or flaw in a system that can be exploited by a threat to gain unauthorized access or cause harm.

Risk: The potential for loss or damage when a threat exploits a vulnerability. 
Risk = Threat + Vulnerability

# Port Numbers

1. HTTP - 80

2. HTTPS -443

3. FTP - 21

4. SSH - 22

5. DNS -53

6. Private or dynamic ports - 49152 to 65535

# Encoding

The process of converting data from one form to another for transmission, storage, or interpretation by computers or other electronic devices. It involves translating information into a format that is suitable for a specific purpose or compatible with a particular system. Here are some key aspects of encoding:

Types of Encoding:

* Character Encoding:

ASCII (American Standard Code for Information Interchange): ASCII uses 7 bits to represent each character, providing a total of 128 possible characters.
Unicode: Unicode uses 8, 16, or 32 bits per character, depending on the encoding form (UTF-8, UTF-16, UTF-32).

UTF-8: It is widely used on the web and in computing systems due to its efficient use of storage space for ASCII characters while supporting all Unicode characters.

* Data Encoding:

Base64: A method of encoding binary data into ASCII text format. Base64 encoding is commonly used to encode data in MIME (Multipurpose Internet Mail Extensions) email messages, including attachments, and in other contexts such as transmitting binary data over text-based protocols like HTTP.

Binary Encoding: Represents data in a binary form suitable for storage or transmission, such as in computer memory or across a network.

# Deep web and Dark web

*Deep Web*:

Definition: The deep web refers to any part of the internet that is not indexed by standard search engines like Google, Bing, or Yahoo. This includes content that is behind paywalls, password-protected websites, private databases, or dynamically generated content.

Access: Generally accessible with the right credentials or permissions, such as subscription-based content, private company intranets, or academic databases.

Usage: Often contains legitimate and legal content, though it can also include unindexed pages used for various purposes.

*Dark Web*:

Definition: The dark web is a small portion of the deep web that is intentionally hidden and inaccessible through standard web browsers. It operates on overlay networks that require specific software or configurations to access, such as Tor (The Onion Router).

Anonymity: Users and websites on the dark web often operate anonymously or pseudonymously to conceal their identities and activities.

Content: Known for hosting illicit activities, black markets, forums, and websites involved in illegal activities like drug trafficking, illegal arms sales, hacking services, and more.

# MITRE ATT&CK

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a framework and knowledge base that categorizes and describes adversary behaviors based on real-world observations of cyberattacks.

TTP --> Tactics, techniques, and procedures 

#  Events, alerts, and incidents 

Events are occurrences or observable actions happening within an information system, network, or application.

Alerts are notifications generated by security monitoring systems in response to specific events that match predefined criteria or thresholds. 

Incidents refer to confirmed or suspected security breaches or events that have a negative impact on the confidentiality, integrity, or availability of an organization's information assets.
