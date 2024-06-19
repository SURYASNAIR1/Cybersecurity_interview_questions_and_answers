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

Components of nmap: source IP, destination IP, source port and destination port

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

# SSH

SSH stands for Secure Shell, which is a cryptographic network protocol for securely connecting to and managing networked devices or systems over an unsecured network.

# Proxy

Purpose: A proxy server acts as an intermediary between a client (user device) and the internet.

Functionality: It forwards client requests to other servers (web servers, file servers, etc.) and returns responses to the client, often altering the client's IP address.

Usage: Improving performance by caching data, filtering content, or bypassing network restrictions.

# Load Balancer

Definition: A load balancer distributes incoming network traffic across multiple servers (or server instances) to optimize resource utilization, ensure high availability, and improve performance.

Functionality: It monitors server health, allocates incoming requests based on predefined algorithms (e.g., round-robin, least connections), and directs traffic to the most available or least loaded server.

Usage: Load balancers are critical in environments with high traffic or applications requiring scalability, such as websites, APIs, and cloud-based services

# CDN (Content Delivery Network)

Definition: A CDN is a geographically distributed network of servers and data centers that work together to deliver content (such as web pages, images, videos, and other assets) to users based on their geographic location.

# HIDS (Host-based Intrusion Detection System) vs NIDS (Network-based Intrusion Detection System):

*HIDS (Host-based Intrusion Detection System):*

Definition: HIDS monitors and analyzes activity on individual hosts or endpoints within a network.

Functionality: It examines logs and system events, compares system files against known good versions, and detects unauthorized changes or anomalies on a specific host.

Examples: Examples of HIDS include OSSEC (Open Source HIDS), Tripwire, and Windows Security Center.

*NIDS (Network-based Intrusion Detection System):*

Definition: NIDS monitors network traffic in real-time to detect suspicious activity or attacks on the network as a whole.

Functionality: It analyzes network packets, looking for patterns indicative of known threats or deviations from normal traffic behavior.

Examples: Examples of NIDS include Snort, Suricata, and Cisco IDS (Intrusion Detection System).

# Packet Sniffing and Spoofing

*Packet Sniffing:*

Definition: Packet sniffing, or packet capturing, is the process of intercepting and logging network traffic passing through a network interface. It allows capturing and analyzing packet contents, including sensitive data such as passwords or application data.

Purpose: Packet sniffing is used for network troubleshooting, performance monitoring, and security analysis. However, it can also be used maliciously to capture sensitive information transmitted over the network.

*Packet Spoofing:*

Definition: Packet spoofing involves forging the header information of IP packets to falsely indicate their origin. This can involve modifying the source IP address, MAC address, or other packet header fields.

Purpose: Packet spoofing is often used in DDoS (Distributed Denial of Service) attacks to mask the true source of attack traffic, making it difficult to trace and mitigate the attack.

# SSL and TLS

SSL (Secure Sockets Layer) and TLS (Transport Layer Security) are cryptographic protocols designed to provide secure communication over a computer network, typically between a client (such as a web browser) and a server (such as a web server). While they serve the same fundamental purpose of securing data transmission, there are important differences between SSL and TLS:

SSL (Secure Sockets Layer):
History: SSL was developed by Netscape in the mid-1990s to ensure secure communication over the internet.

Versions: SSL has several versions, including SSL 1.0 (never publicly released due to security flaws), SSL 2.0, SSL 3.0, and SSL 3.1 (which is often referred to as TLS 1.0).

Vulnerabilities: Over time, SSL has been found to have several security vulnerabilities, particularly with older versions like SSL 2.0 and SSL 3.0, which have led to their deprecation.

TLS (Transport Layer Security):
Successor: TLS is the successor to SSL and was first defined in 1999 as TLS 1.0, which was based on SSL 3.1.

Improvements: TLS includes improvements over SSL, such as more robust encryption algorithms, better authentication, and support for forward secrecy.

Versions: TLS has several versions, including TLS 1.0, TLS 1.1, TLS 1.2, and TLS 1.3 (the latest as of now). Each version has introduced enhancements in security and performance.

Compatibility: TLS is designed to be backward compatible with SSL, allowing modern implementations of TLS to negotiate a secure connection with older SSL implementations, although it's recommended to use the latest TLS versions for improved security.

Key Differences:
Security: TLS is generally considered more secure than SSL, especially newer versions like TLS 1.2 and TLS 1.3, which offer stronger encryption algorithms and better resistance to attacks.

Protocol Support: Most modern applications and browsers have transitioned to using TLS protocols instead of SSL due to security concerns and protocol vulnerabilities in SSL.

Naming and Usage: Despite the technical differences, the terms "SSL" and "TLS" are often used interchangeably in everyday conversation to refer to the secure connection between a client and a server, although strictly speaking, TLS is the modern and recommended protocol for secure communications.

DLP --> Data Loss Prevention. 

Pipes (|): Pipes are a way to connect the output of one command to the input of another command. 

# Cryptography

Cryptography is a technique of securing information and communications through the use of codes so that only those persons for whom the information is intended can understand and process it. Thus preventing unauthorized access to information. The prefix “crypt” means “hidden” and the suffix “graphy” means “writing”.

# OSI Layer

Securing each OSI layer (Open Systems Interconnection model) is crucial for maintaining overall network security. 

1. **Physical Layer (Layer 1):**
   - **Definition:** This layer deals with the physical connection between devices and the transmission of raw data bits over a physical medium.
   - **Security Measures:**
     - **Physical security:** Ensure that physical access to network devices, cables, and infrastructure is restricted to authorized personnel only.
     - **Encryption of physical connections:** Use technologies like VPNs (Virtual Private Networks) to secure data transmitted over physical connections.

2. **Data Link Layer (Layer 2):**
   - **Definition:** This layer provides node-to-node data transfer, ensuring data is delivered error-free between directly connected nodes.
   - **Security Measures:**
     - **MAC address filtering:** Limit which devices can access the network by filtering based on MAC addresses.
     - **VLANs (Virtual Local Area Networks):** Segregate network traffic to improve security and performance.
     - **802.1X authentication:** Provides port-based network access control, requiring users or devices to authenticate before gaining network access.

3. **Network Layer (Layer 3):**
   - **Definition:** This layer handles logical addressing, routing, and forwarding of data packets between different networks.
   - **Security Measures:**
     - **Firewalls:** Implement firewalls to filter and control incoming and outgoing traffic based on predetermined security rules.
     - **IPSec (IP Security):** Provides encryption and authentication at the IP layer to ensure secure communication between nodes.
     - **Network segmentation:** Divide the network into smaller, isolated segments to limit the impact of security breaches.

4. **Transport Layer (Layer 4):**
   - **Definition:** This layer ensures reliable data transfer between end systems and provides error-checking mechanisms.
   - **Security Measures:**
     - **TLS/SSL (Transport Layer Security/Secure Sockets Layer):** Encrypts data exchanged between applications to ensure confidentiality and integrity.
     - **TCP/IP filtering:** Use firewalls or intrusion detection systems to monitor and filter traffic based on TCP/IP port numbers.

5. **Session Layer (Layer 5):**
   - **Definition:** This layer establishes, manages, and terminates sessions between applications.
   - **Security Measures:**
     - **Session management:** Implement mechanisms to authenticate and authorize sessions, ensuring that only authorized users can establish sessions.
     - **Token-based authentication:** Use tokens to verify the identities of users and devices involved in the session.

6. **Presentation Layer (Layer 6):**
   - **Definition:** This layer ensures that data is presented in a readable format for the application layer.
   - **Security Measures:**
     - **Data encryption:** Encrypt data at this layer to protect it during transmission and storage.
     - **Data validation:** Implement mechanisms to validate the integrity and authenticity of data at this layer.

7. **Application Layer (Layer 7):**
   - **Definition:** This layer provides an interface between the user and the network services.
   - **Security Measures:**
     - **Authentication and authorization:** Implement strong authentication mechanisms (e.g., multi-factor authentication) and granular access controls.
     - **Application-level encryption:** Encrypt sensitive data within applications to protect it from unauthorized access.
     - **Regular updates and patches:** Keep applications up to date with security patches to mitigate vulnerabilities.

