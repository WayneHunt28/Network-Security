# Network-Security
Module 11 Challenge UWA Cybersecurity Bootcamp submission file. 

Network Security
Make a copy of the M11 Challenge Submission FileLinks to an external site., and fill it out with your answers as you work through this Challenge. You will submit this document as your final deliverable for this Challenge.

Part 1: Review Questions
Before moving on to the lab exercises, complete the following review questions:

Security Control Types
The concept of defense-in-depth can be broken down into three security control types. Identify the security control type of each set of defense tactics.

Walls, bollards, fences, guard dogs, cameras, and lighting are what type of security control?

Security awareness programs, BYOD policies, and ethical hiring practices are what type of security control?

Encryption, biometric fingerprint readers, firewalls, endpoint security, and intrusion detection systems are what type of security control?

Intrusion Detection and Attack Indicators
What's the difference between an IDS and an IPS?

What's the difference between an indicator of attack (IOA) and an indicator of compromise (IOC)?

The Cyber Kill Chain
Name the seven stages of the cyber kill chain, and provide a brief example of each.

Stage 1:

Stage 2:

Stage 3:

Stage 4:

Stage 5:

Stage 6:

Stage 7:

Snort Rule Analysis
Use the provided Snort rules to answer the following questions:

Snort Rule #1

alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
Break down the Snort rule header and explain what this rule does.

What stage of the cyber kill chain does the alerted activity violate?

What kind of attack is indicated?

Snort Rule #2

alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)
Break down the Snort rule header and explain what this rule does.

What layer of the cyber kill chain does the alerted activity violate?

What kind of attack is indicated?

Snort Rule #3

Your turn! Write a Snort rule that alerts when traffic is detected inbound on port 4444 to the local network on any port. Be sure to include the msg in the rule option.

Part 2: "Drop Zone" Lab
In this lab exercise, you will assume the role of a junior security administrator at an indoor skydiving company called Drop Zone.

Your company hosts a web server that accepts online reservations and credit card payments. As a result, your company must comply with PCI/DSS regulations that require businesses who accept online credit card payments to have a firewall in place to protect personally identifiable information (PII).

Your network has been under attack from the following three IPs: 10.208.56.23, 135.95.103.76, and 76.34.169.118. You have decided to add these IPs to the drop zone within your firewall.

The first requirement of PCI/DSS regulations is to protect your system with firewalls. "Properly configured firewalls protect your card data environment. Firewalls restrict incoming and outgoing network traffic through rules and criteria configured by your organization." —
PCI DSS Quick Reference GuideLinks to an external site.

Set Up
For this lab, use the web lab virtual machine (VM).

Once logged in, launch the firewalld and ufw docker containers, and create an interactive session with the firewalld container with the following command:
docker exec -it firewalld bash

Instructions
The senior security manager has drafted configuration requirements for your organization with the following specification:

You need to configure zones that will segment each network according to service type.

public Zone
Services: HTTP, HTTPS, POP3, SMTP
Interface: ETH0
web Zone
Source IP: 201.45.34.126
Services: HTTP
Interface: ETH1
sales Zone
Source IP: 201.45.15.48
Services: HTTPS
Interface: ETH2
mail Zone
Source IP: 201.45.105.12
Services: SMTP, POP3
Interface: ETH3
You also need to drop all traffic from the following blacklisted IPs:

10.208.56.23
135.95.103.76
76.34.169.118
Reference: https://manpages.debian.org/testing/firewalld/firewall-cmd.1.en.htmlLinks to an external site.

Uninstall ufw
Before getting started, you should verify that you do not have any instances of UFW running. This will avoid conflicts with your firewalld service. This also ensures that firewalld will be your default firewall.

Run the command that removes any running instance of UFW.
Enable and start firewalld.
By default, the firewalld service should be running. If not, then run the commands that enable and start firewalld upon boots and reboots.

NOTE
This will ensure that firewalld remains active after each reboot.

Confirm that the service is running.
Run the command that checks whether the firewalld service is up and running.
List all firewall rules currently configured.
Next, lists all currently configured firewall rules. This will give you a good idea of what's currently configured and save you time in the long run by ensuring that you don’t duplicate work that’s already done.

Run the command that lists all currently configured firewall rules.

Take note of what zones and settings are configured. You many need to remove unneeded services and settings.

List all supported service types that can be enabled.
Run the command that lists all currently supported services to find out whether the service you need is available.

Notice that the home and drop zones are created by default.

Zone views.
Run the command that lists all currently configured zones.

Notice that the public and drop zones are created by default. Therefore, you will need to create zones for web, sales, and mail.

Create zones for web, sales and mail.
Run the commands that create web, sales, and mail zones.

HINT
Remember to reload the firewalld service in order to apply your new settings before moving on.

Set the zones to their designated interfaces.
Run the commands that set your eth interfaces to your zones.

Use the configurations provided at the beginning of the instructions.
Add services to the active zones.
Run the commands that add services to the public zone, the web zone, the sales zone, and the mail zone.

Use the configurations provided at the beginning of the instructions.
Add your adversaries to the drop zone.
Run the command that will add all current and any future blacklisted IPs to the drop zone.
Make rules permanent, then reload them.
It's good practice to ensure that your firewalld installation remains nailed up and retains its services across reboots. This helps ensure that the network remains secure after unplanned outages such as power failures.

Run the command that reloads the firewalld configurations and writes it to memory.
View active zones.
Now, provide truncated listings of all currently active zones. This is a good time to verify your zone settings.

Run the command that displays all zone services.
Block an IP address.
Use a rich-rule that blocks the IP address 138.138.0.3 on your public zone.
Block Ping/ICMP Requests
Harden your network against ping scans by blocking icmp ehco replies.

Run the command that blocks pings and icmp requests in your public zone.
Rule Check
Now that you've set up your brand new firewalld installation, it's time to verify that all of the settings have taken effect.

Run the command that lists all of the rule settings. Run one command at a time for each zone.

Are all of the rules in place? If not, then go back and make the necessary modifications before checking again.

Congratulations! You have successfully configured and deployed a fully comprehensive firewalld installation.

Part 3: IDS, IPS, DiD, and Firewalls
Answer the following review questions.

IDS vs. IPS Systems
Name and define two ways an IDS connects to a network.

Describe how an IPS connects to a network.

What type of IDS compares patterns of traffic to predefined signatures and is unable to detect zero-day attacks?

What type of IDS is beneficial for detecting all suspicious traffic that deviates from the well-known baseline and is excellent at detecting when an attacker probes or sweeps a network?

Defense-in-Depth
For each of the following scenarios, provide the layer of defense-in-depth that applies:

A criminal hacker tailgates an employee through an exterior door into a secured facility, explaining that they forgot their badge at home.

A zero-day goes undetected by antivirus software.

A criminal successfully gains access to HR’s database.

A criminal hacker exploits a vulnerability within an operating system.

A hacktivist organization successfully performs a DDoS attack, taking down a government website.

Data is classified at the wrong classification level.

A state-sponsored hacker group successfully firewalked an organization to produce a list of active services on an email server.

Name one method of protecting data-at-rest from being readable on hard drive.

Name one method of protecting data-in-transit.

What technology could provide law enforcement with the ability to track and recover a stolen laptop?

How could you prevent an attacker from booting a stolen laptop using an external hard drive?

Firewall Architectures and Methodologies
Which type of firewall verifies the three-way TCP handshake? TCP handshake checks are designed to ensure that session packets are from legitimate sources.

Which type of firewall considers the connection as a whole? Meaning, instead of considering only individual packets, these firewalls consider whole streams of packets at one time.

Which type of firewall intercepts all traffic prior to forwarding it to its final destination? In a sense, these firewalls act on behalf of the recipient by ensuring the traffic is safe prior to forwarding it.

Which type of firewall examines data within a packet as it progresses through a network interface by examining source and destination IP address, port number, and packet type—all without opening the packet to inspect its contents?

Which type of firewall filters solely based on source and destination MAC address?

Optional Additional Challenge Lab: "Green Eggs & SPAM"
This optional activity is a culmination of the topics and tools covered during the following Module 11 activities:

Alert - FTP File Extraction
Alert - ET INFO Executable Download
Alert - C2 Beacon
Investigation, Analysis, and Escalation
Threat Hunting - Cyber Threat Intelligence
In this activity, you will target spam, uncover its whereabouts, and attempt to discover the intent of the attacker.

You will assume the role of a junior security administrator working for the Department of Technology for the State of California.

As a junior administrator, your primary role is to perform the initial triage of alert data: the initial investigation and analysis followed by an escalation of high-priority alerts to senior incident handlers for further review.

You will work as part of a Computer and Incident Response Team (CIRT), responsible for compiling threat intelligence as part of your incident report.

Instructions
NOTE
Log in to the Security Onion VM, and use the following indicator of attack to complete this portion of the assignment.

Locate the indicator of attack in Security Onion based off of the following:

Source IP/port: 188.124.9.56:80
Destination address/port: 192.168.3.35:1035
Event message: ET TROJAN JS/Nemucod.M.gen downloading EXE payload
Answer the following questions:

What was the indicator of an attack?

HINT
What was the adversarial motivation (purpose of the attack)?

Describe observations and indicators that may be related to the perpetrators of the intrusion. Categorize your insights according to the appropriate stage of the cyber kill chain, as structured in the following table:

TTP	Example	Findings
Reconnaissance	How did the attacker locate the victim?	
Weaponization	What was downloaded?	
Delivery	How was it downloaded?	
Exploitation	What does the exploit do?	
Installation	How is the exploit installed?	
Command & Control (C2)	How does the attacker gain control of the remote machine?	
Actions on Objectives	What does the software that the attacker sent do to complete its tasks?	
What are your recommended mitigation strategies?

List your third-party references.
