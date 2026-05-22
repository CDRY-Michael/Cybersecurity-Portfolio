# Network Traffic Analysis Findings

## Summary

Network traffic analysis was successfully performed between a Kali Linux attacker machine and a Windows 11 target machine within an isolated VMware host-only lab environment.

Traffic was captured and analyzed using Wireshark to inspect multiple protocols, authentication activity, and reconnaissance behavior across the internal network.

---

## Key Findings

### ICMP Traffic Observed

ICMP echo request and reply packets were successfully analyzed between the Kali Linux and Windows systems.

This confirmed:

- network connectivity
- host availability
- successful packet transmission

Additional observations included:

- consistent packet replies
- successful communication between Linux and Windows hosts
- expected TTL behavior during transmission

---

### DNS Traffic Captured

DNS queries resolving domains such as `google.com` were identified and inspected.

Observed behavior included:

- UDP port 53 communication
- DNS A record lookups
- plaintext DNS query requests
- domain resolution activity

Packet analysis revealed readable domain queries and response behavior commonly used during normal network communication.

---

### HTTP Traffic Identified

HTTP traffic generated from a local Python web server was successfully captured and inspected.

Captured data included:

- HTTP GET requests
- HTTP 200 OK responses
- plaintext web traffic
- visible HTTP headers and content

Because HTTP traffic was unencrypted, request and response contents were directly visible during packet inspection.

---

### SMB Authentication Traffic Detected

SMB2 traffic was captured during SMB enumeration and authentication activities over TCP port 445.

Observed SMB behavior included:

- NTLMSSP authentication negotiation
- SMB session setup requests
- SMB session setup responses
- authenticated share enumeration activity

Packet inspection demonstrated how SMB authentication traffic can reveal account usage and network share interaction between systems.

---

### TCP Handshake Analysis Performed

TCP connection establishment packets were successfully analyzed during network communication.

The following stages were identified:

- SYN
- SYN-ACK
- ACK

Analysis confirmed successful TCP three-way handshake communication between hosts and demonstrated standard TCP session establishment behavior.

---

### Nmap Reconnaissance Traffic Detected

Nmap SYN scanning activity generated multiple TCP SYN packets targeting various ports on the Windows host.

Observed activity included:

- reconnaissance scanning behavior
- service discovery attempts
- targeted SMB-related ports
- repeated SYN packet transmission across multiple ports

Traffic patterns matched typical TCP SYN reconnaissance behavior commonly associated with network scanning and service enumeration activities.

---

### ARP Communication Observed

ARP requests and responses were captured within the local network environment.

This demonstrated:

- MAC address resolution
- local device discovery
- broadcast network communication
- host-to-host address mapping behavior

Packet analysis revealed standard ARP communication used for resolving IP addresses to physical MAC addresses within the VMware host-only network.

---

## Security Impact

Captured traffic demonstrated how protocol-level network visibility can assist security analysts in identifying reconnaissance activity, authentication attempts, exposed services and unencrypted communication within internal environments.

The project highlighted how protocols such as SMB, HTTP, and DNS may expose sensitive operational information if improperly monitored or secured.

Traffic analysis also demonstrated how attackers and defenders can both utilize network visibility for reconnaissance, service discovery, authentication monitoring, and behavioral analysis.

---

## Skills Demonstrated

- Packet analysis
- Protocol inspection
- Wireshark traffic analysis
- TCP/IP analysis
- SMB traffic investigation
- DNS analysis
- HTTP traffic inspection
- TCP handshake analysis
- Reconnaissance detection
- Network security monitoring
- Traffic filtering and inspection
- Security documentation
