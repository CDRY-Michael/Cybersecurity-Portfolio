# SMB Enumeration Lab Findings

## Summary

SMB enumeration and network reconnaissance were successfully performed against a Windows 11 host within an isolated VMware lab environment.

---

## Key Findings

### Network Connectivity Established

- ICMP communication between Kali Linux and the Windows host was successful.
- The target system responded consistently to ping requests.

---

### SMB Services Exposed

Nmap scanning identified multiple exposed Windows-related services:

| Port | Service      | Description                     |
| ---- | ------------ | ------------------------------- |
| 135  | MSRPC        | Microsoft Remote Procedure Call |
| 139  | NetBIOS-SSN  | NetBIOS Session Service         |
| 445  | Microsoft-DS | SMB File Sharing                |

---

### SMB Share Enumeration Successful

Authenticated SMB enumeration revealed the following shares:

- ADMIN$
- C$
- IPC$
- LabShare

The presence of `LabShare` confirmed successful custom share exposure within the lab environment.

---

### NetBIOS and Workgroup Enumeration

enum4linux successfully identified:

- Windows hostname
- WORKGROUP domain/workgroup name
- File Server Service visibility
- NetBIOS information

---

### Anonymous Enumeration Restricted

Null session attempts using anonymous credentials were denied by the target system.

This indicates:

- authentication enforcement
- restricted guest enumeration
- improved SMB security posture

---

## Security Impact

Exposed SMB services may increase attack surface visibility within internal networks if improperly secured. Restricting anonymous enumeration and enforcing authentication significantly reduces unauthorized access and reconnaissance opportunities.

---

## Skills Demonstrated

- Network reconnaissance
- SMB enumeration
- Service discovery
- NetBIOS analysis
- Authentication behavior analysis
- Security documentation
