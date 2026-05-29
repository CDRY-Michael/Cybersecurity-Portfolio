# Splunk Detection Queries — AD Attack Lab

## 1. Brute Force (4625, 4740, 4771)
# Password Guessing — failed logons + lockout
index=* (EventCode=4625 OR EventCode=4740)
| table _time, EventCode, Account_Name
| sort -_time

# Password Spraying — Kerberos pre-auth failures
index=* EventCode=4771
| table _time, Account_Name
| sort -_time

## 2. Domain Account Creation (4720, 4728)
index=* "hacker" ("EventCode=4728" OR "EventCode=4720")
| table _time, EventCode, Account_Name

## 3. Additional Local/Domain Groups (4728, 4732, 4756)
index=* (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| table _time, EventCode, Account_Name, Group_Name
| sort -_time

## 4. Kerberoasting (4769)
index=* EventCode=4769 Ticket_Encryption_Type=0x17
| table _time, Account_Name, Service_Name, Client_Address
| sort -_time

## 5. PowerShell Execution (4104, Sysmon EID 1)
# Script Block Logging — captures decoded command content
index=Powershell_Op EventCode=4104
| table _time, ComputerName, User, Message
| sort -_time

# Sysmon Process Create — captures process lineage (parent/child, command line, hashes)
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ParentImage="*powershell.exe*"
| table _time, ComputerName, User, Image, CommandLine, ParentImage
| sort -_time

## 6. Privilege Escalation — DCSync (4662)
index=* EventCode=4662 Account_Name="john.smith"
| table _time, Account_Name, Object_Name, Properties
| sort -_time
