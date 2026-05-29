# IR-004: Kerberoasting Attempt Against Service Account

| Field       | Value                |
| ----------- | -------------------- |
| Incident ID | IR-004               |
| Severity    | Medium               |
| Status      | Closed               |
| Detected    | 2026-05-28 02:25 UTC |
| Reported by | Splunk detection     |
| Analyst     | Michael Chaudhary    |
| MITRE       | T1558.003            |

## Summary

A Kerberos service ticket (TGS) was requested for the `svc_sql` service account using RC4 (etype 23) encryption by the standard user account `john.smith`. RC4 ticket requests for user style accounts are uncommon in environments that default to AES, and are a strong indicator of Kerberoasting. The ticket would have been captured and taken offline by the attacker for password cracking.

## Detection

- Splunk search on `EventCode=4769 Ticket_Encryption_Type=0x17` returned one event matching the Kerberoasting pattern.
- Account that requested the ticket: `john.smith@CORP.LOCAL`.
- Target service account: `svc_sql` with SPN `MSSQLSvc/dc01.corp.local:1433`.
- Client address: `::ffff:192.168.40.130` (the attacker host from earlier incidents).
- The same IP and account appeared in IR-001 (initial credential compromise), so this activity is treated as a continuation of the same attack chain.

## Timeline (UTC)

| Time         | Activity                                                                              |
| ------------ | ------------------------------------------------------------------------------------- |
| 02:25:39     | Event 4769: TGS requested by `john.smith` for `svc_sql`, Ticket Encryption Type 0x17. |
| 02:25 approx | Ticket captured to file (`kerberoast_hashes.txt`) by attacker tooling.                |

## Impact

- A TGS encrypted with the `svc_sql` account password hash was issued and could be taken offline for cracking.
- Offline cracking was attempted against the captured hash. The `svc_sql` password (`STRONG@PASS@321`) was strong and not present in standard wordlists, so the offline crack attempt did not succeed within the rockyou dictionary.
- No service account compromise is confirmed at this time. The captured ticket remains a risk if the attacker has access to larger wordlists, custom dictionaries, or significant compute over a longer period.
- Kerberoasting generates no failed logons, no lockouts, and no errors. The attack succeeded in the sense that the ticket was captured. Detection is the only signal that it happened.

## Indicators of Compromise (IOCs)

- Account that requested the ticket: `corp.local\john.smith`
- Target service account: `corp.local\svc_sql`
- SPN: `MSSQLSvc/dc01.corp.local:1433`
- Ticket Encryption Type: `0x17` (RC4-HMAC, the Kerberoasting fingerprint)
- Client address: `192.168.40.130`
- Related incident: IR-001 (the `john.smith` credential used to request the ticket)

## Recommendations

1. Reset the `svc_sql` account password. Although the offline crack did not succeed in this window, the captured ticket remains useful to the attacker. Rotating the password renders the captured hash worthless.
2. Where possible, migrate `svc_sql` and other service accounts to Group Managed Service Accounts (gMSAs). gMSAs use long, automatically rotated passwords that are not vulnerable to Kerberoasting.
3. Verify that all service accounts in the domain use strong passwords. The actual mitigation against Kerberoasting is password strength, since the captured ticket can only be cracked if the password is weak.
4. Disable RC4 encryption for Kerberos where possible. Modern environments should be using AES (etype 18). Removing RC4 support eliminates the easy crack path that attackers prefer.
5. Add a Splunk detection that alerts on 4769 events with `Ticket_Encryption_Type=0x17` from non machine accounts. Filtering by `Account_Name!="*$"` removes the machine account noise.
6. Review which user accounts have SPNs registered. Service accounts often retain unused SPNs from legacy software, and each one is a potential Kerberoasting target.

## Status

- Closed.
- Detection coverage takeaway: Kerberoasting leaves no failures and no errors. It can only be detected by looking at the encryption type of normal looking Kerberos traffic. A detection that watches for failures will miss it entirely.
- Open item for follow up: the strong password on `svc_sql` was the actual mitigation here. Confirming all service account passwords are similarly strong, or migrating to gMSAs, removes this attack class.
