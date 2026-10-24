# Sysmon + Atomic Red Team Detection Lab (Splunk)

A small home SOC lab where I collect Windows Security and Sysmon logs in Splunk, run a simulated attacker technique with Atomic Red Team, and find it in the logs. I also fixed two log-collection problems along the way.

**Everything here is simulated activity in an isolated lab.** It is not a real attack or a real incident.

---

## Lab Architecture

```
SOC-Windows (Windows 11)
  Sysmon + Windows Security logs
        |
        v
Splunk Universal Forwarder  --(TCP 9997, host-only network)-->  SOC-Splunk (Ubuntu 24.04)
                                                                 Splunk Enterprise
                                                                 192.168.56.10
```

| VM | Role | Lab IP |
| --- | --- | --- |
| SOC-Splunk | SIEM server (Ubuntu 24.04 LTS, Splunk Enterprise) | 192.168.56.10 |
| SOC-Windows | Monitored endpoint (Windows 11) | 192.168.56.20 |

## Tools

- Oracle VirtualBox 7.2.14
- Splunk Enterprise and Splunk Universal Forwarder 10.4.2
- Sysmon v15.22 with the SwiftOnSecurity sysmon-config
- Atomic Red Team (Invoke-AtomicRedTeam)

---

## What I Built

1. Gave the Splunk server a fixed IP on a host-only network so the forwarder always reaches it.
2. Forwarded the Windows Security log to Splunk (index `main`).
3. Installed Sysmon on the Windows VM and forwarded its log to Splunk.
4. Wrote searches that pull the fields I need (program, command line, parent program, user) out of the Sysmon events.
5. Ran an Atomic Red Team test and found its footprint in Splunk.

### Evidence: setup

| Step | Screenshot |
| --- | --- |
| Splunk service running | ![Splunk running](Screenshots/01-splunk-service-running.png) |
| Server has a fixed lab IP | ![Static IP](Screenshots/02-splunk-server-static-ip.png) |
| Forwarder points to the server | ![Forwarder config](Screenshots/03-forwarder-points-to-splunk-server.png) |
| Windows Security events arriving | ![Security events](Screenshots/04-windows-security-events-in-splunk.png) |

---

## Problems I Troubleshot

### 1. Forwarder was sending to an old IP
- **Symptom:** The Splunk server's address had been assigned by DHCP and changed, so the forwarder pointed at an address that no longer existed.
- **Fix:** Set a fixed IP (`192.168.56.10`) on the server and updated `outputs.conf` on the Windows VM to match.
- **Check:** Windows Security events appeared in Splunk.

### 2. Sysmon logs were not reaching Splunk (access denied)
- **Symptom:** Sysmon was running and writing events on the Windows VM, but nothing arrived in Splunk. The forwarder's `splunkd.log` showed `Could not subscribe to Windows Event Log channel 'Microsoft-Windows-Sysmon/Operational'` with `errorCode=5` (access denied).
- **Cause:** The forwarder's service account was not allowed to read the Sysmon log.
- **Fix:** Added the forwarder's service account to the local **Event Log Readers** group, then restarted the forwarder.
- **Check:** Sysmon events appeared in Splunk.

![Access denied error](Screenshots/05-forwarder-sysmon-access-denied-error.png)

### 3. Splunk trial license expired
- The Enterprise trial had expired, so I switched the server to the Free license. This is fine for searching, but **the Free license does not support scheduled alerts**, so the detections below are manual searches, not automatic alerts.

---

## Detection: Account Discovery (MITRE ATT&CK T1087.001)

**Technique:** An attacker who has access to a machine lists local user accounts and groups to learn what is there.

**Simulation:** Atomic Red Team test `T1087.001-8` ("Enumerate all accounts on Windows (Local)"), run on SOC-Windows.

![Sysmon installed](Screenshots/06-sysmon-installed-and-running.png)
![Atomic test run](Screenshots/08-atomic-red-team-t1087-test-run.png)

### Search

```
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "<EventID>1</EventID>"
| rex "Name='Image'>(?<Image>[^<]+)"
| rex "Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex "Name='ParentImage'>(?<ParentImage>[^<]+)"
| rex "Name='User'>(?<User>[^<]+)"
| search Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\cmdkey.exe" OR Image="*\\whoami.exe"
| table _time Image CommandLine ParentImage User
| sort - _time
```

(The Sysmon fields are extracted with `rex` because I did not use the Splunk Sysmon add-on.)

### What I found

![Detection in Splunk](Screenshots/09-account-discovery-detected-in-splunk.png)

- Within about one second (01:40:26 to 01:40:27 UTC), Sysmon recorded `whoami`, `net user`, `net localgroup`, `net localgroup "Users"`, and `cmdkey /list`.
- Those commands were launched by `cmd.exe`, which is how the test script runs them.
- `cmdkey /list` checks for stored credentials, which an attacker would want to know about.
- For comparison, I also typed `net user` and `net localgroup` by hand earlier. Those ran directly from `powershell.exe`, one at a time, about a minute apart. The rapid burst and the `cmd.exe` parent are what make the test stand out.

### How an analyst would treat this
1. Look at the parent process and the speed. A fast burst of enumeration commands is unusual for a person typing.
2. Check which user ran them and whether that account normally does this.
3. Look for what happened right before and after (new logons, new services, files created).
4. Escalate if the activity is not expected or is followed by other suspicious actions.

**Possible false positives:** IT staff or management tools also run `net user` and `whoami`. The cluster and the credential check are the parts worth a closer look.

---

## Evidence: Sysmon capturing admin activity

Sysmon also recorded the permission fix from troubleshooting problem 2 (`net localgroup "Event Log Readers" ... /add`).

![Sysmon admin command](Screenshots/07-sysmon-captures-admin-commands-in-splunk.png)

---

## MITRE ATT&CK Coverage

| Technique | Status | Evidence |
| --- | --- | --- |
| T1087.001 Account Discovery: Local Account | Done, found in Splunk | Screenshots 08 and 09 |
| T1053.005 Scheduled Task | Planned | |
| T1136.001 Create Local Account | Planned | |

---

## Limitations

- Everything is simulated on one endpoint in an isolated lab.
- Detections are manual searches, not scheduled alerts, because the Splunk Free license does not support alerting.
- The detection is based on process names and parents, so it is easy to tune but not hardened against an attacker who renames tools.
- Timestamps in Splunk are shown in UTC.

## Next Steps

- Add detections for scheduled task creation and new local account creation.
- Add scheduled alerts once I have a license that supports them.
- Add a Kali VM so activity comes from a real separate source address.
