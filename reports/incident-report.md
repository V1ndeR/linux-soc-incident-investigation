# Linux SOC Incident Investigation
## LNX-001 — Suspicious Bash Script Execution

### 1. Incident Overview

| Field | Details |
|---|---|
| Incident ID | LNX-001 |
| Investigation Date | 2026-11-16 |
| Operating System | Ubuntu 24.04 |
| Environment | Controlled Laboratory |
| User | v1nr |
| Alert Type | Suspicious Script Execution |
| Investigated File | update.sh |
| Severity | Low |
| Classification | Benign — Authorized Laboratory Activity |
| Status | Closed |
| Escalation | Not Required |

**Disclaimer:** This investigation documents a simulated security alert involving an intentionally created Bash script. No actual system compromise occurred as part of this exercise.

---

### 2. Executive Summary

On November 16, 2026, a Bash script named `update.sh` was investigated on an Ubuntu 24.04 laboratory endpoint.

The investigation focused on identifying the process responsible for executing the script, reconstructing its parent-child process relationships, analyzing its contents, examining file metadata, and reviewing associated activity.

Process analysis identified `update.sh` running under the `v1nr` user account, launched from an interactive Zsh terminal session.

The script appended a predefined message to `activity.log` and executed `sleep 300`.

Three log entries containing the message `System update completed` were observed.

No network connections or persistence mechanisms attributable to the script were identified during the limited checks performed.

The activity was confirmed as part of an authorized laboratory exercise.

**Final Assessment: Benign — Authorized Laboratory Activity.**

---

### 3. Process Investigation

#### 3.1 Process Discovery

The following command was used to identify the running script:

```bash
ps -eo pid,ppid,user,args | grep '[u]pdate.sh'
```

**Observed process:**

```text
PID:     80084
PPID:    6740
USER:    v1nr
COMMAND: /bin/bash ./incident-001-lab/update.sh
```

**Findings:**

- The investigated script was running as PID `80084`.
- The process belonged to user `v1nr`.
- The parent process ID was `6740`.
- The script was interpreted by Bash.

#### 3.2 Parent-Child Process Analysis

Command:

```bash
pstree -aps 80084
```

**Observed output:**

```text
systemd,1 splash
  `-systemd,4171 --user
      `-gnome-terminal-,6733
          `-zsh,6740
              `-update.sh,80084 ./incident-001-lab/update.sh
                  `-sleep,80089 300
```

**Process hierarchy:**

```text
systemd (PID 1)
└── systemd --user (PID 4171)
    └── gnome-terminal (PID 6733)
        └── zsh (PID 6740)
            └── update.sh (PID 80084)
                └── sleep (PID 80089)
```

**Analysis:**

The process hierarchy shows that `update.sh` was executed from an interactive terminal session.

The immediate parent process was `zsh`, and the observed child process was `sleep`.

This behavior was consistent with the known laboratory script.

No unexpected child process was identified in the captured process tree.

The exact process execution timestamp was not preserved.

---

### 4. Script Analysis

**Investigated file:**

```text
/home/v1nr/soc-lab/incident-001-lab/update.sh
```

**Script contents:**

```bash
#!/bin/bash

echo "System update completed" >> ~/soc-lab/incident-001-lab/activity.log
sleep 300
```

#### Behavior Analysis

| Command | Function |
|---|---|
| `#!/bin/bash` | Specifies the Bash interpreter |
| `echo` | Generates a predefined text message |
| `>>` | Appends the message to an existing file or creates the file if needed |
| `sleep 300` | Pauses execution for approximately 300 seconds |

The examined script does not contain commands for downloading files, initiating network connections, modifying user privileges, or establishing persistence.

The message `System update completed` is a predefined string and does not indicate that an operating system update actually occurred.

**Finding:** The script's examined functionality was limited to local file writing and a timed delay.

---

### 5. File Metadata Analysis

The following command was used to examine the script:

```bash
stat incident-001-lab/update.sh
```

**Observed metadata:**

| Attribute | Value |
|---|---|
| Filename | update.sh |
| Size | 97 bytes |
| Owner | v1nr |
| Group | v1nr |
| Permissions | 0764 |
| Birth | 2026-11-16 10:33:01 |
| Modify | 2026-11-16 10:35:41 |
| Change | 2026-11-16 10:48:06 |

**Timezone:** UTC−05:00

#### Findings

- The file inode was created at approximately 10:33:01.
- The file contents were last modified at approximately 10:35:41.
- The file metadata or contents last changed at approximately 10:48:06.
- The file belonged to user `v1nr` when examined.

These timestamps describe file-system activity, not the exact time of process execution.

File ownership does not independently establish who originally created the file.

---

### 6. SHA256 Analysis

The following command was used:

```bash
sha256sum incident-001-lab/update.sh
```

**Observed SHA256:**

```text
03e148c9cdd70f7f399fe301e49ab64e04fc86306d2dfc0961e7979854b32323
```

#### Analysis

The SHA256 value provides a cryptographic fingerprint of the examined script.

It can be used to identify whether a later version of the file differs from the version investigated.

The hash was collected and saved as investigation evidence.

No independent trusted-baseline comparison or malware reputation lookup was performed.

**Finding:** Script fingerprint documented.

---

### 7. Activity Log Investigation

**Investigated log:**

```text
/home/v1nr/soc-lab/incident-001-lab/activity.log
```

Command:

```bash
cat ~/soc-lab/incident-001-lab/activity.log
```

**Observed output:**

```text
System update completed
System update completed
System update completed
```

#### Findings

Three identical entries were observed.

The messages matched the text generated by the known script.

The log did not contain individual timestamps or process identifiers.

The entries are consistent with repeated execution of the append operation, but they do not independently prove three separate script executions.

#### 7.1 Activity Log Metadata

Command:

```bash
stat ~/soc-lab/incident-001-lab/activity.log
```

**Observed metadata:**

| Attribute | Value |
|---|---|
| Filename | activity.log |
| Size | 72 bytes |
| Owner | v1nr |
| Group | v1nr |
| Permissions | 0664 |
| Birth | 2026-11-16 10:51:18 |
| Modify | 2026-11-16 11:06:18 |
| Change | 2026-11-16 11:06:18 |
| Access | 2026-11-16 11:57:05 |

**Timezone:** UTC−05:00

#### Analysis

The log file inode was created at approximately 10:51:18.

Its contents were last modified at approximately 11:06:18.

The exact time of each individual log entry cannot be established from these metadata values.

**Finding:** Three matching log entries were observed, but precise individual event timestamps were unavailable.

---

### 8. Network Investigation

The investigation included inspection of active network sockets using:

```bash
sudo ss -tunap
```

The available socket snapshots were reviewed for connections attributable to the investigated script.

#### Findings

- No network socket was positively associated with `update.sh` in the reviewed output.
- The examined script contained no explicit network communication command.
- No command-and-control communication was identified.
- No data exfiltration was identified.

#### Limitations

The network investigation relied on point-in-time socket inspection.

No dedicated packet capture or historical network flow correlation was performed for the script.

Therefore, the available evidence does not establish the absence of all network activity throughout the script's lifetime.

**Network Assessment:** No network activity attributable to the script was identified during the available inspection.

---

### 9. Persistence Investigation

The investigation included limited checks for mechanisms that could automatically execute the investigated script.

#### 9.1 User Crontab

Command:

```bash
crontab -l
```

No entries associated with `update.sh` were found in the investigated user's Crontab.

#### 9.2 systemd Services

System-level and user-level service listings were reviewed for evidence of a service associated with the investigated script.

No service was identified as a confirmed launcher of `update.sh`.

#### Persistence Findings

| Mechanism | Result |
|---|---|
| User Crontab | No associated entry identified |
| System-level systemd service listing | No confirmed association identified |
| User-level systemd service listing | No confirmed association identified |

#### Limitations

The persistence investigation was not exhaustive.

Not all system-wide Cron configurations, systemd timers, or service execution configurations were individually examined.

**Persistence Assessment:** No persistence mechanism associated with `update.sh` was confirmed during the performed checks.

---

### 10. Incident Timeline

**Date:** November 16, 2026  
**Timezone:** UTC−05:00

| Time | Event | Evidence |
|---|---|---|
| 10:33:01 | `update.sh` inode created | Script metadata |
| 10:35:41 | Script contents last modified | Script metadata |
| 10:48:06 | Script metadata or contents last changed | Script metadata |
| 10:51:18 | `activity.log` inode created | Activity log metadata |
| 11:06:18 | Activity log contents last modified | Activity log metadata |
| Not recorded | `update.sh` observed running as PID 80084 | Process inspection |
| Not recorded | `zsh` identified as parent process | Process tree |
| Not recorded | `sleep 300` observed as child process | Process tree |

**Important:** File-system timestamps do not establish the exact execution time of the script.

A separate timeline is available in:

`investigation/timeline.md`

---

### 11. Evidence Collected

The following evidence files were saved during the investigation:

| File | Description |
|---|---|
| `evidence/process.txt` | Captured parent-child process hierarchy |
| `evidence/file-metadata.txt` | Metadata of the investigated Bash script |
| `evidence/script-hash.txt` | SHA256 hash of the Bash script |
| `evidence/activity.log` | Preserved copy of the script activity log |
| `investigation/timeline.md` | Documented investigation timeline |

#### Activity Log Integrity

A copy of `activity.log` was preserved in the `evidence/` directory.

SHA256 comparison confirmed that the preserved copy matched the original file at the time of verification.

**SHA256:**

`20ee2c0ff6f74248d365709c768076da2afb2840a8c4159c506e7b394c96e250`

#### Process Evidence Integrity

A SHA256 hash was calculated for `evidence/process.txt`.

**SHA256:**

```text
94c2a91e18846bc01e0fef09b81ef6278d80ea0191e057ddc6d560e9c32460c2
```

This value identifies the contents of the collected process evidence at the time the hash was calculated.

#### Evidence Limitations

The investigation was conducted using live system inspection rather than a complete forensic acquisition.

### 12. MITRE ATT&CK Mapping

#### T1059.004 — Command and Scripting Interpreter: Unix Shell

**Observed evidence:**

- The investigated file was a Bash script.
- The process executed through `/bin/bash`.
- The script was launched from an interactive shell.
- The script created a `sleep 300` child process.

**Assessment:**

The observed behavior is consistent with Unix shell execution described by MITRE ATT&CK T1059.004.

However, the activity was authorized and benign.

This mapping describes the technical behavior observed during the simulation and does not represent a confirmed malicious technique.

#### Persistence

No MITRE ATT&CK persistence technique was confirmed.

No persistence technique is assigned to this incident.

---

### 13. Final SOC Assessment

#### What Happened?

An authorized Bash script named `update.sh` was executed on an Ubuntu 24.04 laboratory workstation.

The script ran under the `v1nr` account from an interactive terminal session.

It appended a predefined message to `activity.log` and launched a `sleep 300` child process.

#### Malicious or Benign?

**Classification: Benign.**

The activity was intentionally created and executed as part of an authorized laboratory investigation.

The observed process behavior and examined script contents were consistent with the expected test.

No malicious behavior was demonstrated in the collected evidence.

#### Severity

**Low**

The activity was authorized, and no evidence requiring incident escalation was identified.

#### Confidence

**High confidence in the benign classification**, based on the directly known laboratory context.

This confidence does not imply that every possible system-level threat or persistence mechanism was comprehensively investigated.

#### Final Decision

**Close Alert — No Escalation Required.**

The observed activity was consistent with the known laboratory simulation.

No containment, eradication, or recovery actions were required.

---

### 14. Investigation Limitations

The following limitations apply to this investigation:

1. Exact script execution timestamps were not preserved.
2. Activity log entries did not contain individual timestamps.
3. Network inspection was based on available socket snapshots.
4. Persistence checks were limited in scope.
5. SHA256 values were not compared with a trusted software baseline.
6. Some inspected information was not preserved as separate evidence files.
7. No complete forensic image was collected.

These limitations do not change the known authorized nature of the laboratory activity, but they restrict conclusions about what the collected technical evidence independently proves.

---

### 15. Lessons Learned

This investigation demonstrated practical Linux SOC Analyst skills, including:

- Identifying suspicious processes with `ps`.
- Reconstructing process relationships using `pstree`.
- Interpreting PID and PPID.
- Analyzing Bash script behavior.
- Examining file metadata with `stat`.
- Calculating SHA256 hashes.
- Reviewing application logs.
- Inspecting network sockets.
- Checking selected persistence mechanisms.
- Building an evidence-based incident timeline.
- Distinguishing confirmed facts from assumptions.
- Documenting investigation limitations.
- Assigning incident severity.
- Making a justified SOC alert closure decision.

---

### 16. Conclusion

The investigation confirmed that `update.sh` was executed under the `v1nr` account on an Ubuntu 24.04 laboratory endpoint.

The observed process chain was:

```text
gnome-terminal
    └── zsh
          └── update.sh
                └── sleep 300
```

The examined script performed local log writing and a timed delay.

Three matching activity log entries were observed.

No network connection or persistence mechanism attributable to the script was confirmed within the scope of the available investigation.

The script execution was part of an authorized laboratory simulation.

**Final Classification:** Benign — Authorized Laboratory Activity  
**Severity:** Low  
**Disposition:** Closed  
**Escalation:** Not Required

---

**End of Report — LNX-001**
