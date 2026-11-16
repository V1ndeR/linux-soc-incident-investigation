# Linux SOC Incident Investigation — LNX-001

## Suspicious Bash Script Execution

**Environment:** Ubuntu 24.04 | Controlled SOC Laboratory  
**Investigation Date:** November 16, 2026  
**Severity:** Low  
**Classification:** Benign — Authorized Laboratory Activity  
**Final Status:** Closed

---

## Overview

This project documents a Linux endpoint security investigation conducted in a controlled laboratory environment.

The investigation focused on a Bash script named `update.sh` and aimed to determine its execution context, parent-child process relationships, file activity, and potential indicators of malicious behavior.

The objective was to practice a realistic SOC Analyst workflow using Linux command-line tools and evidence-based incident analysis.

**This is an educational simulation, not a real security compromise.**

## Investigation Objectives

- Identify the investigated process and its execution context.
- Reconstruct the parent-child process hierarchy.
- Analyze the Bash script and its functionality.
- Examine file permissions, ownership, and timestamps.
- Calculate SHA256 hashes.
- Investigate associated activity logs.
- Review available network evidence.
- Check selected persistence mechanisms.
- Document findings and investigation limitations.
- Make an evidence-based SOC alert disposition.

## Tools Used

| Tool | Purpose |
|---|---|
| `ps` | Process identification |
| `pstree` | Parent-child process analysis |
| `cat` | File and log examination |
| `stat` | File metadata analysis |
| `sha256sum` | File fingerprinting and integrity verification |
| `ss` | Active network socket inspection |
| `crontab` | User Cron inspection |
| `systemctl` | systemd service review |

## Key Findings

### Process Execution

The investigated Bash script was observed running under the `v1nr` user account.

**Observed process hierarchy:**

```text
systemd
└── systemd --user
    └── gnome-terminal
        └── zsh
            └── update.sh
                └── sleep 300
```

The script was launched from an interactive terminal session.

### Script Behavior

The examined script contained:

```bash
#!/bin/bash

echo "System update completed" >> ~/soc-lab/incident-001-lab/activity.log
sleep 300
```

The script appended a predefined message to a local log file and executed a timed delay.

### File Investigation

The script's SHA256 hash was collected:

```text
03e148c9cdd70f7f399fe301e49ab64e04fc86306d2dfc0961e7979854b32323
```

File ownership, permissions, and timestamps were examined.

### Activity Log

Three matching entries were observed:

```text
System update completed
System update completed
System update completed
```

The log did not contain individual event timestamps.

A copy of the activity log was preserved, and its SHA256 matched the original at the time of verification.

### Network Investigation

No network socket was positively associated with the investigated script in the reviewed snapshots.

The network investigation was limited to available point-in-time observations.

### Persistence Investigation

Limited Cron and systemd checks did not identify a confirmed persistence mechanism associated with `update.sh`.

The persistence review was not exhaustive.

## MITRE ATT&CK Context

**T1059.004 — Command and Scripting Interpreter: Unix Shell**

The observed Bash execution is technically consistent with this ATT&CK technique.

However, the activity was authorized and benign.

No persistence technique was confirmed or assigned to this incident.

## Final SOC Assessment

| Question | Assessment |
|---|---|
| What happened? | An authorized Bash script was executed on a Linux laboratory endpoint. |
| Malicious or Benign? | Benign |
| Severity | Low |
| Evidence of compromise? | None established |
| Escalation required? | No |
| Final decision | Close Alert |

**Conclusion:** The observed activity was consistent with an authorized laboratory simulation. No malicious behavior requiring escalation was demonstrated in the collected evidence.

## Repository Structure

```text
linux-soc-incident-investigation/
├── README.md
├── evidence/
│   ├── activity.log
│   ├── file-metadata.txt
│   ├── process.txt
│   └── script-hash.txt
├── investigation/
│   └── timeline.md
├── mitre/
└── reports/
    └── incident-report.md
```

## Investigation Documentation

- [Full Incident Report](reports/incident-report.md)
- [Incident Timeline](investigation/timeline.md)
- [Process Evidence](evidence/process.txt)
- [Script Metadata](evidence/file-metadata.txt)
- [Script SHA256](evidence/script-hash.txt)
- [Activity Log](evidence/activity.log)

## Skills Demonstrated

- Linux endpoint investigation
- Process and parent-process analysis
- Bash script analysis
- File metadata examination
- SHA256 integrity verification
- Log analysis
- Basic network investigation
- Persistence checks
- MITRE ATT&CK behavioral mapping
- Evidence-based SOC alert classification
- Technical incident reporting

---

**Project Type:** Personal Cybersecurity Portfolio  
**Focus:** Junior SOC Analyst / Linux Endpoint Investigation  
**Environment:** Authorized Laboratory Simulation
