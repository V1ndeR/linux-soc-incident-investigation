# Incident 001 — Investigation Timeline

**Incident ID:** LNX-001  
**Host:** Ubuntu 24.04 — Lab Environment  
**Investigation Date:** 2026-11-16  
**Timezone:** UTC-05:00  
**Incident Type:** Suspicious Script Execution  
**Environment:** Controlled SOC Simulation

## 1. Timeline of Events

| Timestamp | Event | Evidence |
|---|---|---|
| 10:33:01 | The `update.sh` file inode was created. | File metadata |
| 10:35:41 | The script content was last modified. | File metadata |
| 10:48:06 | The script metadata or content was last changed. | File metadata |
| 10:51:18 | The `activity.log` file inode was created. | Activity log metadata |
| 11:06:18 | The activity log content was last modified. | Activity log metadata |
| Not recorded | The `update.sh` process was observed running under user `v1nr`. | Process evidence |
| Not recorded | The script was observed launching `sleep 300`. | Process tree |

## 2. Process Execution Chain

```text
systemd (PID 1)
    └── systemd --user (PID 4171)
          └── gnome-terminal (PID 6733)
                └── zsh (PID 6740)
                      └── update.sh (PID 80084)
                            └── sleep (PID 80089)
```

## 3. Key Findings

- The script executed under the `v1nr` user account.
- The observed parent process was `zsh`.
- The script recorded messages in `activity.log`.
- Three activity log entries were observed.
- No network sockets associated with the investigated script were observed during the network inspection.
- No persistence mechanism associated with this script was confirmed.

## 4. Limitations

- Exact process execution timestamps were not captured.
- Activity log entries do not contain timestamps.
- The network inspection was a point-in-time snapshot.
- The persistence investigation was not exhaustive.
- File ownership does not independently establish who originally created the file.

## 5. Preliminary Assessment

**Classification:** Benign — Controlled Laboratory Activity

The available evidence is consistent with an intentionally executed test script. No malicious behavior was demonstrated in the collected evidence.
