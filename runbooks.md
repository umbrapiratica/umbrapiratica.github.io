---
layout: cyberpunk
title: Run Books
permalink: /run-books/
---

# Run Books

Detailed run books for common offensive security workflows. Each run book provides a repeatable set of steps, tooling references, and validation checks to help streamline operations during assessments.

## Initial Access Reconnaissance

1. **Scope Confirmation**
   - Review rules of engagement and confirm allowed hosts, ports, and protocols.
   - Document testing windows and escalation contacts.
2. **Baseline Network Discovery**
   - Run `nmap -sn <target>/24` to identify live hosts.
   - Capture results with timestamps and note anomalies.
3. **Service Enumeration**
   - Execute `nmap -sC -sV -Pn -oA scans/full <target_host>`.
   - Queue targeted scripts (e.g., `nmap --script vuln`) for exposed services.
4. **Web Footprinting**
   - Use `whatweb`, `nikto`, and directory brute forcing (`ffuf`, `gobuster`).
   - Mirror site structure (`wget --mirror`) for offline review.
5. **Credential and Leak Hunting**
   - Search paste sites, GitHub, and company domains for exposed secrets.
   - Run `theHarvester -d <domain> -l 200 -b all` for enumerating emails and hosts.
6. **Reporting Checkpoint**
   - Update recon log with key findings, screenshots, and next-step hypotheses.

## Exploitation Execution

1. **Exploit Validation**
   - Confirm vulnerability by reproducing the proof-of-concept safely in a test harness or controlled VM.
   - Record affected versions and CVE references.
2. **Payload Preparation**
   - Customize payloads (`msfvenom`, `nccreate`) with proper callbacks and AV evasion.
   - Stage listeners (`nc`, `socat`) and ensure firewall exceptions are in place.
3. **Exploit Deployment**
   - Execute exploit with verbose logging, redirecting output to dated files (`exploit-<host>-<timestamp>.log`).
   - Monitor listener for incoming shells; document timestamps and shell context (user, host).
4. **Stability Hardening**
   - Establish redundancy (e.g., second shell, scheduled task beacon) to mitigate session loss.
   - Gather volatile artifacts (process lists, network connections) immediately after access.
5. **Evidence Preservation**
   - Hash payloads and exploit binaries before and after transfer.
   - Capture screen recordings or terminal logs for critical steps.
6. **Communication Update**
   - Notify stakeholders per escalation plan; include impact summary and risk assessment.

## Post-Exploitation & Privilege Escalation

1. **Local Enumeration**
   - Run automated scripts (`linpeas`, `winpeas`, `Seatbelt`) and review manually.
   - Check kernel versions, installed software, and misconfigurations.
2. **Credential Harvesting**
   - Dump password stores (e.g., `mimikatz`, `lsassy`) and database connection strings.
   - Search file system for `config`, `backup`, or `password` artifacts.
3. **Privilege Escalation Paths**
   - Evaluate SUID/SGID binaries, service misconfigurations, and scheduled tasks.
   - Attempt token impersonation, UAC bypass, or kernel exploits as appropriate.
4. **Lateral Movement Preparation**
   - Map network shares and reachable hosts (`net view`, `crackmapexec`).
   - Stage credentials into password manager with tagging for rotation recommendations.
5. **Persistence & Covering Tracks**
   - Set limited-scope persistence (registry run keys, cron jobs) only if in scope.
   - Catalog all modifications for rollback and cleanup instructions.
6. **Documentation & Cleanup**
   - Update centralized notes with commands, screenshots, and loot paths.
   - Remove artifacts, restore configs, and verify services are operational.

## Incident Response Run Book (Blue Team)

1. **Alert Intake**
   - Triage SIEM alerts; validate severity and affected assets.
   - Correlate with recent change tickets or ongoing assessments.
2. **Containment**
   - Isolate affected endpoints via EDR network containment.
   - Block malicious indicators on firewalls and proxy lists.
3. **Investigation**
   - Acquire volatile data (`memdump`, `live response`) and collect relevant logs.
   - Analyze for root cause, lateral movement, and data exfiltration evidence.
4. **Eradication**
   - Remove malicious binaries, disable persistence mechanisms, and patch vulnerabilities.
   - Revoke compromised credentials and enforce password resets.
5. **Recovery**
   - Restore systems from clean backups; monitor for reinfection indicators.
   - Communicate restoration status to stakeholders.
6. **Post-Incident Review**
   - Conduct lessons learned session; update detection rules and run books.
   - File final incident report with timeline, impact, and remediation tasks.

---

**Usage Tips:** Convert each section into checklist items within your task tracker. Include timestamps, tooling versions, and evidence paths whenever executing steps to maintain audit readiness.
