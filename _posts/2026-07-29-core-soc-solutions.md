---
title: "Core SOC Solutions: How EDR, SIEM, and SOAR Work Together"
date: 2026-08-06 10:00:00 +0530
categories: [SOC Level 1, TryHackMe]
tags: [soc, edr, siem, soar, splunk, elk, tryhackme]
---
 
## Why this module matters 

Before this module, I knew EDR, SIEM, and SOAR as buzzwords from job postings. After going
through it hands-on, I can explain what each one actually does, where it sits in a SOC's
workflow, and why an analyst needs all three working together rather than any one alone.

## 1. EDR (Endpoint Detection and Response)

### What is EDR and why it exists 
 
Endpoint Detection and Response (EDR) is a security tool used to protect all of an organization's endpoint devices laptops, servers, workstations regardless of whether those devices are inside the corporate network or remote. It goes well beyond what traditional antivirus offers.

Traditional antivirus mainly scans files on a single device, looking for known malware signatures, and stops there it has no visibility beyond that one machine and no way for an analyst to act on what it finds. EDR is built for a different job: it continuously collects detailed activity data from every endpoint even ones outside the traditional network perimeter and feeds it into a central dashboard where a SOC analyst can actually investigate what's happening. Crucially, EDR doesn't just detect; it lets the analyst respond remotely isolating a device, killing a process, or containing a threat before it spreads, which a normal antivirus simply can't do.

### How EDR works / how it detect threats

### How EDR collects data

EDR tools use a very lightweight software agent installed on all end devices. This agent captures and logs all kinds of activity — this data is called telemetry. The collected data includes:
    - Process activity: every process that starts, what spawned it (parent-child relationship), and the command-line arguments used
    - File activity: files created, modified, or deleted, especially in sensitive locations
    - Registry changes: (Windows) — especially persistence-related keys (e.g. programs set to auto-run at startup)
    - Network connections: what process is making outbound connections, to which IP/domain, on what port
    - Memory/API calls: some EDRs hook into system calls to catch code injection or in-memory-only malware that never touches disk

All of this telemetry is sent to the vendor's cloud service, which is where the EDR software is hosted. Analysts log in securely to the dashboard to triage the incoming logs and alerts.

### How EDR detects threats

The collected telemetry is used to detect threats using a few core techniques:

IOC & Signature Matching — computes file hashes as files are created or modified, and checks these hashes, along with connection IPs, domains, and URLs, against known threat intelligence blocklists. This is the same basic idea antivirus uses.
Behavioral & Heuristic Detection — instead of looking at file attributes alone, this evaluates the chain of execution — tracking which process spawned which. A classic example is Microsoft Word spawning PowerShell, which then reaches out to an external IP. Individually, winword.exe and powershell.exe are both legitimate programs, so antivirus wouldn't flag either — but EDR tracks the parent-child relationship between them, and an office app spawning a shell that then makes a network connection is a known malicious pattern, so EDR flags the chain even though no single step looks malicious alone.
Machine Learning-based Detection — EDR also uses ML models to flag unusual activity that doesn't match a known signature or behavior rule, mainly to catch zero-day threats — malware nobody has seen before, so no signature exists for it yet.

(Note: I found sources listing anywhere from 3 to 6 "standard" detection techniques — some enterprise EDR platforms go much deeper, with things like cross-host correlation and memory-level exploit detection. I've kept this to the three I can explain and defend properly at my current level, rather than listing everything I found.)

### How EDR responds to threats

After detecting a threat, EDR provides both automatic and manual ways to respond.

The automatic response is handled by the agent installed on the end device itself. These agents contain privileged system components, a lightweight trained ML model to catch zero-day threats locally, and a small local database with cached malicious hash lists and response playbooks — this is how the agent can triage some threats automatically on its own.

1. Isolate Host During malicious activity on an endpoint, the endpoint can be isolated from the network through EDR. This is very effective for containing an attack — most attacks start on a single endpoint and try to move laterally to compromise the rest of the network, so isolating the infected endpoint in time can stop that from happening.

2. Process Termination & Process Tree Not every malicious activity needs full host isolation, and isolating some hosts can actually cause more business damage than the threat itself if they're running critical operations. In those cases, just terminating the malicious process is enough to contain it. The agent bypasses the standard Windows/Linux task manager and instead uses its kernel callback module to issue an un-bypassable process-termination call directly to the OS kernel, cleanly tearing down the process and its child processes.

3. Forensic Artifact Gathering In some cases analysts need more information for deeper analysis or legal reasons, and collect artifacts like:
    - Memory dumps
    - Event logs
    - Specific folder contents
    - Registry hives

 This can be done through the EDR console by sending commands to the agent, automatically via a SOAR playbook when a rule triggers, or by  the analyst opening a remote shell to the device directly to collect custom files themselves.

4. Cleanup and Quarantine Once a malicious file is found on an endpoint, it can be quarantined — put somewhere it can't cause harm — and later either recovered by the analyst for further inspection or wiped from the system entirely.

 
## 2. SIEM (Security Information and Event Management)

[your explanation here] cool checking

## 3. Splunk: The Basics

[your explanation + screenshot]

## 4. Elastic Stack (ELK): The Basics

[your explanation + screenshot]

## 5. SOAR

[your explanation here]

## Putting it together: the alert pipeline

[diagram here]

## What confused me initially / what clicked

[your honest reflection]
