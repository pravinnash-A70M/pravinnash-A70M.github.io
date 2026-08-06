---
title: "Core SOC Solutions: How EDR, SIEM, and SOAR Work Together"
date: 2026-07-29 10:00:00 +0530
categories: [SOC Level 1, TryHackMe]
tags: [soc, edr, siem, soar, splunk, elk, tryhackme]
---

## Why this module matters

Before this module, I knew EDR, SIEM, and SOAR as buzzwords from job postings. After going
through it hands-on, I can explain what each one actually does, where it sits in a SOC's
workflow, and why an analyst needs all three working together rather than any one alone.

## 1. EDR (Endpoint Detection and Response)

What is EDR and why it exists
 
Endpoint Detection and Response (EDR) is a security tool used to protect all of an organization's endpoint devices — laptops, servers, workstations — regardless of whether those devices are inside the corporate network or remote. It goes well beyond what traditional antivirus offers.

Traditional antivirus mainly scans files on a single device, looking for known malware signatures, and stops there — it has no visibility beyond that one machine and no way for an analyst to act on what it finds. EDR is built for a different job: it continuously collects detailed activity data from every endpoint — even ones outside the traditional network perimeter — and feeds it into a central dashboard where a SOC analyst can actually investigate what's happening. Crucially, EDR doesn't just detect; it lets the analyst respond — remotely isolating a device, killing a process, or containing a threat before it spreads, which a normal antivirus simply can't do.

## 2. SIEM (Security Information and Event Management)

[your explanation here]

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
