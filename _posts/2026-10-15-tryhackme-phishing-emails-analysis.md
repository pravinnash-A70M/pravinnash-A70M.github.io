---
title: "TryHackMe Phishing Module: How Email Works, How Fakes Get Caught, and How I Analysed One"
date: 2026-10-15 17:00:00 +0530
categories: [TryHackMe, Phishing]
tags: [tryhackme, phishing, email-analysis, smtp, spf, dkim, dmarc, phishtool, virustotal, urlscan, soc]
description: "My full notes from the TryHackMe phishing module, in plain English: how email travels, what SPF, DKIM and DMARC actually do, the tools analysts use, and a walkthrough of a fake Netflix email."
---

I finished the phishing analysis module on TryHackMe, and I wanted to write it up the way I'd explain it to a friend. Phishing is one of the first things a SOC analyst deals with every day, so I want to really understand it, not just memorise terms.

The order here is: how email works, then what's inside an email, then the three checks that catch fakes (SPF, DKIM, DMARC), then the tools, then a real example I analysed. Each section ends with a one-line summary so it's quick to revise later.

---

## 1. How email actually travels

Think of email like the postal system. Three protocols, three jobs:

| Protocol | What it does | Postal version | Ports |
|---|---|---|---|
| **SMTP** | Sends and passes mail along | The postman who carries the letter | 25, 587, 465 |
| **IMAP** | Lets you read mail that stays on the server | A window into a mailbox that stays at the post office | 143, 993 |
| **POP3** | Downloads mail to one device | Taking the letters home | 110, 995 |

**IMAP vs POP3**

- With **IMAP**, the mail stays on the server and your devices just show a synced copy. If I read or delete a mail on my phone, my laptop shows the same thing, because they're all looking at the same mailbox.
- With **POP3**, the mail is downloaded to one device. By default the server copy is then deleted, so my other devices never see it. Most email apps let you change that and leave a copy on the server, but the classic behaviour is download and delete.

**SMTP** is only about *sending*. It moves a message from my email app to my mail server, and then from one mail server to another. It can't be used to read my mailbox.

### The journey of one email

1. **I press send.** My email app hands the message to my mail server using SMTP.
2. **My server asks DNS** where the recipient's domain receives mail (this is the MX record).
3. **DNS answers** with the address of the recipient's mail server.
4. **The message crosses the internet** to that server, again over SMTP.
5. **The recipient opens their email app**, which connects to their mail server.
6. **The mail is fetched:** downloaded with POP3 or synced with IMAP.

> **To remember:** SMTP sends, IMAP syncs, POP3 downloads. DNS is the address book that tells the mail server where to deliver.
{: .prompt-tip }

---

## 2. What's inside an email

Every email has two parts: the **header** and the **body**.

### The header: the envelope and the postmarks

Your email app hides most of the header. You can see it with "View original" or "Show raw message". It's a list of `Key: Value` lines. The important ones:

- **From, To, Cc, Date, Subject:** the obvious ones.
- **Received:** every mail server that handles the message stamps its own `Received` line on top, like a postmark. The newest is at the top, so to follow the real journey you **read them from the bottom up**.
- **Message-ID:** a unique ID created by the sending server.
- **Return-Path:** where bounce messages go. It's the "return address on the envelope", and it can be different from the `From` line you see. That difference is a clue that comes up a lot in phishing.
- **Authentication results:** the receiving server's verdict on SPF, DKIM and DMARC (explained next).

### The body: the letter inside

The body is the message itself. It's built with **MIME**, which lets one email carry several things at once:

- a **plain-text** version (a fallback),
- an **HTML** version (colours, buttons, images, links),
- **attachments**, which are converted into text (usually Base64) so they can travel inside the email, then turned back into files by your email app.

For an analyst: the HTML part is where disguised links hide, and the attachments are where malware hides.

> **To remember:** the header tells you *where it really came from and how it travelled*. The body tells you *what it wants you to do*.
{: .prompt-tip }

---

## 3. The three guards: SPF, DKIM and DMARC

Here's the problem: SMTP was designed in a more trusting time, and anyone can *write* any "From" address on an email. There's nothing in basic email that stops me typing `ceo@yourcompany.com`. SPF, DKIM and DMARC were added later to fix that. Each one checks something different.

### SPF: the guest list

**What it checks:** is the server that sent this email *allowed* to send for that domain?

A domain owner publishes a list of approved sending servers in a DNS record (a TXT record). When an email arrives, the receiving server looks up the domain's list and checks whether the sending server's IP is on it.

> **Analogy:** a bouncer with a guest list. If you're not on the list, you don't get in, however nice your outfit is.
{: .prompt-tip }

Here's what an SPF record looks like:

```
v=spf1 ip4:127.0.0.1 include:_spf.google.com -all
```

- `v=spf1` says "this is an SPF record".
- `ip4:127.0.0.1` says "this IP address may send for us".
- `include:_spf.google.com` says "also trust whatever servers Google lists" (handy when a company uses Gmail or another service to send mail).
- `-all` says "anyone not listed is **not** allowed". A softer version, `~all`, means "probably not allowed, but don't be strict about it".

What the receiving server does with the result:

| SPF result | What it means | Usual action |
|---|---|---|
| Pass, Neutral, None | Allowed, or no strong opinion | Accept |
| SoftFail, PermError | Not on the list (soft), or the record is broken | Accept but flag as suspicious |
| Fail, TempError | Not allowed, or a temporary problem | Reject |

**The weakness:** SPF checks the sending server against the *Return-Path* domain, not the `From` address you can see. And it breaks when mail is forwarded, because the forwarding server isn't on the original list. That's one reason we need DKIM.

### DKIM: the wax seal

**What it checks:** was this message changed on the way, and did this domain really sign it?

The sending server signs the email with a **private key** that only it has. The receiving server grabs the matching **public key** from the domain's DNS record and uses it to verify the signature. If someone changed the message after it was signed, the check fails.

> **Analogy:** a wax seal on a letter. If the seal is intact and carries the right stamp, the letter hasn't been opened or changed. If it's broken, something's wrong.
{: .prompt-tip }

A DKIM record looks like this:

```
v=DKIM1; k=rsa; p=<public key goes here>
```

- `v=DKIM1` is the version.
- `k=rsa` is the type of key.
- `p=` is the public key itself.

DKIM survives forwarding, because the signature travels with the message, which is why it's more reliable than SPF on its own. A `permerror` result in a header means DKIM failed permanently. Common reasons are a bad signature, a missing DNS record, a server that modified the message, or a setup mistake.

### DMARC: the rule that ties them together

**What it checks:** do SPF and DKIM actually match the `From` address the user sees, and what should happen if they don't?

This is called **alignment**. It's the part that matters most. DMARC asks: "Okay, SPF passed, but did it pass for the *same domain* shown in the From line?" and the same for DKIM. If neither lines up, DMARC fails. The domain owner also publishes a policy that tells receivers what to do:

```
v=DMARC1; p=quarantine; rua=mailto:postmaster@website.com
```

- `v=DMARC1` is the version.
- `p=quarantine` is the policy. The three options are `none` (just watch), `quarantine` (send to spam) and `reject` (block it).
- `rua=` is an address where the domain owner wants summary reports, so they can see who's using their domain.

> **Analogy:** the club owner. The bouncer (SPF) checks the guest list, the wax seal (DKIM) proves the invitation is real, and DMARC is the owner saying "the name on the invitation must match the name on the ID, and if it doesn't, here's what to do with that person".
{: .prompt-tip }

### Putting the three together

| | Checks | Weakness on its own |
|---|---|---|
| **SPF** | Is this server allowed to send for the domain? | Breaks when forwarded; checks the Return-Path, not the visible From |
| **DKIM** | Was the message changed, and who signed it? | A scammer can sign with *their own* domain |
| **DMARC** | Do the above match the visible From domain? What to do if not? | Only works if the domain owner publishes a policy |

> **To remember:** SPF = guest list. DKIM = wax seal. DMARC = the owner's rule that the name on the invite must match the ID.
{: .prompt-tip }

---

## 4. Tools I used

| Tool | What it's for |
|---|---|
| **PhishTool** | Opens a raw email and splits it into readable parts: headers, authentication, URLs, attachments, transmission path |
| **dmarcian SPF Surveyor** | Shows a domain's SPF record visually, including the other domains it trusts |
| **dmarcian Domain Checker** | Checks a domain's SPF, DKIM and DMARC records and points out problems. I tried it on `microsoft.com`: everything passed, and its DMARC policy was `p=reject` |
| **Google Admin Toolbox Messageheader** | Paste in a full header and it explains the delivery path and the SPF/DKIM/DMARC results |
| **VirusTotal** | Checks a URL, file hash, IP or domain against many security engines at once, like asking dozens of experts for an opinion |
| **urlscan.io** | Opens a suspicious link in a safe, remote browser and shows you the screenshot, the redirects and the connections, so you never visit it yourself |
| **AbuseIPDB** | Shows whether an IP address has been reported for abuse |
| **ANY.RUN** | A sandbox: runs a suspicious file or link in a safe virtual machine and records what it does |

**One example:** Google's Messageheader tool showed an SPF result of `softfail` with an unknown IP. That means the sending server wasn't on the domain's approved list, but the email was still accepted and flagged. It's a good reminder that "flagged" is not the same as "blocked".

---

## 5. Analysing a real phishing email

In the lab, I was given an email file (`.eml`) that claims to be from Netflix and says "Your account is on hold, please update your payment details". My job was to decide whether it's real.

I looked at the raw file (left) and the rendered email (right), then loaded it into PhishTool.

![The raw email in a text editor next to the rendered message in Thunderbird](/assets/img/posts/phishing-analysis/raw-headers.png){: w="700" }

![PhishTool details tab for the email](/assets/img/posts/phishing-analysis/phishtool-details.png){: w="700" }

### What gave it away

**1. The sender doesn't match the brand.**
- The display name reads "NetfIix". Look closely: the "l" in Netflix is a capital **I**. It's a lookalike character, designed to fool a quick glance.
- The real `From` address is a long random string at **gogolecloud.com**, a domain that has nothing to do with Netflix.

**2. The `Return-Path` is yet another domain.** Bounces would go to `postmaster@etekno.xyz`. A real Netflix email wouldn't have a `.xyz` return address.

**3. It was sent through Google's servers, and that's a trap.**
- The originating IP is 209.85.167.226, whose reverse DNS is `mail-oi1-f226.google.com`.
- The `Message-ID` ends in `@mx.google.com`.
- The DKIM signature in the raw headers belongs to `1e100.net`, which is a Google domain, not `netflix.com`.

This is the lesson I want to remember: **an email passing a check doesn't mean it's safe.** A scammer can send through Gmail, and Google will sign it as Google. DKIM only proves "this really passed through Google", not "this really came from Netflix". What matters is whether the checked domain **matches the domain the email claims to be from**. Here, the visible `From` domain, the `Return-Path` domain and the DKIM domain are all different, so DMARC alignment would have nothing to line up with. This is exactly what DMARC is built to catch.

**4. The pressure.** "Your account is on hold" is designed to make you rush, and the red "UPDATE ACCOUNT NOW" button is the whole point of the email.

**5. The link is disguised.** PhishTool's URLs tab shows the button leads to a `t.co` short link, not to netflix.com.

![PhishTool URLs tab showing the t.co link](/assets/img/posts/phishing-analysis/phishtool-urls.png){: w="620" }

A shortened link hides where it really goes. An analyst doesn't click it. You'd check it in **urlscan.io** or **VirusTotal**, which show the final destination without you visiting it.

<!-- TODO: add the SPF / DKIM / DMARC results from PhishTool's Authentication tab here -->

### Verdict

**Phishing.** The sender's identity doesn't match Netflix, the return path is an unrelated domain, the link is disguised, and the message pushes the reader to hand over payment details.

### What I'd do next as an analyst

- Block the sender domain and the return-path domain.
- Search the mail system for the same email sent to other users, and remove it.
- Report the link for blocking after checking where it goes.
- Tell the affected user not to click, and to change their password if they did.

---

## 6. Sandboxing a suspicious attachment

Another tool was **ANY.RUN**. It opens a suspicious file inside a safe, throwaway virtual machine and records everything it does, so you don't have to risk opening it yourself.

![ANY.RUN analysis of a PDF sample](/assets/img/posts/phishing-analysis/anyrun-sandbox.png){: w="700" }

The sample here was a PDF named `Payment-updateid.pdf`. ANY.RUN flagged it as **suspicious activity** and showed:

- the **process tree** (what launched what),
- the **network connections** it made,
- a **browser window** it opened, showing a fake Netflix help page,
- **MITRE ATT&CK** tags for behaviours such as querying the registry.

A PDF that opens a browser and makes network connections is a red flag. A document that just displays text shouldn't need to.

---

## 7. How companies stop phishing before it reaches us

Analysts are the second line. Email systems also have defences in front:

- **Email filtering:** blocks or quarantines mail based on the reputation of the sender's IP and domain. Like a doorman who knows the troublemakers.
- **Secure email gateways (SEGs):** scan every message for spoofing, impersonation and phishing tricks that simple filters miss.
- **Link rewriting:** replaces links in emails with safe redirected ones. When you click, the link is checked first, giving the system time to scan it.
- **Sandboxing:** opens suspicious attachments and links in an isolated environment to see what they do, the same idea as ANY.RUN, but automatic.

---

## Quick revision

- **SMTP** sends, **IMAP** syncs, **POP3** downloads.
- Read `Received` lines **bottom to top**.
- **SPF** = guest list. **DKIM** = wax seal. **DMARC** = name on the invite must match the ID, plus what to do if it doesn't.
- Compare the **display name**, the **From**, the **Return-Path** and the **DKIM domain**. If they disagree, be suspicious.
- A pass doesn't make an email safe. Check that the checked domain matches the claimed sender.
- Never click first. Use **VirusTotal**, **urlscan.io**, **AbuseIPDB** and **ANY.RUN** to check.
