---
title: "Digital Forensics: Investigating a Corporate Data Leak on a Windows 7 Disk Image"
date: 2026-10-14 12:00:00 +0530
categories: [Digital Forensics, Case Study]
tags: [forensics, autopsy, regripper, windows-registry, userassist, ntfs, dfir]
description: "A walkthrough of a university forensics case: verifying evidence, mounting it read-only, and reading the Windows registry, browser history and Outlook mailbox to reconstruct an insider data leak."
---

This is a write-up of a practical forensics assignment I did at university. The case is simulated: a division manager at a technology company is suspected of leaking confidential product information to a rival. His devices were seized and imaged, and my job was to work out what he did from the evidence.

I'm still a student, so I've written this the way I worked through it: what I looked at, which tool I used, and why that step comes where it does.

**Evidence:** a Windows 7 disk image (`evidence_pc.dd`), plus USB and CD-R images.
**Tools:** md5sum, Autopsy / The Sleuth Kit, RegRipper, BrowsingHistoryView, OST PST Viewer, on Kali Linux.

> This post covers the disk-image analysis (acquisition, system profile, program use, browser activity, email and USB devices). I haven't included the deleted-file recovery, cloud-sync and CD-burning, or memory-analysis parts here.
{: .prompt-info }

---

## 1. Verify the evidence first

Before analysing anything, I needed to know my working copy matched the seized evidence. I tried hashing in Autopsy, but my laptop overheated and it didn't finish in time, so I used the command line instead:

```bash
md5sum evidence_pc.dd
```

![md5sum of the disk image](/assets/img/posts/forensics-data-leak/image1.png)

This has to come first. If the hash of a working copy doesn't match the original, nothing found afterwards can be trusted, and it may not hold up if the case went further. If the values didn't match, I'd stop, re-copy from the original, and document what happened.

## 2. Map the disk

The image contains two NTFS partitions:

- **C:** starts at sector 2048 and ends at 206847. This is the System Reserved partition.
- **D:** starts at sector 206848 and ends at 41940991. Windows is installed here.

![Partition layout in Autopsy](/assets/img/posts/forensics-data-leak/image2.png)

![Partition table from mmls](/assets/img/posts/forensics-data-leak/image3.png)

![File system information, first partition](/assets/img/posts/forensics-data-leak/image4.png)

![File system information, second partition](/assets/img/posts/forensics-data-leak/image5.png)

## 3. Mount it read-only

To browse the evidence without any chance of changing it, I mounted the OS partition on Kali with the `ro` flag and a loop device. The offset is the partition's start sector (206848) multiplied by 512 bytes:

```bash
sudo mkdir /mnt/evidence_pc
sudo mount -t ntfs -o ro,loop,offset=105906176 evidence_pc.dd /mnt/evidence_pc
```

![Read-only mount command](/assets/img/posts/forensics-data-leak/image6.png)

To confirm the safeguard worked, I tried to create a file inside the mount. It failed with "Read-only file system".

![Write attempt fails on the read-only mount](/assets/img/posts/forensics-data-leak/image7.png)

To prove nothing changed afterwards, I can hash the image again and compare it with the first value.

## 4. Check the boot sector

Looking at the raw bytes at the start of the OS partition, I found the boot sector and the two-byte end marker `55 AA`. The boot code also contains the standard error messages ("BOOTMGR is missing", "Press Ctrl+Alt+Del to restart") that the machine shows if booting fails.

![Start of the OS partition in a hex view](/assets/img/posts/forensics-data-leak/image8.png)

![The 55 AA end marker and boot error text](/assets/img/posts/forensics-data-leak/image9.png)

## 5. Profile the system from the registry

I exported the registry hives from Autopsy (Export Contents) and parsed them with RegRipper, which has plugins for specific keys:

```bash
regripper -r SOFTWARE.raw -p winver
```

![Exporting a hive from Autopsy](/assets/img/posts/forensics-data-leak/image10.png)

**Windows edition, install date, owner** (SOFTWARE hive, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`):

| Item | Value |
|---|---|
| Edition | Windows 7 Ultimate, Service Pack 1 |
| Installed | 2015-03-22 14:34:26Z |
| Registered owner | informant |

![winver plugin output](/assets/img/posts/forensics-data-leak/image11.png)

**Timezone** (SYSTEM hive, `ControlSet001\Control\TimeZoneInformation`): Eastern Standard Time. This matters because Windows stores most timestamps in UTC. Without the correct offset you can't line them up with real-world events, and a 4 to 5 hour error can completely change the order of what happened.

![timezone plugin output](/assets/img/posts/forensics-data-leak/image12.png)

**Hostname** (SYSTEM hive, `ControlSet001\Control\ComputerName\ComputerName`): `INFORMANT-PC`, found with the `compname` plugin.

![compname plugin output](/assets/img/posts/forensics-data-leak/image13.png)

## 6. User accounts

The SAM hive (`samparse` plugin) showed four accounts:

![samparse output, first account](/assets/img/posts/forensics-data-leak/image14.png)

![admin11 account](/assets/img/posts/forensics-data-leak/image15.png)

![informant account](/assets/img/posts/forensics-data-leak/image16.png)

![temporary account](/assets/img/posts/forensics-data-leak/image17.png)

![ITechTeam account](/assets/img/posts/forensics-data-leak/image18.png)

I then matched the SIDs against the SOFTWARE hive's ProfileList to confirm which accounts have profile folders.

![ProfileList mapping SIDs to profile folders](/assets/img/posts/forensics-data-leak/image19.png)

| Username | Logins | Last login (UTC) | Profile |
|---|---|---|---|
| informant | 10 | 2015-03-25 14:45:59 | C:\Users\informant |
| admin11 | 2 | 2015-03-22 15:57:02 | C:\Users\admin11 |
| temporary | 1 | 2015-03-22 15:55:57 | C:\Users\temporary |
| ITechTeam | 0 | Never | none |

The `informant` profile is the one under investigation. It has the most logins, and its name matches both the hostname and the registered owner.

**Last sign-in and shutdown:** `informant` was the last to log in (2015-03-25 14:45:59Z). The last orderly shutdown was 2015-03-25 15:31:05Z (SYSTEM hive, `Control\Windows`, `ShutdownTime`).

![shutdown plugin output](/assets/img/posts/forensics-data-leak/image20.png)

**Network:** the `nic2` plugin showed an IP of 10.11.11.129 with a 255.255.255.0 mask. `EnableDHCP` is set to 1 and a DHCP server address is recorded, so the address was assigned automatically rather than set by hand.

![nic2 plugin output](/assets/img/posts/forensics-data-leak/image21.png)

## 7. What software was added?

The `uninstall` plugin reads the installed-programs list from the SOFTWARE hive. Default Windows components date to 2009-07-14. Programs added after setup carry dates in March 2015:

- Google Drive (a way to move data off the machine)
- Google Chrome
- Eraser 6.2.0.2962 (a secure file-wiping tool), installed 2015-03-25 14:57:31Z

![Default components dated 2009](/assets/img/posts/forensics-data-leak/image22.png)

![Programs added in March 2015, including Google Drive](/assets/img/posts/forensics-data-leak/image23.png)

![Eraser install time](/assets/img/posts/forensics-data-leak/image24.png)

## 8. Evidence of program execution: UserAssist

UserAssist records programs a user launches through Explorer, with a run count and last-run time. It lives in the user's own `NTUSER.DAT`, so I parsed the `informant` hive with the `userassist` plugin.

| Executable | Runs | Last run (UTC) | Note |
|---|---|---|---|
| Eraser.exe | 1 | 2015-03-25 15:12:28 | Anti-forensics (file wiping) |
| CCleaner64.exe | 1 | 2015-03-25 15:15:50 | Anti-forensics (cleaning) |
| googledrivesync.exe | 1 | 2015-03-25 15:21:30 | Possible exfiltration (cloud sync) |
| OUTLOOK.EXE | 5 | 2015-03-25 14:41:03 | Email, possible data movement |
| WINWORD.EXE | 4 | 2015-03-25 15:24:48 | Normal document use |

![UserAssist output](/assets/img/posts/forensics-data-leak/image25.png)

The order stands out. Eraser and CCleaner ran first, then the Google Drive sync client about ten minutes before the final shutdown. That pattern fits cleaning up and then syncing, though UserAssist alone doesn't show which files were involved.

**Why UserAssist is useful:** Windows keeps it to personalise the Start menu. The record sits in the registry, separate from the program files, so it survives even if the program is later deleted. It can still show the program existed, that this user ran it, when, and how many times.

## 9. Browser activity

UserAssist also showed Internet Explorer (through the Explorer taskbar link) and Chrome in use.

![Explorer run count](/assets/img/posts/forensics-data-leak/image26.png)

![Chrome run count](/assets/img/posts/forensics-data-leak/image27.png)

| Browser | Artifact | Path |
|---|---|---|
| Chrome | `History` (SQLite) | C:\Users\informant\AppData\Local\Google\Chrome\User Data\Default\ |
| Internet Explorer | `WebCacheV01.dat` (ESE) | C:\Users\informant\AppData\Local\Microsoft\Windows\WebCache\ |

I exported both and opened them in BrowsingHistoryView. The Chrome history showed this research on 2015-03-23, as displayed by the tool:

- 11:35 PM: an article on data breaches ("Top 5 sources leaking personal data")
- 11:36 PM: "Intellectual property"
- 11:45 PM: "Digital forensics"
- 11:47 PM: "Anti-forensic techniques"
- 11:49 PM: "List of data recovery software"

![Chrome history in BrowsingHistoryView](/assets/img/posts/forensics-data-leak/image28.png)

The Internet Explorer record shows browsing of local and network folders, including ones named "secret".

![Internet Explorer history](/assets/img/posts/forensics-data-leak/image29.png)

**File-search box:** the `WordWheelQuery` key in `NTUSER.DAT` stores what a user types into the Explorer search box. The `wordwheelquery` plugin returned one search term, `secret` (key last write 2015-03-23 18:40:17Z).

![wordwheelquery plugin output](/assets/img/posts/forensics-data-leak/image30.png)

## 10. Email

The suspect used Microsoft Outlook. The mailbox is an offline `.ost` file in his profile (`...\AppData\Local\Microsoft\Outlook\`), for the account `iaman.informant@nist.gov`. I exported it from Autopsy, renamed it from `.ost.raw` to `.ost`, and opened it in OST PST Viewer, which reads it without needing a mail server.

![Mailbox opened in OST PST Viewer](/assets/img/posts/forensics-data-leak/image31.png)

The messages between the suspect (iaman) and the outside contact (spy), with times as shown in the viewer and not converted to UTC:

| Time | From | Subject | What it shows |
|---|---|---|---|
| Mar 23, 4:39 PM | iaman | It's me | Sends Google Drive links ("Use links below") |
| Mar 23, 10:56 PM | spy | Hello, Iaman | Contact acknowledges |
| Mar 24, 2:11 AM | spy | RE: It's me | "I got it." Confirms receipt |
| Mar 24 | spy | Good job, buddy | Encouragement |
| Mar 24, to 6:55 PM | spy | Important request / Last request | Asks for the remaining data |
| Mar 24, 7:05 PM | iaman | RE: Last request | Replies about ten minutes later |
| Mar 25, 1:04 AM | iaman | RE: Watch out! | Signals concern about being detected |
| Mar 25, 2:35 AM | iaman | Done | Says the job is finished |

Four of these messages were in the **Deleted Items** folder, including "Done". The data was shared as Google Drive links in the message bodies rather than as attachments.

Together this points to a planned leak through personal cloud storage, with an attempt to hide it by deleting messages.

## 11. USB devices

The `usbstor` plugin on the SYSTEM hive (`Enum\USBStor`) listed two SanDisk Cruzer Fit USB devices:

| Device | Serial number | First connected (UTC) |
|---|---|---|
| SanDisk Cruzer Fit | 4C530012450531101593 | 2015-03-24 13:38:00 |
| SanDisk Cruzer Fit | 4C530012550531106501 | 2015-03-24 13:58:33 |

![usbstor plugin output](/assets/img/posts/forensics-data-leak/image32.png)

## 12. Thumbnail cache

Windows keeps small preview images of files a user has viewed, in `thumbcache_*.db` files under `C:\Users\informant\AppData\Local\Microsoft\Windows\Explorer\`. They survive after the original files are deleted because deleting a file only changes the filesystem records. Windows doesn't go back and clean the separate thumbnail database, so previews of confidential files can remain.

---

## What the evidence shows

- The suspect researched data leaks and anti-forensics.
- He searched his own files for "secret".
- He emailed an outside contact about the data and deleted key messages.
- He connected two USB drives.
- On the last day he ran file-wiping and cleaning tools, then a cloud sync client, shortly before shutting down.

## What I learned

- Hash first, and work only on read-only copies.
- The registry holds a lot of evidence, and each hive answers different questions: SOFTWARE for the OS, SYSTEM for hostname, timezone, USB devices and network, SAM for accounts, NTUSER.DAT for user activity.
- Timezones matter before you trust any timeline.
- Evidence of use (UserAssist) is different from evidence of installation.
- A single artifact proves little. Registry, browser history and email together tell the story.
- This was a lab case. Real investigations add documentation, chain of custody and legal process that I only studied in theory.
