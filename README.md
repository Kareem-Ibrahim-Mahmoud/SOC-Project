# 🛡️ Incident Response Handbook: Phishing → Ransomware Simulation (MailHog + GoPhish)

[cite_start]**Project:** Phishing → Ransomware Simulation (MailHog + GoPhish) [cite: 2]

**Authors:**
* [cite_start]Abdulrahman Al-Sayed Abdulaziz [cite: 4]
* [cite_start]Khaled Mohamed Mohamed [cite: 4]
* [cite_start]Kareem Ibrahim Mahmoud Omar [cite: 5]
* [cite_start]Abdul Rahman Ali Abu Al-Maati [cite: 6]
* [cite_start]Mohammed Ahmed Issa [cite: 7]
* [cite_start]Mazen Mohamed Fathi [cite: 8]

---

## [cite_start]📝 Table of Contents [cite: 9]

1.  [cite_start][Project Overview](#1-project-overview) [cite: 10]
2.  [cite_start][Ethical & Legal Disclaimer](#2-ethical-legal-disclaimer) [cite: 11]
3.  [cite_start][Environment & System Requirements](#3-environment--system-requirements) [cite: 12]
4.  [cite_start][Installation & Configuration](#4-installation--configuration) [cite: 13]
5.  [cite_start][Phishing Campaign Setup (GoPhish)](#5-phishing-campaign-setup-gophish) [cite: 17]
6.  [cite_start][Payload Design (ticket.exe)](#6-payload-design-ticketexe-safe-handling-and-reporting-note) [cite: 21]
7.  [cite_start][Running the Simulation (step-by-step)](#7-running-the-simulation-step-by-step) [cite: 27]
8.  [cite_start][Observing Results & Metrics](#8-observing-results--metrics) [cite: 28]
9.  [cite_start][Disk & Memory Image Acquisition](#9-disk--memory-image-acquisition) [cite: 29]
10. [cite_start][Forensic Analysis & Indicators of Compromise (IOCs)](#10-forensic-analysis--indicators-of-compromise-iocs) [cite: 30]
11. [cite_start][MITRE ATT&CK Mapping](#11-mitre-attck-mapping) [cite: 31]
12. [cite_start][Cyber Kill Chain](#12-cyber-kill-chain) [cite: 32]
13. [cite_start][Incident Response and Post-Incident Activities](#13-incident-response-and-post-incident-activities) [cite: 33]
14. [cite_start][Recommendations & Mitigations](#14-recommendations--mitigations) [cite: 34]
15. [cite_start][Project Summary & Conclusion](#15-project-summary--conclusion) [cite: 35]

---

## [cite_start]1. Project Overview [cite: 37]

[cite_start]**Objective:** This project demonstrates a controlled phishing campaign that delivers a benign, mock ransomware payload[cite: 38]. The educational goals are:
* [cite_start]Show how phishing can deliver malicious payloads[cite: 39].
* [cite_start]Demonstrate how an unsuspecting user can be tricked into executing a payload[cite: 39].
* [cite_start]Gather campaign metrics (open, click rates) using GoPhish[cite: 40].
* [cite_start]Teach detection, mitigation, and incident response best practices[cite: 41].

[cite_start]**Scope:** Local/lab environment using MailHog as a local SMTP capture server and GoPhish as the phishing framework[cite: 42]. [cite_start]The `ticket.exe` payload is a safe, non-destructive simulation that shows ransom-note behavior without encrypting real user data[cite: 43].

## [cite_start]2. Ethical & Legal Disclaimer [cite: 11]

*(The full text for this section was not provided in the source PDF output.)*

## [cite_start]3. Environment & System Requirements [cite: 44]

### [cite_start]Minimum recommended requirements: [cite: 45]
* **CPU:** 2 cores
* **RAM:** 4 GB (2 GB may suffice for very small tests)
* **Disk:** 10 GB free
* **OS:** Windows $10/11$, Ubuntu 20.04+, or macOS (latest)
* **Network:** Localhost / isolated lab network

### [cite_start]Software: [cite: 46]
* GoPhish (latest release)
* MailHog (latest release)
* Python 3.8+ and PyInstaller (for building the payload)
* Browser for admin UIs (Chrome, Firefox)

### [cite_start]Ports used (default): [cite: 47]
* **MailHog SMTP:** 1025
* **MailHog HTTP UI:** 8025
* **GoPhish Admin:** 3333 (HTTPS by default)
* **GoPhish Phishing server:** 80 (HTTP) or custom port in `config.json`
* **Local payload hosting (example):** 8000 (Python `http.server`)

## [cite_start]4. Installation & Configuration [cite: 48]

> **Note:** All commands are examples. [cite_start]Adjust paths and permissions for your OS[cite: 49].

### 4.1 MailHog
* [cite_start]**Installation (Linux/macOS):** [cite: 50]
    * [cite_start]**Option 1 (prebuilt binary):** Download the appropriate binary from MailHog releases and place it in `/usr/local/bin`[cite: 50].
    * [cite_start]**Option 2 (Homebrew macOS):** `brew update && brew install mailhog`[cite: 51].
* [cite_start]**Run MailHog:** [cite: 52]
    ```bash
    # [cite_start]start MailHog (default ports 1025 SMTP, 8025 HTTP) [cite: 53]
    [cite_start]mailhog [cite: 53]
    # [cite_start]or if using a binary [cite: 54]
    [cite_start]./MailHog [cite: 55]
    ```
* [cite_start]**Verify:** Open `http://localhost:8025` to view MailHog UI[cite: 57]. [cite_start]MailHog will receive emails sent to SMTP port 1025[cite: 57].
* **Configuration tips:**
    * [cite_start]If port conflicts exist, stop the conflicting service or map MailHog to different ports[cite: 58].
    * [cite_start]Ensure local firewall allows loopback connections for the chosen ports[cite: 59].

### [cite_start]4.2 GoPhish [cite: 60]
* **Installation:**
    * [cite_start]Download the latest GoPhish release from the official repository[cite: 61].
    * [cite_start]Unzip and place the folder in a suitable location (e.g., `~/gophish`)[cite: 62].
* [cite_start]**Run GoPhish:** [cite: 63]
    ```bash
    [cite_start]cd ~/gophish [cite: 64]
    # [cite_start]On Linux/macOS [cite: 65]
    [cite_start]./gophish [cite: 66]
    # [cite_start]On Windows (PowerShell) [cite: 67]
    [cite_start].\gophish.exe [cite: 67]
    ```
* [cite_start]**Default config:** `admin_server.listen_url` $\rightarrow$ `127.0.0.1:3333` [cite: 68] - [cite_start]`phish_server.listen_url` $\rightarrow$ `0.0.0.0:80` [cite: 69]
* [cite_start]**Accessing UI:** Open a browser to `https://127.0.0.1:3333` (Admin panel) and log in with the generated credentials[cite: 70]. [cite_start]**Change password on first login**[cite: 71].
* [cite_start]**Important:** If you cannot bind to port 80 for the phishing server, change `phish_server.listen_url` to `127.0.0.1:8080` and update templates/links accordingly[cite: 72].

### [cite_start]4.3 Python & PyInstaller (payload build) [cite: 73]
* [cite_start]**Install Python:** Ensure Python 3.8+ is installed and `python`/`python3` is on `PATH`[cite: 74].
* [cite_start]**Install PyInstaller:** [cite: 74]
    ```bash
    [cite_start]pip install pyinstaller [cite: 75]
    ```
* [cite_start]**Create a virtualenv (optional but recommended):** [cite: 76]
    ```bash
    [cite_start]python3 -m venv venv [cite: 77]
    [cite_start]source venv/bin/activate # Linux/macOS [cite: 78]
    [cite_start]venv\Scripts\activate # Windows [cite: 79]
    ```

## [cite_start]5. Phishing Campaign Setup (GoPhish) [cite: 80]

### [cite_start]5.1 Create Email Template [cite: 81]

[cite_start]![GoPhish Email Template Setup (Template, Subject, and Body)](images/gophish_email_template.png) [cite: 83, 107-115]

* **Example Subject:** `Congratulations! [cite_start]You've Won an iPhone 17 Pro` [cite: 84]
* [cite_start]**HTML body (example):** [cite: 85]
    ```html
    [cite_start]<!doctype html> [cite: 86]
    [cite_start]<html> [cite: 87]
    [cite_start]<body> [cite: 88]
    [cite_start]<div style="font-family: Arial, sans-serif;"> [cite: 89]
    [cite_start]<img src="[https://example.com/logo.png](https://example.com/logo.png)" alt="Fawryz Logo" [cite: 90]
    style="width: 160px;" [cite_start]/> [cite: 91]
    [cite_start]<h2>Congratulations!</h2> [cite: 92]
    [cite_start]<p>Dear {{.FirstName}},</p> [cite: 93]
    [cite_start]<p>We are excited to inform you that you have been randomly selected to [cite: 94]
    [cite_start]receive a brand new <strong>iPhone 17 Pro</strong> in our customer [cite: 95]
    [cite_start]appreciation giveaway.</p> [cite: 95]
    [cite_start]<p>To claim your prize, please download your raffle ticket and run it [cite: 96]
    [cite_start]on your Windows machine:</p> [cite: 97]
    [cite_start]<p><a href="http://localhost:8000/ticket.exe">Download your [cite: 98]
    [cite_start]ticket</a></p> [cite: 99]
    [cite_start]<p>Best regards, <br/>Fawryz Team</p> [cite: 100]
    [cite_start]</div> [cite: 101]
    [cite_start]</body> [cite: 102]
    [cite_start]</html> [cite: 103]
* **Template notes:**
    * [cite_start]Replace `{{.FirstName}}` with GoPhish template variables where appropriate[cite: 104].
    * [cite_start]Use realistic logos and formatting to increase believability for training, but do not impersonate any real organization without permission[cite: 105].
    * [cite_start]Leave the default GoPhish tracking image enabled if you want open/click tracking[cite: 106].

### [cite_start]5.2 Sending Profile (MailHog) [cite: 116]

[cite_start]![GoPhish Sending Profile (MailHog) setup on port 1025](images/gophish_sending_profile.png) [cite: 119-127]

* [cite_start]**In GoPhish Admin:** Navigate to **Sending Profiles** $\rightarrow$ **New Profile**[cite: 117].
* [cite_start]**SMTP Host:** `localhost:1025` [cite: 118]
* [cite_start]**From Address:** `support@fawryz.com` (MailHog will accept it) [cite: 118]
* [cite_start]**Save** and **Send a Test email** to verify MailHog receives it[cite: 118].

### [cite_start]5.3 Target Groups (CSV import) [cite: 128]
* [cite_start]**CSV example** (headers are optional; GoPhish accepts name/email columns): [cite: 129]
    ```csv
    [cite_start]first_name, last_name, email [cite: 130]
    [cite_start]Marwan, Sherif, Marwan.Sherif@mail.com [cite: 131]
    [cite_start]Alice, Smith, alice.smith@example.test [cite: 132]
    ```
* [cite_start]**In GoPhish:** **Users & Groups** $\rightarrow$ **New Group** $\rightarrow$ **Import CSV** (or add single users manually)[cite: 133].

[cite_start]![GoPhish Target Group Setup (showing imported user Marwan Sherif)](images/gophish_target_group.png) [cite: 135-149]

## [cite_start]6. Payload Design (ticket.exe) Safe handling and reporting note [cite: 150]

* [cite_start]**Note:** For background research we obtained a known WannaCry ransomware sample for analysis only[cite: 151]. [cite_start]The sample was not executed on any production system[cite: 152]. [cite_start]All handling of the sample was done in a controlled, isolated lab environment under supervisor approval[cite: 152].
* [cite_start]The live demonstration shown in this project used a **benign mock payload** (`ticket.exe`) that only simulates ransomware behavior (pop-up ransom message and safe file rename inside a contained demo folder) and **does not encrypt or damage real user data**[cite: 153].
* [cite_start]**What we did with the WannaCry sample:** Referenced for academic analysis and comparison (static metadata and high-level behavior only)[cite: 154]. [cite_start]No execution, no distribution, and no replication of the malware code is included in this report[cite: 155].
* [cite_start]**What we used in the demo:** `ticket.exe` (a safe, reversible mock payload) to show the user-facing effects without risk[cite: 156].
* [cite_start]**Safety measures (summary):** [cite: 157]
    * [cite_start]Analysis work limited to an isolated VM in an air-gapped/test lab[cite: 158].
    * [cite_start]Supervisor/lab authorization was obtained[cite: 158].
    * [cite_start]No real user files or production networks were used[cite: 159].
    * [cite_start]All artifacts and screenshots included in the report are sanitized[cite: 160].

## [cite_start]7. Running the Simulation (Step-by-step) [cite: 161]

1.  [cite_start]Start MailHog: `mailhog` (ensure SMTP 1025 and UI 8025 are active)[cite: 162].
2.  Start GoPhish: `./gophish` (note admin URL and phishing server URL). [cite_start]Log into admin console[cite: 164].
3.  [cite_start]Build `ticket.exe` and start a local HTTP server to host it: `python3 -m http.server 8000` in the directory containing `ticket.exe`[cite: 165, 166].
4.  [cite_start]In GoPhish, create the email template that links to `http://localhost:8000/ticket.exe`[cite: 167, 168].
5.  [cite_start]Create a sending profile pointing to `localhost:1025` (MailHog)[cite: 169].
6.  [cite_start]Prepare a target group with one or more test email addresses[cite: 170].
7.  [cite_start]Launch the campaign from GoPhish and monitor the campaign dashboard[cite: 171].
8.  [cite_start]Open MailHog at `http://localhost:8025` to view delivered emails[cite: 172]. [cite_start]Click the link to download & run `ticket.exe` (or instruct a test user to do so in a VM)[cite: 173].
9.  [cite_start]Observe the payload behaviour (ransom note popup and demo file renaming) and check logs generated by the payload[cite: 174].
10. [cite_start]Review GoPhish campaign results for opens/clicks[cite: 175].

## [cite_start]8. Observing Results & Metrics [cite: 176]

* **GoPhish Dashboard Metrics:**
    * [cite_start]**Sent:** Number of emails sent[cite: 177].
    * [cite_start]**Delivered:** MailHog reception (GoPhish shows send status)[cite: 177].
    * [cite_start]**Opened:** Tracked via embedded tracking pixel[cite: 178].
    * [cite_start]**Clicked:** Tracked via link redirection through GoPhish[cite: 178].

[cite_start]![GoPhish Campaign Results Dashboard (showing Clicked status)](images/gophish_results_dashboard.png) [cite: 179-210]

[cite_start]![Simulated Ransomware Pop-up (WannaCry-like)](images/simulated_ransomware_popup.png) [cite: 211-241]

## [cite_start]9. Disk & Memory Image Acquisition [cite: 242]

* [cite_start]Once images are captured, verify their integrity using the acquisition tool's built-in verification/confirmation features and confirm the images are readable[cite: 243].
* [cite_start]Store the images securely for analysis (use encrypted or access-controlled storage)[cite: 244].
* [cite_start]As noted in digital forensics best practices, a complete bitstream image is the standard "forensic duplicate" for later analysis[cite: 246].

[cite_start]![Acquired Forensic Images (memdump and E01 files)](images/forensic_acquisition_files.png) [cite: 247-304]

## [cite_start]10. Forensic Analysis & Indicators of Compromise (IOCs) [cite: 305]

* [cite_start]Using the disk and memory images, analysis proceeded with Volatility (for RAM) and registry/file-viewing tools (for the disk image)[cite: 306].
* [cite_start]Volatility was used to enumerate running processes, show process trees, and inspect loaded modules from memory[cite: 307].
* [cite_start]**In the memory image we identified two notable items** via `pstree`/`pslist` style output and process inspection: [cite: 308]
    * [cite_start]A process named `@wannacrydecryptor` present in memory and showing behavior consistent with a dropped/running payload (visible in the process list)[cite: 309].
    * [cite_start]A process named `tasksche.exe` shown running from a suspicious filesystem location (reported in the process tree and confirmed by memory-resident module information)[cite: 310].
* [cite_start]**On the disk image, registry analysis revealed a persistence entry** created to maintain execution across reboots[cite: 610].
* [cite_start]The specific Run key discovered was: [cite: 611]
    * [cite_start]`HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\WanaCrypt0` [cite: 612]
* [cite_start]This Run key referenced the persistence executable (the same path/name observed in the memory analysis)[cite: 613].

[cite_start]![Volatility Analysis Output (Process Listing)](images/volatility_process_list.png) [cite: 312-609]

[cite_start]![Registry Editor Persistence Key (showing HKLM\SOFTWARE\WOW6432Node\WanaCrypt0)](images/registry_persistence_key.png) [cite: 616, 617]

* [cite_start]In this controlled lab, the registry Run key plus the in-memory evidence of `@wannacrydecryptor` and `tasksche.exe` form the **primary indicators of compromise (IOCs)** for the simulated infection[cite: 614].

## [cite_start]11. MITRE ATT&CK Mapping [cite: 617]

| Stage | Technique ID | Technique Name | Description |
| :--- | :--- | :--- | :--- |
| **Initial Access** | T1566.001 | Phishing: Spearphishing Attachment | [cite_start]The phishing email (sent via GoPhish) contained a download link to `ticket.exe`, representing a malicious attachment or link lure[cite: 617]. |
| **Execution** | T1204.002 | User Execution: Malicious File | [cite_start]The victim executed `ticket.exe` believing it was a raffle ticket [cite: 618][cite_start]; this initiated the simulated ransomware payload[cite: 619]. |
| **Persistence** | T1547.001 | Registry Run Keys / Startup Folder | [cite_start]Registry key `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\WanaCrypt0` ensured the payload (`tasksche.exe`) ran on startup[cite: 619]. |
| **Defense Evasion** | T1036.005 | Masquerading: Match Legitimate Name or Location | [cite_start]The payload used legitimate-sounding filenames like `tasksche.exe` to avoid suspicion[cite: 620]. |
| **Impact** | T1486 | Data Encrypted for Impact | [cite_start]While the mock payload did not encrypt real files, it simulated the encryption process and displayed a ransom message, demonstrating this technique safely[cite: 621]. |
| **Command & Control** | T1071.001 | Application Layer Protocol: Web Protocols | [cite_start]In a real-world WannaCry-style attack, communication to a command server would occur via HTTP/S [cite: 622][cite_start]; this behavior was conceptually discussed but not executed[cite: 623]. |

## [cite_start]12. Cyber Kill Chain [cite: 623]

| Kill Chain Phase | What happened in the simulation | Artifacts / Evidence | Was it detected? If so how & when |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** | [cite_start]Attacker (simulator) prepared the lure and target list (created email template and CSV of targets)[cite: 624]. | [cite_start]GoPhish templates, `targets.csv`, project notes[cite: 625]. | [cite_start]**Not detected** – preparation phase[cite: 625]. |
| **Weaponization** | [cite_start]Created the payload concept (`ticket.exe` mock) and phishing HTML body template[cite: 626]. | [cite_start]`ticket.py` source, PyInstaller build artifacts, HTML body template[cite: 626]. | [cite_start]**Not detected** – payload preparation[cite: 626]. |
| **Delivery** | [cite_start]Email sent via GoPhish $\rightarrow$ MailHog; phishing email delivered to target inbox[cite: 627, 628]. | [cite_start]MailHog captured mails, GoPhish “Sent” entries[cite: 628]. | [cite_start]**Not detected** – email successfully delivered[cite: 629]. |
| **Exploitation** | [cite_start]The victim clicked the link and executed `ticket.exe` on the test VM[cite: 629]. [cite_start]This is where code ran[cite: 630]. | [cite_start]Download logs, `ticket.exe` execution on VM, process entry in memory[cite: 630]. | [cite_start]**Detected here – Late Detection:** Infection became visible only after execution (ransomware activity observed)[cite: 631]. |
| **Installation** | [cite_start]Registry Run key added to maintain persistence (`HKLM\...\WanaCrypt0` referencing the payload)[cite: 632]. | [cite_start]Registry hive from disk image, Run key entry, file path referenced by key[cite: 633]. | [cite_start]**Detected later** during forensic analysis (post infection)[cite: 634]. |
| **Command & Control (C2)** | [cite_start]Simulated / Not executed[cite: 634]. [cite_start]In a real WannaCry variant C2 or worming may exist [cite: 635][cite_start]; no external C2 activity was performed in the lab[cite: 636]. | [cite_start]N/A (no network callbacks executed)[cite: 636]. | [cite_start]Not applicable[cite: 636]. |
| **Actions on Objectives** | [cite_start]Impact renamed demo files and displayed ransom-note UI (simulated data encryption)[cite: 637]. [cite_start]| demo\_files with `.encrypted` names, `ticket_log.txt`, ransom-note popup screenshots[cite: 638]. | [cite_start]Observed as visible system impact[cite: 638]. |

### [cite_start]12.1 Detection Summary [cite: 639]

* [cite_start]Detection occurred **late**, during the Exploitation phase, after the payload executed[cite: 639].
* [cite_start]Volatility analysis revealed malicious processes (`@WannaCryDecryptor`, `tasksche.exe`) running from suspicious paths[cite: 640].
* [cite_start]FTK Imager and registry examination showed a persistence entry at `HKLM\SOFTWARE\WOW6432Node\WanaCrypt0`[cite: 641].
* [cite_start]These findings confirm that the simulated ransomware successfully executed before detection, which reflects real-world challenges in early ransomware identification[cite: 642].

## [cite_start]13. Incident Response and Post-Incident Activities [cite: 643]

[cite_start]After identifying the infection indicators in memory and registry analysis, an incident response workflow was initiated to contain, analyze, and recover the affected system within the controlled lab environment[cite: 643].

### [cite_start]13.1 Containment and Recovery Actions [cite: 644]

Following the forensic findings, we took several steps to safely manage and restore the affected virtual machine:
* [cite_start]**Root Cause Analysis:** The infection originated from the execution of the downloaded `ticket.exe`, which simulated the WannaCry behavior after a successful phishing email interaction[cite: 644]. [cite_start]The root cause was confirmed to be user interaction with the phishing attachment, demonstrating the effectiveness of social engineering tactics[cite: 645].
* [cite_start]**Isolation of Affected Systems:** The infected VM was immediately isolated from the lab network to prevent any possible propagation or external communication[cite: 646]. [cite_start]No data exfiltration or cross-system infection occurred, as confirmed through network monitoring and memory analysis[cite: 647].
* [cite_start]**System Recovery:** After isolation, we restored the affected VM using a clean backup image created before the simulation[cite: 648]. [cite_start]This ensured the environment was returned to a stable state without residual infection[cite: 649]. [cite_start]FTK Imager was used to verify the backup image before restoration[cite: 650].

## [cite_start]14. Recommendations & Mitigations [cite: 651]

[cite_start]Based on the analysis of the phishing and ransomware simulation, several preventive and corrective security controls are recommended[cite: 651]. [cite_start]These measures address the weaknesses that allowed the simulated infection to occur and strengthen defenses against similar real-world attacks[cite: 652].

### [cite_start]14.1 User Awareness and Training [cite: 653]
* [cite_start]Conduct regular phishing-awareness sessions to help users identify suspicious emails and attachments[cite: 653].
* [cite_start]Include periodic phishing simulations using safe frameworks like GoPhish to test employee readiness[cite: 654].
* [cite_start]Reinforce a “Think Before You Click” culture — encourage users to report unexpected links or downloads[cite: 655].
* [cite_start]Establish a clear incident-reporting channel (e.g., `report@company.local`) to quickly escalate suspicious messages[cite: 656].

### [cite_start]14.2 Email Security Controls [cite: 657]

[cite_start]![Windows Desktop Environment (Context Image, located near the end of the report)](images/windows_desktop_context.png) [cite: 657]

* [cite_start]Implement SPF, DKIM, and DMARC to prevent domain spoofing and reduce phishing success rates[cite: 657].
* [cite_start]Deploy email filtering and sandboxing to analyze attachments and links before delivery[cite: 658].
* [cite_start]Block or quarantine executable attachments (`.exe`, `.bat`, `.js`) at the mail gateway[cite: 659].
* [cite_start]Use URL rewriting and scanning to inspect links embedded in emails[cite: 660].

### [cite_start]14.3 Endpoint and System Hardening [cite: 661]
* [cite_start]Enable Application Whitelisting to restrict execution to approved software only[cite: 661].
* [cite_start]Maintain regular patch management across all systems to reduce exploitability of vulnerabilities[cite: 662].
* [cite_start]Deploy Endpoint Detection & Response (EDR) or antivirus tools with behavioral analysis to detect and stop ransomware-like activity[cite: 663].
* [cite_start]Enforce least-privilege principles for user accounts to limit damage if compromise occurs[cite: 664].

### [cite_start]14.4 Backup and Recovery Practices [cite: 665]
* [cite_start]Maintain regular, automated backups stored offline or in immutable cloud storage[cite: 665].
* [cite_start]Periodically test backup restorations to confirm data integrity and recovery speed[cite: 666].
* [cite_start]Keep multiple backup generations to ensure recovery even if recent data becomes compromised[cite: 667].
* [cite_start]Document backup schedules and recovery points within organizational policies[cite: 668].

### [cite_start]14.5 Network and Monitoring Enhancements [cite: 669]
* [cite_start]Segment critical systems and servers from user networks using VLANs or subnets[cite: 669].
* [cite_start]Implement Network Intrusion Detection/Prevention Systems (NIDS/NIPS) to detect suspicious traffic[cite: 670].
* [cite_start]Log all authentication and network events centrally in a SIEM for correlation and alerting[cite: 671].
* [cite_start]Regularly review logs for anomalies and failed login attempts[cite: 672].

### [cite_start]14.6 Policy and Governance [cite: 673]
* [cite_start]Establish a formal Incident Response Plan (IRP) defining roles, escalation paths, and communication protocols[cite: 673].
* [cite_start]Maintain a forensic readiness plan to ensure evidence (memory, disk, logs) can be acquired safely in future incidents[cite: 674].
* [cite_start]Update security policies and standard operating procedures (SOPs) based on lessons learned from this project[cite: 675].
* [cite_start]Conduct annual audits of both technical and procedural controls to ensure compliance and effectiveness[cite: 676].

## [cite_start]15. Project Summary & Conclusion [cite: 677]

[cite_start]This project successfully simulated a full phishing-to-ransomware attack chain in a controlled laboratory environment to demonstrate the real-world lifecycle of a cyber incident — from initial compromise to detection, analysis, and recovery[cite: 677].
* [cite_start]The simulation began with a phishing campaign using **GoPhish** and **MailHog**, where a crafted email imitating a “Fawryz giveaway” lured the victim into downloading a malicious executable named `ticket.exe`[cite: 678].
* [cite_start]Once executed, the payload simulated ransomware behavior similar to WannaCry, encrypting files and creating persistence via registry modifications under `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\WanaCrypt0`[cite: 679].
* [cite_start]Following infection, **FTK Imager** was used to capture disk and memory images, which were then analyzed using **Volatility 3** to identify malicious processes such as `@WannaCryDecryptor` and `tasksche.exe`[cite: 680]. [cite_start]These artifacts, along with the persistence registry key, served as clear **Indicators of Compromise (IOCs)**[cite: 681].
* [cite_start]A Chain of Custody was maintained throughout evidence acquisition to preserve forensic integrity[cite: 682].
* [cite_start]In the recovery phase, the affected virtual machine was isolated, and data was successfully restored using a clean backup image, completing the containment and recovery steps[cite: 683].
* [cite_start]Finally, the **MITRE ATT&CK framework** was used to map adversary behavior and identify key tactics such as initial access, execution, persistence, and impact[cite: 684].
* [cite_start]Based on these findings, a set of **recommendations and mitigations** was developed to strengthen security posture — including user awareness, email filtering, endpoint protection, backup management, and formal incident response planning[cite: 685].

[cite_start]**In conclusion, the project demonstrated the complete cybersecurity incident lifecycle:** [cite: 686]
* [cite_start]Attack Simulation (Phishing + Malware Execution) [cite: 686]
* [cite_start]Forensic Investigation (Evidence Collection & Analysis) [cite: 686]
* [cite_start]Incident Response (Containment, Eradication, Recovery) [cite: 686]
* [cite_start]Post-Incident Review (Lessons Learned & Recommendations) [cite: 686]

[cite_start]This end-to-end approach reflects real-world practices used by cybersecurity professionals to detect, analyze, and respond to modern threats[cite: 687]. [cite_start]It highlights the importance of combining technical defenses, user training, and procedural discipline to maintain resilience against evolving cyberattacks[cite: 687].
