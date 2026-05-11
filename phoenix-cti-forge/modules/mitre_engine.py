"""
CTI Forge - MITRE ATT&CK Engine
Curated educational subset of MITRE ATT&CK framework.
All data is static Python dictionaries - no external API dependencies.
"""
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class Tactic(Enum):
    """MITRE ATT&CK Tactics (Phases of the attack lifecycle)."""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class Technique:
    """MITRE ATT&CK Technique with educational context."""
    id: str
    name: str
    tactic: Tactic
    description: str
    ctipearl: str  # Educational insight for CTI analysts
    detection_tips: List[str]
    data_sources: List[str]
    mitigations: List[str]
    apt_examples: List[str]
    difficulty: str  # Low, Medium, High - for learning progression


class MITREEngine:
    """
    Educational MITRE ATT&CK explorer.
    Provides curated techniques with CTI-focused learning content.
    """
    
    TECHNIQUES: List[Technique] = [
        # Initial Access
        Technique(
            id="T1566",
            name="Phishing",
            tactic=Tactic.INITIAL_ACCESS,
            description="Adversaries send malicious messages to gain access to victim systems.",
            ctipearl="Email security gateways catch 99% of phishing, but that 1% represents thousands of messages. CTI tracks phishing infrastructure (domains, sender IPs, attachment hashes) to build proactive blocks.",
            detection_tips=[
                "Monitor for suspicious sender domains and display name spoofing",
                "Track attachment hash patterns across campaigns",
                "Correlate URL clicks with domain registration dates",
                "Use DMARC, DKIM, SPF failure rates as indicators"
            ],
            data_sources=["Email gateway logs", "Proxy logs", "Endpoint detection", "Sandbox detonations"],
            mitigations=["Email filtering", "User training", "Application whitelisting", "Disable macros"],
            apt_examples=["APT29 (Cozy Bear)", "APT28 (Fancy Bear)", "FIN7", "TA505"],
            difficulty="Low"
        ),
        Technique(
            id="T1190",
            name="Exploit Public-Facing Application",
            tactic=Tactic.INITIAL_ACCESS,
            description="Adversaries exploit vulnerabilities in internet-facing systems to gain access.",
            ctipearl="Shodan, Censys, and Exploit-DB are CTI analyst staples. Knowing what software your organization exposes to the internet is half the battle - the other half is tracking which CVEs are weaponized.",
            detection_tips=[
                "Monitor WAF logs for unusual request patterns",
                "Track exploit kit landing page IOCs",
                "Watch for out-of-band application errors",
                "Correlate vulnerability scan data with threat intel feeds"
            ],
            data_sources=["Web server logs", "WAF logs", "Vulnerability scanners", "Exploit databases"],
            mitigations=["Patch management", "WAF rules", "Network segmentation", "Application hardening"],
            apt_examples=["APT41", "Lazarus Group", "Hafnium"],
            difficulty="Medium"
        ),
        
        # Execution
        Technique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic=Tactic.EXECUTION,
            description="Adversaries abuse command and scripting interpreters to execute commands.",
            ctipearl="PowerShell is both an admin tool and adversary favorite. CTI analysts track obfuscated PowerShell patterns, LOLBAS (Living Off The Land Binaries), and encoded command structures.",
            detection_tips=[
                "Monitor for encoded commands (-enc, base64)",
                "Look for PowerShell spawned by Office applications",
                "Track unusual child processes from wscript/cscript",
                "Use script block logging and AMSI integration"
            ],
            data_sources=["Process monitoring", "PowerShell logs", "EDR telemetry", "Sysmon"],
            mitigations=["Constrained Language Mode", "AppLocker", "Disable unused interpreters", "Logging"],
            apt_examples=["APT29", "Emotet", "TrickBot", "Cobalt Strike"],
            difficulty="Low"
        ),
        Technique(
            id="T1204",
            name="User Execution",
            tactic=Tactic.EXECUTION,
            description="Adversaries rely on specific user actions for execution.",
            ctipearl="The human factor is both the weakest link and hardest to patch. CTI tracks the social engineering pretexts that make users click - timely intel on current lures (tax season, COVID, etc.) helps training.",
            detection_tips=[
                "Monitor for document macros with AutoOpen/AutoExec",
                "Track .iso, .img, .lnk file executions from downloads",
                "Look for UserAssist registry entries for suspicious programs",
                "Correlate execution with recent email delivery"
            ],
            data_sources=["Endpoint detection", "Email logs", "Registry monitoring", "User behavior analytics"],
            mitigations=["Macro security", "Application control", "User training", "Mark-of-the-Web enforcement"],
            apt_examples=["Qbot", "IcedID", "Bumblebee"],
            difficulty="Low"
        ),
        
        # Persistence
        Technique(
            id="T1547",
            name="Boot or Logon Autostart Execution",
            tactic=Tactic.PERSISTENCE,
            description="Adversaries configure autostart execution to maintain persistence.",
            ctipearl="Persistence mechanisms are gold for CTI because they are consistent. Attackers reuse what works. Tracking new persistence methods across incident reports builds better detection logic.",
            detection_tips=[
                "Monitor Run/RunOnce registry keys",
                "Track Startup folder modifications",
                "Watch for new scheduled tasks at boot",
                "Detect new services with suspicious names/descriptions"
            ],
            data_sources=["Registry monitoring", "File monitoring", "Service control manager", "Scheduled task logs"],
            mitigations=["Restrict registry permissions", "AppLocker", "User Account Control", "EDR policies"],
            apt_examples=["APT41", "OilRig", "FIN6"],
            difficulty="Medium"
        ),
        Technique(
            id="T1053",
            name="Scheduled Task/Job",
            tactic=Tactic.PERSISTENCE,
            description="Adversaries create scheduled tasks to execute malicious code.",
            ctipearl="Scheduled tasks are dual-use: legitimate admins use them, and so do attackers. CTI distinguishes by tracking task names, actions, and triggers that match known APT tradecraft.",
            detection_tips=[
                "Monitor Windows Event ID 4698 (task creation)",
                "Look for tasks executing from temporary directories",
                "Track hidden tasks (deleted registry keys, .job files)",
                "Correlate with binary reputation at task execution"
            ],
            data_sources=["Scheduled task logs", "Windows Security logs", "Sysmon", "EDR telemetry"],
            mitigations=["Restrict task scheduler permissions", "Monitor task creation", "Application control", "User training"],
            apt_examples=["Sandworm", "APT29", "Lazarus Group"],
            difficulty="Medium"
        ),
        
        # Defense Evasion
        Technique(
            id="T1027",
            name="Obfuscated Files or Information",
            tactic=Tactic.DEFENSE_EVASION,
            description="Adversaries obfuscate files or information to evade detection.",
            ctipearl="Obfuscation is an arms race. CTI analysts catalog encoding patterns, packers, and crypters used by specific malware families. Recognizing the 'signature' of a packer speeds up analysis.",
            detection_tips=[
                "Monitor for excessive entropy in files (indicates encryption/packing)",
                "Look for Base64, XOR, or custom encoding patterns",
                "Track certificate anomalies in signed executables",
                "Detect process hollowing and injection patterns"
            ],
            data_sources=["File analysis", "Memory forensics", "Static analysis", "EDR telemetry"],
            mitigations=["Antivirus/EDR", "Application control", "Memory protection", "Behavioral detection"],
            apt_examples=["APT32", "APT19", "FIN8"],
            difficulty="High"
        ),
        Technique(
            id="T1070",
            name="Indicator Removal on Host",
            tactic=Tactic.DEFENSE_EVASION,
            description="Adversaries delete or modify artifacts generated on a host.",
            ctipearl="Anti-forensics tells you what the attacker fears. If they clear logs, they know you're watching. CTI uses the *absence* of expected logs as an indicator of sophisticated intrusion.",
            detection_tips=[
                "Monitor for event log clearing (Event IDs 1102, 104)",
                "Look for timestomping (creation time > modification time)",
                "Track large-scale file deletion patterns",
                "Correlate with volume shadow copy deletions"
            ],
            data_sources=["Windows Event logs", "File system monitoring", "Command-line monitoring", "Sysmon"],
            mitigations=["Centralized logging", "Immutable backups", "Tamper-proof audit policies", "EDR protection"],
            apt_examples=["APT29", "APT41", "Carbanak"],
            difficulty="High"
        ),
        
        # Credential Access
        Technique(
            id="T1003",
            name="OS Credential Dumping",
            tactic=Tactic.CREDENTIAL_ACCESS,
            description="Adversaries dump credentials to obtain account login credentials.",
            ctipearl="Credential dumping is the pivot point of most intrusions. Once LSASS is dumped, the attacker has the keys to the kingdom. CTI tracks which tools (Mimikatz, Lazagne, etc.) are circulating.",
            detection_tips=[
                "Monitor LSASS access by non-system processes",
                "Look for SAM/SYSTEM/SECURITY hive dumps",
                "Track Kerberos ticket extraction (T1003.002)",
                "Detect suspicious NTDS.dit access or replication"
            ],
            data_sources=["Windows Security logs", "EDR telemetry", "Sysmon", "Authentication logs"],
            mitigations=["Credential Guard", "LSASS protection", "WDAC", "PPL (Protected Process Light)"],
            apt_examples=["APT28", "APT29", "Wizard Spider", "Lazarus Group"],
            difficulty="High"
        ),
        Technique(
            id="T1557",
            name="Man-in-the-Middle",
            tactic=Tactic.CREDENTIAL_ACCESS,
            description="Adversaries position themselves between two or more communicating hosts.",
            ctipearl="MITM attacks in enterprise environments often use ARP poisoning, LLMNR/NBT-NS poisoning, or rogue access points. CTI tracks responder tools, evilginx frameworks, and certificate anomalies.",
            detection_tips=[
                "Monitor for ARP table changes",
                "Detect duplicate IP or MAC addresses",
                "Track unauthorized DHCP servers",
                "Look for SMB signing disabled events"
            ],
            data_sources=["Network flow logs", "DHCP logs", "DNS logs", "Endpoint detection"],
            mitigations=["SMB signing", "DHCP snooping", "Dynamic ARP inspection", "Certificate pinning"],
            apt_examples=["APT28", "OilRig", "FIN8"],
            difficulty="Medium"
        ),
        
        # Discovery
        Technique(
            id="T1083",
            name="File and Directory Discovery",
            tactic=Tactic.DISCOVERY,
            description="Adversaries enumerate files and directories.",
            ctipearl="Discovery is where attackers make noise. File enumeration patterns - searching for password files, crypto wallets, or specific extensions - create detectable signatures that CTI can catalog.",
            detection_tips=[
                "Monitor for rapid file enumeration in sensitive directories",
                "Look for dir /s, Get-ChildItem on network shares",
                "Track searches for password files, keys, or config files",
                "Detect recursive enumeration of /etc, C:\\Users, etc."
            ],
            data_sources=["File monitoring", "Command-line logs", "EDR telemetry", "Sysmon"],
            mitigations=["File system permissions", "EDR policies", "Honeypot files", "Logging"],
            apt_examples=["APT32", "FIN10", "Cobalt Strike"],
            difficulty="Low"
        ),
        Technique(
            id="T1046",
            name="Network Service Scanning",
            tactic=Tactic.DISCOVERY,
            description="Adversaries scan networks for available services.",
            ctipearl="Port scanning is the heartbeat of reconnaissance. CTI correlates scanning patterns with known APT infrastructure - some groups use distinctive port ranges, timing, or banner grabbing.",
            detection_tips=[
                "Monitor for sequential port connections",
                "Look for SYN scans, connect scans from internal hosts",
                "Track unusual internal host-to-host scanning",
                "Correlate with vulnerability scan schedules"
            ],
            data_sources=["Netflow", "Firewall logs", "IDS/IPS alerts", "EDR telemetry"],
            mitigations=["Network segmentation", "Host firewalls", "IDS/IPS", "Honeypots"],
            apt_examples=["APT1", "APT32", "FIN6"],
            difficulty="Low"
        ),
        
        # Command and Control
        Technique(
            id="T1071",
            name="Application Layer Protocol",
            tactic=Tactic.COMMAND_AND_CONTROL,
            description="Adversaries communicate using application layer protocols.",
            ctipearl="HTTPS C2 is the norm now. CTI analysts profile TLS fingerprints (JA3/JA3S), SNI patterns, and certificate chains. Domain fronting and CDN abuse require tracking cloud infrastructure patterns.",
            detection_tips=[
                "Monitor for beaconing patterns (fixed intervals, jitter)",
                "Look for unusual User-Agent strings",
                "Track DNS query patterns for DGA domains",
                "Analyze TLS certificate anomalies and self-signed certs"
            ],
            data_sources=["Proxy logs", "DNS logs", "Netflow", "TLS inspection"],
            mitigations=["Proxy filtering", "DNS security", "TLS inspection", "Network segmentation"],
            apt_examples=["APT29", "APT41", "TrickBot", "Emotet"],
            difficulty="Medium"
        ),
        Technique(
            id="T1572",
            name="Protocol Tunneling",
            tactic=Tactic.COMMAND_AND_CONTROL,
            description="Adversaries tunnel network communications to C2 through protocols.",
            ctipearl="DNS tunneling and ICMP tunneling are classic covert channels. CTI tracks the specific encoding used (base64 in DNS TXT records, etc.) and the query volume patterns that give away tunneling.",
            detection_tips=[
                "Monitor for large DNS TXT records or queries",
                "Look for ICMP payloads larger than typical",
                "Track unusual data volume over 'normal' protocols",
                "Detect SSH tunneling and port forwarding"
            ],
            data_sources=["DNS logs", "Netflow", "Firewall logs", "DPI (Deep Packet Inspection)"],
            mitigations=["DNS filtering", "Protocol enforcement", "DLP", "Network monitoring"],
            apt_examples=["APT32", "Lazarus Group", "FIN6"],
            difficulty="High"
        ),
        
        # Exfiltration
        Technique(
            id="T1041",
            name="Exfiltration Over C2 Channel",
            tactic=Tactic.EXFILTRATION,
            description="Adversaries exfiltrate data over existing C2 channel.",
            ctipearl="Using the C2 channel for exfiltration is efficient for attackers but creates correlation opportunities for defenders. CTI tracks the staging patterns - attackers rarely exfiltrate raw data directly.",
            detection_tips=[
                "Monitor for data staging in temp directories",
                "Look for compression and encryption before transmission",
                "Track outbound data volume spikes",
                "Detect file extensions being changed before transfer"
            ],
            data_sources=["EDR telemetry", "Netflow", "Proxy logs", "DLP logs"],
            mitigations=["Data loss prevention", "Network monitoring", "Application control", "Encryption"],
            apt_examples=["APT29", "APT28", "Carbanak"],
            difficulty="Medium"
        ),
        Technique(
            id="T1567",
            name="Exfiltration Over Web Service",
            tactic=Tactic.EXFILTRATION,
            description="Adversaries exfiltrate data over web services like cloud storage.",
            ctipearl="Using legitimate cloud services (Dropbox, OneDrive, Google Drive) for exfiltration blends in. CTI tracks OAuth abuse, suspicious app registrations, and data volumes to consumer cloud services.",
            detection_tips=[
                "Monitor for new OAuth app registrations",
                "Look for bulk uploads to consumer cloud storage",
                "Track API calls to file sharing services",
                "Detect unusual user-agent strings for cloud APIs"
            ],
            data_sources=["Cloud access logs", "Proxy logs", "CASB logs", "Authentication logs"],
            mitigations=["CASB (Cloud Access Security Broker)", "DLP", "Proxy filtering", "Application control"],
            apt_examples=["APT29", "APT41", "FIN7"],
            difficulty="Medium"
        ),
        
        # Impact
        Technique(
            id="T1486",
            name="Data Encrypted for Impact",
            tactic=Tactic.IMPACT,
            description="Adversaries encrypt data to interrupt access.",
            ctipearl="Ransomware is the most visible form of this technique. CTI tracks ransom notes, wallet addresses, TTPs, and the 'double extortion' tactic of stealing before encrypting.",
            detection_tips=[
                "Monitor for mass file extension changes",
                "Look for shadow copy deletions (vssadmin delete)",
                "Track suspicious processes writing to many files rapidly",
                "Detect backup system access and deletion"
            ],
            data_sources=["File monitoring", "Windows Event logs", "EDR telemetry", "Backup logs"],
            mitigations=["Offline backups", "EDR behavioral detection", "Application control", "Network segmentation"],
            apt_examples=["Wizard Spider (Conti, Ryuk)", "REvil", "LockBit", "BlackCat"],
            difficulty="Medium"
        ),
        Technique(
            id="T1491",
            name="Defacement",
            tactic=Tactic.IMPACT,
            description="Adversaries modify content to make it undesirable.",
            ctipearl="Website defacement is often hacktivism or low-skill vandalism, but can also signal APT presence. CTI tracks defacement messages for political context and claiming groups.",
            detection_tips=[
                "Monitor website integrity via checksums",
                "Look for unauthorized web server modifications",
                "Track DNS hijacking leading to defacement",
                "Detect content management system exploitation"
            ],
            data_sources=["Web server logs", "File integrity monitoring", "DNS logs", "CMS logs"],
            mitigations=["WAF", "FIM (File Integrity Monitoring)", "CSP", "Patch management"],
            apt_examples=["APT27", "Iranian groups", "Pro-Palestinian hacktivists"],
            difficulty="Low"
        ),

        # ── Reconnaissance ──────────────────────────────────────────────
        Technique(
            id="T1595",
            name="Active Scanning",
            tactic=Tactic.RECONNAISSANCE,
            description="Adversaries actively probe victim infrastructure to gather information before an attack.",
            ctipearl="Shodan, Censys, and FOFA are passive — they index what's already public. Active scanning from adversary IPs leaves traces in firewall and IDS logs. CTI correlates scanner IPs across campaigns to attribute pre-attack reconnaissance.",
            detection_tips=[
                "Monitor IDS/IPS logs for port scans from external IPs",
                "Track repeated requests to non-existent resources (404 storms)",
                "Correlate scanning IPs with known threat actor infrastructure",
                "Alert on enumeration of service banners and version strings",
            ],
            data_sources=["Network IDS/IPS", "Firewall logs", "Web server logs", "Honeypots"],
            mitigations=["Network segmentation", "Firewall ACLs", "Honeypots", "Banner suppression"],
            apt_examples=["Volt Typhoon", "APT28", "Sandworm", "Scattered Spider"],
            difficulty="Low",
        ),
        Technique(
            id="T1589",
            name="Gather Victim Identity Information",
            tactic=Tactic.RECONNAISSANCE,
            description="Adversaries gather victim identity information such as employee names, emails, and credentials before attacks.",
            ctipearl="LinkedIn, Hunter.io, and credential breach databases are primary OSINT sources for adversaries. CTI tracks which threat actors purchase breach data and how quickly they operationalize it after a leak appears on dark web markets.",
            detection_tips=[
                "Monitor credential breach databases for your domain (HaveIBeenPwned enterprise)",
                "Track unusual login attempts with recently breached credentials",
                "Watch for mass enumeration of employee email formats",
                "Monitor OSINT platforms for data about your organization",
            ],
            data_sources=["Identity providers", "Email gateway", "SIEM anomaly detection", "Threat intel feeds"],
            mitigations=["MFA enforcement", "Breach monitoring", "Password manager policies", "Employee OSINT awareness"],
            apt_examples=["FIN7", "LAPSUS$", "Scattered Spider", "TA505"],
            difficulty="Low",
        ),

        # ── Resource Development ─────────────────────────────────────────
        Technique(
            id="T1583",
            name="Acquire Infrastructure",
            tactic=Tactic.RESOURCE_DEVELOPMENT,
            description="Adversaries acquire infrastructure such as domains, servers, and cloud accounts to support operations.",
            ctipearl="Infrastructure acquisition leaves breadcrumbs: WHOIS registrations, SSL certificates, ASN hosting patterns. CTI pivots from a single IOC through passive DNS and certificate transparency logs to map an actor's full infrastructure cluster — often before it's used.",
            detection_tips=[
                "Monitor certificate transparency logs for lookalike domain registrations",
                "Track passive DNS for fast-flux or newly registered domains",
                "Correlate ASN and hosting provider patterns with known threat actor infrastructure",
                "Watch for domain registrations mimicking your brand",
            ],
            data_sources=["Passive DNS", "Certificate transparency logs", "WHOIS data", "Threat intel feeds"],
            mitigations=["Brand monitoring", "Domain takedown procedures", "Preemptive registration", "Threat intel sharing"],
            apt_examples=["APT28", "APT29", "Kimsuky", "Lazarus Group"],
            difficulty="Medium",
        ),
        Technique(
            id="T1588",
            name="Obtain Capabilities",
            tactic=Tactic.RESOURCE_DEVELOPMENT,
            description="Adversaries obtain tools and capabilities to use in operations, including purchasing, stealing, or developing malware.",
            ctipearl="Crimeware-as-a-Service (CaaS) dramatically lowered the bar for entry. CTI tracks tool provenance: who sells what on dark web forums, which toolkits are affiliated with specific ransomware groups, and how commodity malware is modified for targeted campaigns.",
            detection_tips=[
                "Track dark web forums for new tool releases and sales",
                "Monitor for YARA rule matches on known commercial RATs",
                "Watch for obfuscated versions of publicly available post-exploitation frameworks",
                "Correlate tool signatures across unrelated incidents for shared infrastructure",
            ],
            data_sources=["Malware repositories", "YARA rules", "Dark web monitoring", "Sandbox analysis"],
            mitigations=["EDR with behavioral detection", "YARA scanning", "Threat intel subscriptions", "Supply chain monitoring"],
            apt_examples=["Conti affiliates", "REvil", "LockBit", "BlackCat/ALPHV"],
            difficulty="Medium",
        ),

        # ── Initial Access ───────────────────────────────────────────────
        Technique(
            id="T1195",
            name="Supply Chain Compromise",
            tactic=Tactic.INITIAL_ACCESS,
            description="Adversaries manipulate products or delivery mechanisms prior to receipt by a final consumer.",
            ctipearl="Supply chain attacks are devastating because they weaponize trust. The SolarWinds/SUNBURST attack (2020) reached 18,000 organizations through a legitimate signed update. CTI now routinely monitors vendor security posture and software build pipelines as part of supply chain risk management.",
            detection_tips=[
                "Verify software signatures and hashes before deployment",
                "Monitor for unexpected network connections from trusted software",
                "Use software bill of materials (SBOM) to track dependencies",
                "Baseline normal update behavior and alert on deviations",
            ],
            data_sources=["Software inventory", "Network monitoring", "Code signing verification", "SBOM analysis"],
            mitigations=["Software provenance verification", "SBOM management", "Build pipeline security", "Vendor risk assessments"],
            apt_examples=["APT29 (SolarWinds)", "Winnti Group (CCleaner)", "APT41 (ASUS Live Update)", "Lazarus (3CX)"],
            difficulty="High",
        ),
        Technique(
            id="T1078",
            name="Valid Accounts",
            tactic=Tactic.INITIAL_ACCESS,
            description="Adversaries use legitimate credentials to gain initial access, evading detection by appearing as authorized users.",
            ctipearl="Valid account abuse is the hardest initial access to detect because there is no exploit to signature. CTI intelligence about active credential theft operations, credential broker markets, and specific targeted organizations helps defenders prioritize MFA enforcement and anomaly detection.",
            detection_tips=[
                "Monitor for logins from unusual geographies or impossible travel",
                "Track first-time logins from new devices or locations",
                "Alert on login outside business hours for privileged accounts",
                "Correlate credential use with breach and infostealer intelligence",
            ],
            data_sources=["Authentication logs", "Identity provider", "VPN logs", "UEBA"],
            mitigations=["MFA on all accounts", "Conditional access policies", "Privileged access workstations", "Zero-trust architecture"],
            apt_examples=["APT29", "Scattered Spider", "LAPSUS$", "Volt Typhoon"],
            difficulty="Medium",
        ),

        # ── Execution ────────────────────────────────────────────────────
        Technique(
            id="T1047",
            name="Windows Management Instrumentation",
            tactic=Tactic.EXECUTION,
            description="Adversaries use WMI to execute malicious commands and payloads, often for lateral movement.",
            ctipearl="WMI is deeply embedded in Windows administration — almost impossible to disable. CTI looks for WMI executing from unusual parent processes and creating child processes with suspicious arguments. APT32 and APT29 have heavily abused WMI for fileless execution.",
            detection_tips=[
                "Monitor WMI process creation events (Event ID 4688 with WmiPrvSE.exe)",
                "Track WMI subscriptions (T1546.003) for persistence",
                "Alert on WMI spawning cmd.exe, powershell.exe, or mshta.exe",
                "Use Sysmon Event IDs 19, 20, 21 for WMI monitoring",
            ],
            data_sources=["WMI logs", "Sysmon", "EDR process telemetry", "Windows Security logs"],
            mitigations=["WMI namespace permissions", "Restrict remote WMI", "Application control", "Behavioral detection"],
            apt_examples=["APT32 (OceanLotus)", "APT29", "Turla", "Emotet"],
            difficulty="Medium",
        ),
        Technique(
            id="T1106",
            name="Native API",
            tactic=Tactic.EXECUTION,
            description="Adversaries interact directly with Windows Native API functions to execute code, bypassing higher-level API monitoring.",
            ctipearl="Native API calls like NtCreateProcess, NtAllocateVirtualMemory, and NtWriteVirtualMemory are the building blocks of most injection techniques. CTI uses API call sequences as a behavioral fingerprint for malware families even when hashes change.",
            detection_tips=[
                "Monitor for direct syscall invocations bypassing user-mode hooks",
                "Track unusual ntdll.dll imports in process memory",
                "Alert on undocumented Windows API usage patterns",
                "Use memory analysis to identify API hooks and direct syscalls",
            ],
            data_sources=["API monitoring", "Memory forensics", "EDR behavioral telemetry", "Sandbox analysis"],
            mitigations=["EDR with kernel-level visibility", "Exploit protection (EMET)", "Application sandboxing"],
            apt_examples=["Cobalt Strike", "Metasploit", "APT41", "FIN7"],
            difficulty="High",
        ),

        # ── Privilege Escalation ─────────────────────────────────────────
        Technique(
            id="T1055",
            name="Process Injection",
            tactic=Tactic.PRIVILEGE_ESCALATION,
            description="Adversaries inject malicious code into running processes to evade defenses and escalate privileges.",
            ctipearl="Process injection is so prevalent it's almost a requirement for any sophisticated malware. CTI tracks injection methods (DLL injection, process hollowing, reflective loading) as tradecraft fingerprints. The method used narrows down the toolkit and potentially the actor.",
            detection_tips=[
                "Monitor cross-process WriteProcessMemory and VirtualAllocEx calls",
                "Alert on CreateRemoteThread into non-standard processes",
                "Track process hollowing: process creation followed by memory section replacement",
                "Use Sysmon Event IDs 8 (CreateRemoteThread) and 10 (ProcessAccess)",
            ],
            data_sources=["EDR process telemetry", "Sysmon", "Memory forensics", "API monitoring"],
            mitigations=["Exploit Guard memory protections", "EMET", "Credential Guard", "Behavior-based EDR"],
            apt_examples=["Cobalt Strike", "APT28", "APT29", "Turla"],
            difficulty="High",
        ),
        Technique(
            id="T1134",
            name="Access Token Manipulation",
            tactic=Tactic.PRIVILEGE_ESCALATION,
            description="Adversaries manipulate access tokens to operate under different user or system security contexts.",
            ctipearl="Token impersonation allows attackers to act as SYSTEM without a full privilege escalation exploit. CTI tracks token manipulation as a post-exploitation behavior — its presence in an incident indicates the attacker is actively working to elevate access.",
            detection_tips=[
                "Monitor for SeImpersonatePrivilege abuse (Potato attacks)",
                "Track token duplication from high-privilege processes",
                "Alert on processes running under accounts inconsistent with their parent",
                "Watch for CreateProcessWithTokenW called by non-SYSTEM processes",
            ],
            data_sources=["Windows Security logs (Event 4624, 4648)", "EDR telemetry", "Sysmon"],
            mitigations=["Least privilege", "Credential Guard", "Privileged access workstations", "Token restriction policies"],
            apt_examples=["Cobalt Strike", "Meterpreter", "APT41", "FIN6"],
            difficulty="High",
        ),

        # ── Defense Evasion ──────────────────────────────────────────────
        Technique(
            id="T1562",
            name="Impair Defenses",
            tactic=Tactic.DEFENSE_EVASION,
            description="Adversaries disable or modify security tools to avoid detection, including AV, EDR, and audit policies.",
            ctipearl="Defense impairment is a 'crown jewel' indicator — if an attacker disables your defenses, they plan to do something your defenses would catch. CTI treats tamper detection alerts as high-priority indicators of an active intrusion in progress.",
            detection_tips=[
                "Monitor for security tool service stops or uninstalls",
                "Alert on Windows Defender exclusion additions",
                "Track audit policy changes (Event IDs 4719, 4907)",
                "Watch for tamper protection bypass attempts in EDR telemetry",
            ],
            data_sources=["Windows Security logs", "EDR tamper detection", "Sysmon", "Audit policy logs"],
            mitigations=["Tamper protection for EDR", "Centralized logging", "Immutable audit policies", "Privileged access controls"],
            apt_examples=["Ryuk", "Conti", "BlackCat/ALPHV", "LockBit"],
            difficulty="Medium",
        ),
        Technique(
            id="T1036",
            name="Masquerading",
            tactic=Tactic.DEFENSE_EVASION,
            description="Adversaries manipulate file names, paths, or binary metadata to appear legitimate.",
            ctipearl="Masquerading exploits cognitive bias — analysts see 'svchost.exe' and assume legitimacy. CTI documents common masquerade names per threat actor. Process path is the tell: svchost.exe from Temp is not legitimate.",
            detection_tips=[
                "Alert on known system binaries running from non-standard paths",
                "Check executable metadata (publisher, version info) against expected values",
                "Monitor for processes with parent-child relationships inconsistent with name",
                "Track executables with mismatched file extensions",
            ],
            data_sources=["Process monitoring", "File system monitoring", "EDR", "Sysmon Event ID 1"],
            mitigations=["Binary signing enforcement", "Application whitelisting", "Behavioral EDR", "File integrity monitoring"],
            apt_examples=["APT32", "Lazarus Group", "Turla", "FIN7"],
            difficulty="Low",
        ),
        Technique(
            id="T1218",
            name="System Binary Proxy Execution (LOLBins)",
            tactic=Tactic.DEFENSE_EVASION,
            description="Adversaries use trusted Windows binaries to proxy execution of malicious code, bypassing application controls.",
            ctipearl="LOLBins (Living-Off-the-Land Binaries) are the ultimate defense evasion: using Microsoft's own trusted, signed tools against defenders. CTI tracks LOLBAS (lolbas-project.github.io) as an essential reference for detection engineering.",
            detection_tips=[
                "Monitor mshta.exe, certutil.exe, regsvr32.exe spawning child processes",
                "Alert on rundll32.exe executing non-DLL file extensions",
                "Track certutil.exe with -decode or -urlcache flags",
                "Watch wscript.exe and cscript.exe executing from unusual locations",
            ],
            data_sources=["Process monitoring", "Command-line logging", "EDR", "Sysmon"],
            mitigations=["AppLocker rules for LOLBins", "PowerShell Constrained Language Mode", "Application control policies"],
            apt_examples=["APT28", "Kimsuky", "TA505", "Mustang Panda"],
            difficulty="Medium",
        ),

        # ── Credential Access ────────────────────────────────────────────
        Technique(
            id="T1110",
            name="Brute Force",
            tactic=Tactic.CREDENTIAL_ACCESS,
            description="Adversaries use brute force techniques including password spraying and credential stuffing to gain access.",
            ctipearl="Password spraying (few passwords across many accounts) evades lockout policies that trigger on many attempts to one account. CTI shares spray patterns — timing, user agent strings, source IP ranges — to help organizations distinguish attack waves from legitimate authentication.",
            detection_tips=[
                "Alert on multiple failed logins across many accounts from one source (spraying)",
                "Monitor for authentication from known bad IP ranges",
                "Track unusual authentication protocols (NTLM where Kerberos expected)",
                "Correlate with credential breach intelligence for stuffing attacks",
            ],
            data_sources=["Authentication logs", "Azure AD logs", "SIEM", "Identity protection"],
            mitigations=["MFA", "Account lockout policies", "Smart lockout (Azure AD)", "Conditional access"],
            apt_examples=["APT28 (Fancy Bear)", "Cozy Bear", "Scattered Spider", "Iranian APTs"],
            difficulty="Low",
        ),
        Technique(
            id="T1558",
            name="Steal or Forge Kerberos Tickets",
            tactic=Tactic.CREDENTIAL_ACCESS,
            description="Adversaries steal or forge Kerberos tickets to gain access to resources without knowing account passwords.",
            ctipearl="Kerberoasting and Pass-the-Ticket are stealthy because they abuse legitimate Kerberos operations. CTI tracks tools used for these techniques (known by generic names in reports) and their associated OPSEC mistakes — timestamp anomalies, unusual encryption types, and service account abuse.",
            detection_tips=[
                "Monitor for RC4 (0x17) encryption type in TGS requests for AES-enabled accounts",
                "Alert on abnormal TGT lifetimes or renewable ticket flags",
                "Track accounts requesting tickets for services they never normally access",
                "Monitor Event ID 4769 for suspicious service ticket requests",
            ],
            data_sources=["Windows Security logs (4768, 4769, 4771)", "Domain controller logs", "EDR"],
            mitigations=["AES encryption enforcement", "Long/complex service account passwords", "Managed service accounts", "Privileged access tiers"],
            apt_examples=["APT29", "FIN6", "Wizard Spider", "Turla"],
            difficulty="High",
        ),

        # ── Discovery ────────────────────────────────────────────────────
        Technique(
            id="T1087",
            name="Account Discovery",
            tactic=Tactic.DISCOVERY,
            description="Adversaries enumerate user and service accounts to identify privileged targets for lateral movement.",
            ctipearl="Account discovery is the attacker mapping the human terrain. CTI analysts look for LDAP enumeration queries, net user commands, and BloodHound/SharpHound collection as indicators of pre-lateral-movement reconnaissance.",
            detection_tips=[
                "Monitor net user/group commands and their LDAP equivalents",
                "Alert on LDAP queries returning large result sets from non-admin systems",
                "Track BloodHound collection artifacts (specific LDAP queries)",
                "Watch for PowerShell Active Directory module usage from unusual hosts",
            ],
            data_sources=["Windows Security logs (4661, 4662)", "LDAP monitoring", "Command-line logs", "EDR"],
            mitigations=["LDAP query restrictions", "Tiered Active Directory", "Just-in-time access", "Honeypot accounts"],
            apt_examples=["APT29", "Conti", "BlackCat", "FIN6"],
            difficulty="Low",
        ),
        Technique(
            id="T1482",
            name="Domain Trust Discovery",
            tactic=Tactic.DISCOVERY,
            description="Adversaries enumerate Active Directory domain and forest trusts to identify pathways for lateral movement.",
            ctipearl="Domain trust enumeration is a pre-cursor to cross-domain attacks. CTI analysts use it as a high-confidence indicator of sophisticated actors targeting AD forests — commodity malware rarely bothers with trust enumeration.",
            detection_tips=[
                "Monitor for nltest /domain_trusts command execution",
                "Alert on Get-ADTrust PowerShell cmdlet usage",
                "Track LDAP queries for trustedDomain objects",
                "Watch for unusual processes querying DC for trust information",
            ],
            data_sources=["Command-line monitoring", "Windows Security logs", "LDAP monitoring"],
            mitigations=["Selective authentication on trusts", "SID filtering", "Privileged access workstations"],
            apt_examples=["APT29", "Sandworm", "LockBit", "Conti"],
            difficulty="High",
        ),

        # ── Lateral Movement ─────────────────────────────────────────────
        Technique(
            id="T1021",
            name="Remote Services",
            tactic=Tactic.LATERAL_MOVEMENT,
            description="Adversaries use valid credentials to log into remote services such as RDP, SMB, SSH, and VNC.",
            ctipearl="RDP is the #1 lateral movement vector in ransomware incidents — often via stolen credentials or brute force on exposed RDP ports. CTI tracks which APT groups favor which remote services. Unusual internal RDP sessions are a key detection signal.",
            detection_tips=[
                "Monitor for internal RDP sessions between workstations (unusual)",
                "Alert on RDP logins outside business hours or from unusual sources",
                "Track SMB lateral movement patterns (Event ID 4624 type 3)",
                "Correlate remote service logins with credential theft artifacts",
            ],
            data_sources=["Windows Security logs (4624, 4625, 4648)", "RDP logs", "Network flow", "EDR"],
            mitigations=["Network segmentation", "RDP gateway", "MFA for remote access", "Just-in-time VM access"],
            apt_examples=["Ryuk", "Conti", "APT29", "Scattered Spider"],
            difficulty="Low",
        ),
        Technique(
            id="T1550",
            name="Use Alternate Authentication Material",
            tactic=Tactic.LATERAL_MOVEMENT,
            description="Adversaries use stolen credential material (hashes, tickets, tokens) to authenticate without knowing plaintext passwords.",
            ctipearl="Pass-the-Hash and Pass-the-Ticket attacks are the post-credential-dump follow-on. CTI tracks them together with credential dumping events — the time between dump and use reveals attacker dwell time and speed of operation.",
            detection_tips=[
                "Alert on NTLM authentication from hosts that normally use Kerberos",
                "Monitor for Kerberos ticket use from different source IPs than ticket request",
                "Track authentication with NTLM v1 (should be disabled in modern environments)",
                "Correlate pass-the-hash indicators with credential access events",
            ],
            data_sources=["Windows Security logs", "NTLM logs", "Kerberos logs", "EDR"],
            mitigations=["Credential Guard", "Disable NTLM where possible", "Protected Users security group", "PAM solutions"],
            apt_examples=["APT28", "Sandworm", "FIN6", "Turla"],
            difficulty="High",
        ),

        # ── Collection ───────────────────────────────────────────────────
        Technique(
            id="T1005",
            name="Data from Local System",
            tactic=Tactic.COLLECTION,
            description="Adversaries search local system sources to collect data of interest prior to exfiltration.",
            ctipearl="Collection targeting reveals actor intent. Are they after specific file types (.docx, .pdf, source code)? Specific directories (HR, Finance)? CTI uses collection patterns to validate attribution — different APT groups have distinct collection profiles.",
            detection_tips=[
                "Monitor for bulk file access to sensitive directories",
                "Alert on unusual archive creation (7-zip, RAR) of sensitive files",
                "Track access to document repositories by non-standard processes",
                "Watch for file staging in unusual locations (Temp, ProgramData)",
            ],
            data_sources=["File system monitoring", "DLP", "EDR file telemetry", "User behavior analytics"],
            mitigations=["Data classification", "DLP policies", "Access controls", "Encryption at rest"],
            apt_examples=["APT10", "APT41", "APT28", "Lazarus Group"],
            difficulty="Low",
        ),
        Technique(
            id="T1114",
            name="Email Collection",
            tactic=Tactic.COLLECTION,
            description="Adversaries target email to collect sensitive information and credentials from mailboxes.",
            ctipearl="Email collection is a BEC and espionage staple. Attackers with Exchange access can silently forward every email to an external address. CTI tracks mailbox exfiltration rules as indicators — they often persist for months before discovery.",
            detection_tips=[
                "Monitor for new Outlook forwarding rules to external addresses",
                "Alert on Exchange PowerShell cmdlets accessing multiple mailboxes",
                "Track Graph API applications with Mail.Read permissions",
                "Watch for PST export operations on Exchange",
            ],
            data_sources=["Exchange/O365 audit logs", "Email gateway", "Microsoft 365 Defender", "CASB"],
            mitigations=["Disable auto-forwarding to external domains", "Conditional access for email APIs", "MFA on email accounts"],
            apt_examples=["APT29", "Hafnium", "APT32", "Kimsuky"],
            difficulty="Medium",
        ),

        # ── Command and Control ──────────────────────────────────────────
        Technique(
            id="T1573",
            name="Encrypted Channel",
            tactic=Tactic.COMMAND_AND_CONTROL,
            description="Adversaries encrypt C2 communications to hide the content and evade network detection.",
            ctipearl="TLS is the attacker's best friend — most orgs cannot decrypt it. CTI focuses on JA3/JA3S fingerprints (TLS client/server fingerprints) to identify C2 tools even in encrypted traffic. Cobalt Strike has distinctive JA3 signatures.",
            detection_tips=[
                "Monitor JA3/JA3S fingerprints against known C2 frameworks",
                "Analyze certificate metadata: self-signed, short validity, suspicious Subject fields",
                "Track TLS connections to domains registered < 30 days",
                "Look for beaconing patterns in encrypted traffic (regular intervals)",
            ],
            data_sources=["Network flow", "TLS inspection logs", "DNS logs", "Threat intel feeds"],
            mitigations=["TLS inspection where legal", "DNS monitoring", "Network behavioral analytics", "Zero-trust network access"],
            apt_examples=["APT29", "Cobalt Strike users", "APT41", "Turla"],
            difficulty="High",
        ),
        Technique(
            id="T1090",
            name="Proxy",
            tactic=Tactic.COMMAND_AND_CONTROL,
            description="Adversaries use proxies to route C2 communications through intermediary systems to obscure their true origin.",
            ctipearl="Multi-hop proxies and bulletproof hosting make attribution hard. CTI maps the proxy infrastructure layers — identifying relay nodes vs. true C2 endpoints. Tor exit nodes, residential proxies, and compromised routers are common relay choices.",
            detection_tips=[
                "Monitor for connections to known Tor exit nodes",
                "Alert on traffic through residential proxy ASNs",
                "Track DNS-over-HTTPS bypassing your DNS resolver",
                "Detect multi-hop VPN combinations used for OPSEC",
            ],
            data_sources=["Network flow", "Firewall logs", "DNS logs", "Proxy logs"],
            mitigations=["Block known Tor exit nodes", "DNS filtering", "Network egress filtering", "Threat intel feed integration"],
            apt_examples=["APT28", "APT29", "Lazarus Group", "Sandworm"],
            difficulty="Medium",
        ),

        # ── Exfiltration ─────────────────────────────────────────────────
        Technique(
            id="T1048",
            name="Exfiltration Over Alternative Protocol",
            tactic=Tactic.EXFILTRATION,
            description="Adversaries exfiltrate data using protocols other than the C2 channel, such as DNS, ICMP, or cloud services.",
            ctipearl="DNS exfiltration is often invisible to orgs that don't monitor DNS logs. Hundreds of megabytes can be exfiltrated by encoding data in DNS query subdomains. CTI tracks DNS tunnel characteristics (query length distribution, entropy, request frequency) for detection.",
            detection_tips=[
                "Monitor for unusually long DNS query names (> 40 chars in subdomain)",
                "Alert on high-frequency DNS queries to a single external domain",
                "Track ICMP packets with large or unusual payloads",
                "Watch for cloud storage uploads from endpoint processes",
            ],
            data_sources=["DNS logs", "Network flow", "ICMP monitoring", "Cloud access logs"],
            mitigations=["DNS monitoring and filtering", "Block outbound ICMP", "DLP", "Cloud egress controls"],
            apt_examples=["APT34 (OilRig)", "Turla", "APT32", "Cobalt Strike DNS beacon"],
            difficulty="High",
        ),

        # ── Impact ───────────────────────────────────────────────────────
        Technique(
            id="T1490",
            name="Inhibit System Recovery",
            tactic=Tactic.IMPACT,
            description="Adversaries delete or disable system recovery features to maximize impact of destructive attacks.",
            ctipearl="Volume Shadow Copy deletion is an almost universal ransomware behavior — so common it's a near-perfect indicator. CTI tracks this command sequence as a high-confidence ransomware pre-encryption signal. When you see it, the clock is ticking.",
            detection_tips=[
                "Alert on vssadmin.exe delete shadows immediately",
                "Monitor wmic shadowcopy delete commands",
                "Track bcdedit.exe changes to recovery settings",
                "Watch for wbadmin delete catalog commands",
            ],
            data_sources=["Command-line monitoring", "Windows Security logs", "EDR", "Sysmon"],
            mitigations=["Immutable backups (3-2-1 rule)", "Offsite/offline backups", "VSS protection policies", "EDR behavioral rules"],
            apt_examples=["Conti", "REvil", "LockBit", "BlackCat/ALPHV", "Ryuk"],
            difficulty="Low",
        ),
        Technique(
            id="T1485",
            name="Data Destruction",
            tactic=Tactic.IMPACT,
            description="Adversaries destroy data and files on specific systems to interrupt availability or cover tracks.",
            ctipearl="Destructive malware (NotPetya, WhisperGate, HermeticWiper) is a geopolitical instrument as much as a cyber one. CTI tracks wiper malware as a distinct family with national nexus — different from ransomware despite similar initial TTPs.",
            detection_tips=[
                "Monitor for bulk file deletion or overwrite operations",
                "Alert on MBR/boot sector modification",
                "Track kernel-mode drivers loading from unusual paths (wiper signature)",
                "Watch for file overwrite with null bytes or random data at scale",
            ],
            data_sources=["File system monitoring", "EDR", "Windows Security logs", "Kernel driver monitoring"],
            mitigations=["Immutable backups", "File integrity monitoring", "Application control", "Kernel driver signing enforcement"],
            apt_examples=["Sandworm (NotPetya)", "APT37 (WhisperGate)", "Lazarus Group", "Iranian APTs"],
            difficulty="High",
        ),
    ]
    
    TACTIC_INFO: Dict[Tactic, Dict] = {
        Tactic.RECONNAISSANCE: {
            "name": "Reconnaissance",
            "description": "Gathering information to target the victim.",
            "ctipearl": "Reconnaissance is where CTI can get ahead. Monitoring for your organization's name on dark web markets, paste sites, and in certificate transparency logs can reveal targeting before the attack."
        },
        Tactic.RESOURCE_DEVELOPMENT: {
            "name": "Resource Development",
            "description": "Establishing resources to support operations.",
            "ctipearl": "Track infrastructure before it's used. Domain registration patterns, certificate issuance, and malware staging sites often precede attacks by days or weeks."
        },
        Tactic.INITIAL_ACCESS: {
            "name": "Initial Access",
            "description": "Gaining an initial foothold in the victim environment.",
            "ctipearl": "The entry point. CTI prioritizes understanding phishing lures, exploit kit landing pages, and supply chain compromises affecting your industry sector."
        },
        Tactic.EXECUTION: {
            "name": "Execution",
            "description": "Running adversary-controlled code.",
            "ctipearl": "Living off the land is the trend. CTI catalogs which built-in tools are abused by which groups, enabling behavior-based detection rather than IOC matching."
        },
        Tactic.PERSISTENCE: {
            "name": "Persistence",
            "description": "Maintaining access across restarts and credential changes.",
            "ctipearl": "Persistence mechanisms are consistent. Once an APT technique for persistence is published, it gets reused. CTI tracks these 'tradecraft recipes.'"
        },
        Tactic.PRIVILEGE_ESCALATION: {
            "name": "Privilege Escalation",
            "description": "Gaining higher-level permissions.",
            "ctipearl": "Local privilege escalation (LPE) exploits are commodities. CTI tracks which CVEs have public LPE exploits and which APT groups are known to use them."
        },
        Tactic.DEFENSE_EVASION: {
            "name": "Defense Evasion",
            "description": "Avoiding detection throughout the attack.",
            "ctipearl": "The most creative MITRE tactic. CTI analysts study anti-forensics, packing, and rootkit techniques to understand the sophistication level of a threat actor."
        },
        Tactic.CREDENTIAL_ACCESS: {
            "name": "Credential Access",
            "description": "Stealing credentials to access resources.",
            "ctipearl": "Credentials are the currency of the realm. CTI tracks credential stuffing lists, leaked databases, and the tools used for hash extraction and cracking."
        },
        Tactic.DISCOVERY: {
            "name": "Discovery",
            "description": "Identifying system and network resources.",
            "ctipearl": "Discovery creates the most detectable noise. CTI helps build baselines so anomaly detection can spot the unusual enumeration patterns that precede lateral movement."
        },
        Tactic.LATERAL_MOVEMENT: {
            "name": "Lateral Movement",
            "description": "Moving through the victim environment.",
            "ctipearl": "Lateral movement reveals the attacker's intent. Are they after specific systems? Domain admin? CTI maps common lateral movement paths to network segmentation strategies."
        },
        Tactic.COLLECTION: {
            "name": "Collection",
            "description": "Gathering data of interest.",
            "ctipearl": "Collection targets are specific: source code, customer databases, emails. CTI tracks what different APT groups collect to predict their targets and protect crown jewels."
        },
        Tactic.COMMAND_AND_CONTROL: {
            "name": "Command and Control",
            "description": "Communicating with compromised systems.",
            "ctipearl": "C2 infrastructure is the attacker's lifeline. CTI excels at mapping C2 domains, IP ranges, and protocols to proactively block beacons before data is stolen."
        },
        Tactic.EXFILTRATION: {
            "name": "Exfiltration",
            "description": "Stealing data from the victim network.",
            "ctipearl": "Exfiltration is the endgame. CTI tracks the staging behaviors: compression, encryption, renaming. Understanding the attacker's exfiltration preference helps DLP tuning."
        },
        Tactic.IMPACT: {
            "name": "Impact",
            "description": "Disrupting availability or integrity.",
            "ctipearl": "Ransomware and wipers get the headlines. CTI tracks affiliate programs, access brokers, and the TTPs that precede impact to stop encryption before it starts."
        },
    }
    
    def __init__(self):
        """Initialize the MITRE engine."""
        self._technique_index = {t.id: t for t in self.TECHNIQUES}
        self._tactic_techniques: Dict[Tactic, List[Technique]] = {}
        for tactic in Tactic:
            self._tactic_techniques[tactic] = [
                t for t in self.TECHNIQUES if t.tactic == tactic
            ]
    
    def get_technique(self, technique_id: str) -> Optional[Technique]:
        """Get technique by MITRE ID."""
        if not isinstance(technique_id, str) or not technique_id:
            return None
        # Sanitize input
        technique_id = technique_id.strip().upper()
        return self._technique_index.get(technique_id)
    
    def get_tactic_techniques(self, tactic: Tactic) -> List[Technique]:
        """Get all techniques for a tactic."""
        return self._tactic_techniques.get(tactic, [])
    
    def get_tactic_info(self, tactic: Tactic) -> Dict:
        """Get educational info for a tactic."""
        return self.TACTIC_INFO.get(tactic, {})
    
    def search_techniques(self, query: str) -> List[Technique]:
        """Search techniques by name or description."""
        if not isinstance(query, str) or not query:
            return []
        query = query.lower()
        results = []
        for tech in self.TECHNIQUES:
            if (query in tech.name.lower() or 
                query in tech.description.lower() or
                query in tech.id.lower() or
                any(query in apt.lower() for apt in tech.apt_examples)):
                results.append(tech)
        return results
    
    def get_all_tactics(self) -> List[Dict]:
        """Get all tactics with summaries."""
        tactics = []
        for tactic in Tactic:
            info = self.TACTIC_INFO.get(tactic, {})
            tech_count = len(self._tactic_techniques.get(tactic, []))
            tactics.append({
                "id": tactic.value,
                "name": info.get("name", tactic.name),
                "description": info.get("description", ""),
                "ctipearl": info.get("ctipearl", ""),
                "technique_count": tech_count
            })
        return tactics
    
    def get_difficulty_path(self, difficulty: str) -> List[Technique]:
        """Get techniques filtered by learning difficulty."""
        return [t for t in self.TECHNIQUES if t.difficulty == difficulty]
