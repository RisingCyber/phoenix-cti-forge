"""
Phoenix CTI Forge - Educational Module
Created by Australian Phoenix CyberOps

FORMAT RULES (critical for JS rendering):
  - options: plain text only, NO letter prefixes (JS adds "A. B. C. D.")
  - correct_answer: single letter "A", "B", "C", or "D"
  - True/False: options=["True","False"], correct_answer="A"(True) or "B"(False)
"""
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
import random


class QuestionType(Enum):
    MULTIPLE_CHOICE = "multiple_choice"
    TRUE_FALSE = "true_false"
    SCENARIO = "scenario"
    IDENTIFICATION = "identification"


@dataclass
class QuizQuestion:
    question: str
    question_type: QuestionType
    options: List[str]
    correct_answer: str
    explanation: str
    category: str
    difficulty: str


class TrainingModule:
    QUESTIONS: List[QuizQuestion] = [

        # ── CTI Fundamentals ──────────────────────────────────────────
        QuizQuestion(
            question="What does the Diamond Model of Intrusion Analysis primarily describe?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "The four phases of malware execution",
                "Four core features: Adversary, Infrastructure, Capability, and Victim",
                "The four layers of the TCP/IP stack",
                "Four types of encryption algorithms used in malware",
            ],
            correct_answer="B",
            explanation=(
                "The Diamond Model describes four connected features: Adversary (who), "
                "Infrastructure (where), Capability (how), and Victim (target). CTI analysts "
                "use this to pivot between indicators and build context around an intrusion. "
                "Each event is a complete diamond; campaigns link multiple events."
            ),
            category="CTI Fundamentals",
            difficulty="Easy",
        ),
        QuizQuestion(
            question="What is the primary difference between Strategic and Tactical threat intelligence?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "Strategic is automated; Tactical is manual",
                "Strategic focuses on high-level trends and actor intent; Tactical provides specific IOCs and TTPs",
                "Strategic is classified; Tactical is always public",
                "There is no meaningful difference between them",
            ],
            correct_answer="B",
            explanation=(
                "Strategic intelligence informs long-term decisions (actor motivations, "
                "geopolitical context). Tactical intelligence is immediately actionable "
                "(IP blocks, hash bans, YARA rules). Operational intelligence sits between "
                "them, describing specific campaigns and actor behaviors."
            ),
            category="CTI Fundamentals",
            difficulty="Easy",
        ),
        QuizQuestion(
            question="In CTI, what is an IOC?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "Indicator of Compromise — observable forensic evidence of a potential intrusion",
                "International Operational Center — a global threat intelligence body",
                "Intelligence Oversight Committee — a governance body",
                "Integrated Operations Console — a SIEM dashboard component",
            ],
            correct_answer="A",
            explanation=(
                "Indicator of Compromise (IOC) is forensic evidence of intrusion: "
                "malicious IPs, file hashes, registry keys, or URLs. Unlike IOAs "
                "(Indicators of Attack) which show active behavior, IOCs are historical "
                "artifacts. IOCs are considered 'reactive' intelligence."
            ),
            category="CTI Fundamentals",
            difficulty="Easy",
        ),
        QuizQuestion(
            question="What is Lockheed Martin's Cyber Kill Chain?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "A CVSS-ordered list of exploitable vulnerabilities",
                "A 7-stage intrusion model: Recon, Weaponize, Deliver, Exploit, Install, C2, Act on Objectives",
                "A chain of command structure inside cybercrime organizations",
                "A cryptographic hash chain used in blockchain technology",
            ],
            correct_answer="B",
            explanation=(
                "The Cyber Kill Chain describes seven stages of a cyber intrusion. "
                "CTI uses it to identify where detection or prevention can break the "
                "chain. MITRE ATT&CK later expanded this into 14 tactics and hundreds "
                "of specific techniques for more granular, actionable threat mapping."
            ),
            category="CTI Fundamentals",
            difficulty="Easy",
        ),
        QuizQuestion(
            question="True or False: Threat intelligence should always be shared as widely as possible to maximize defensive value.",
            question_type=QuestionType.TRUE_FALSE,
            options=["True", "False"],
            correct_answer="B",
            explanation=(
                "False. Intel must be shared responsibly using the Traffic Light Protocol "
                "(TLP). Some intelligence is sensitive, contains victim data, or could tip "
                "off threat actors if over-shared. TLP labels (RED, AMBER, GREEN, CLEAR/WHITE) "
                "govern distribution to protect sources and methods."
            ),
            category="CTI Fundamentals",
            difficulty="Medium",
        ),
        QuizQuestion(
            question="What does the 'feedback' step of the intelligence cycle accomplish?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "Analysts resolve attribution disputes through peer review",
                "Operational outcomes refine collection and analysis requirements for the next cycle",
                "Threat feeds are automatically tuned by machine learning algorithms",
                "SIEMs generate automated performance summaries for leadership",
            ],
            correct_answer="B",
            explanation=(
                "The intelligence cycle (direction, collection, processing, analysis, "
                "dissemination, feedback) uses feedback to improve future cycles. "
                "If intelligence didn't help prevent an attack, requirements must change. "
                "CTI programs are only as effective as how well they act on feedback."
            ),
            category="CTI Fundamentals",
            difficulty="Medium",
        ),

        # ── IOC Analysis ──────────────────────────────────────────────
        QuizQuestion(
            question="A SHA256 hash is how many hexadecimal characters long?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=["32 characters", "40 characters", "64 characters", "128 characters"],
            correct_answer="C",
            explanation=(
                "SHA256 produces a 256-bit (32-byte) digest rendered as 64 hex characters. "
                "MD5 = 32 chars (128-bit). SHA1 = 40 chars (160-bit). "
                "SHA256 is the current CTI standard for file identification because "
                "MD5 and SHA1 have known collision vulnerabilities."
            ),
            category="IOC Analysis",
            difficulty="Easy",
        ),
        QuizQuestion(
            question="Why are file hashes considered 'fragile indicators' in isolation?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "They are too long to share in threat reports efficiently",
                "They change with every minor file modification and are trivially altered by attackers",
                "They are illegal to collect without a warrant in most countries",
                "They cannot be stored in standard security databases",
            ],
            correct_answer="B",
            explanation=(
                "File hashes are brittle — one bit change creates a completely different hash. "
                "Attackers routinely recompile or repack malware to change hashes. "
                "CTI prefers behavioral indicators (TTPs, YARA rules, ATT&CK mappings) "
                "that persist across malware variants."
            ),
            category="IOC Analysis",
            difficulty="Medium",
        ),
        QuizQuestion(
            question="What is a Domain Generation Algorithm (DGA)?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "A Data Governance Act — an EU regulation covering DNS registrars",
                "An algorithm malware uses to generate pseudo-random C2 domain names",
                "A Digital Gateway Appliance — a type of network security proxy",
                "A Dynamic Group Authorization — an Active Directory feature",
            ],
            correct_answer="B",
            explanation=(
                "DGAs create pseudo-random domain names for C2 communication. "
                "Both the attacker and malware use the same algorithm and seed, "
                "making blocking individual domains ineffective. CTI analysts "
                "reverse-engineer DGAs to predict future domains and sinkhole them."
            ),
            category="IOC Analysis",
            difficulty="Medium",
        ),
        QuizQuestion(
            question="What does 'defanging' an IOC mean in CTI reporting?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "Permanently blocking the IOC in your perimeter firewall",
                "Modifying the IOC so it cannot be accidentally clicked or executed when shared",
                "Removing an expired IOC from active threat intelligence feeds",
                "Encrypting the IOC value for secure database storage",
            ],
            correct_answer="B",
            explanation=(
                "Defanging modifies IOCs so they cannot accidentally activate: "
                "replace '.' with '[.]', '@' with '[@]', 'http' with 'hxxp'. "
                "This is critical when sharing IOCs via email, Slack, or reports "
                "where links auto-activate. Always defang before sharing, "
                "always re-fang before analysis tools. Phoenix CTI Forge automates this."
            ),
            category="IOC Analysis",
            difficulty="Easy",
        ),
        QuizQuestion(
            question="Which of the following is a correctly defanged URL?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "http://c2-example.test/loader.bin",
                "hxxp://c2-example[.]test/loader[.]bin",
                "http://c2-example[evil]test/loader.bin",
                "http_c2-example.test_loader.bin",
            ],
            correct_answer="B",
            explanation=(
                "The correct defanged form replaces 'http' with 'hxxp' and '.' with '[.]'. "
                "Option A is not defanged at all. Option C uses wrong bracket structure. "
                "Option D is not a valid defang format. Accepted formats also include "
                "[dot] and (dot) for dots, [at] and (at) for @ symbols."
            ),
            category="IOC Analysis",
            difficulty="Easy",
        ),
        QuizQuestion(
            question="True or False: IPv6 addresses can be used as C2 channels and are worth monitoring even in predominantly IPv4 environments.",
            question_type=QuestionType.TRUE_FALSE,
            options=["True", "False"],
            correct_answer="A",
            explanation=(
                "True. Threat actors increasingly use IPv6 for C2 precisely because "
                "many organizations do not monitor IPv6 traffic, creating a blind spot. "
                "Techniques like IPv6-over-IPv4 tunneling (Teredo, 6to4) can bypass "
                "IPv4-only firewalls. Ensure sensors capture both IPv4 and IPv6 traffic."
            ),
            category="IOC Analysis",
            difficulty="Medium",
        ),

        # ── MITRE ATT&CK ──────────────────────────────────────────────
        QuizQuestion(
            question="MITRE ATT&CK technique T1059 falls under which tactic?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "Initial Access (TA0001)",
                "Execution (TA0002)",
                "Persistence (TA0003)",
                "Credential Access (TA0006)",
            ],
            correct_answer="B",
            explanation=(
                "T1059 is 'Command and Scripting Interpreter' — Execution tactic (TA0002). "
                "Sub-techniques: T1059.001 (PowerShell), T1059.003 (Windows Command Shell), "
                "T1059.005 (Visual Basic). Adversaries abuse these interpreters to run "
                "malicious code on victim systems while blending with normal admin activity."
            ),
            category="MITRE ATT&CK",
            difficulty="Medium",
        ),
        QuizQuestion(
            question="What is the key difference between a MITRE ATT&CK technique and a sub-technique?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "Techniques are legacy entries; sub-techniques are newer and more reliable",
                "Techniques are broad behaviors; sub-techniques are specific implementation variants",
                "Techniques apply to APT groups; sub-techniques apply to ransomware only",
                "There is no meaningful difference between them",
            ],
            correct_answer="B",
            explanation=(
                "Techniques are broad behaviors (e.g., T1053 Scheduled Task/Job). "
                "Sub-techniques are specific variants (e.g., T1053.005 Windows Task Scheduler). "
                "This granularity enables precise detection engineering and accurate "
                "threat actor profiling when writing CTI reports."
            ),
            category="MITRE ATT&CK",
            difficulty="Medium",
        ),
        QuizQuestion(
            question="True or False: MITRE ATT&CK is exclusively a detection engineering framework with no application to threat intelligence.",
            question_type=QuestionType.TRUE_FALSE,
            options=["True", "False"],
            correct_answer="B",
            explanation=(
                "False. ATT&CK serves both detection and CTI. Analysts use it to describe "
                "threat actor behavior, compare group TTPs, build actor profiles, map "
                "campaigns, and identify detection coverage gaps. It bridges threat "
                "intelligence and detection engineering in a single shared language."
            ),
            category="MITRE ATT&CK",
            difficulty="Hard",
        ),
        QuizQuestion(
            question="Which ATT&CK tactic covers techniques adversaries use to avoid detection?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "Execution (TA0002)",
                "Persistence (TA0003)",
                "Defense Evasion (TA0005)",
                "Collection (TA0009)",
            ],
            correct_answer="C",
            explanation=(
                "Defense Evasion (TA0005) covers disabling security tools, obfuscating code, "
                "clearing logs, and living off the land (LOLBins). It contains the most "
                "techniques in all of ATT&CK, reflecting how much effort adversaries invest "
                "in staying hidden on compromised systems."
            ),
            category="MITRE ATT&CK",
            difficulty="Easy",
        ),
        QuizQuestion(
            question="What does the ATT&CK tactic 'Lateral Movement' (TA0008) describe?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "Moving files between folders on a compromised endpoint",
                "Techniques adversaries use to pivot through a network to reach target systems",
                "Rotating C2 infrastructure to evade threat intelligence",
                "Exfiltrating data through multiple hops to obscure origin",
            ],
            correct_answer="B",
            explanation=(
                "Lateral Movement covers techniques like RDP (T1021.001), SMB shares "
                "(T1021.002), Pass-the-Hash (T1550.002), and WMI (T1047) that adversaries "
                "use to expand access from an initial foothold across the network toward "
                "high-value targets such as domain controllers and data repositories."
            ),
            category="MITRE ATT&CK",
            difficulty="Easy",
        ),

        # ── Threat Intelligence Sources ────────────────────────────────
        QuizQuestion(
            question="What is an ISAC in the context of threat intelligence sharing?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "International Security Assessment Certificate",
                "Information Sharing and Analysis Center — sector-specific trusted threat intel sharing",
                "Integrated Security Access Control — a network gatekeeping mechanism",
                "Intelligence Surveillance and Collection — a government program",
            ],
            correct_answer="B",
            explanation=(
                "ISACs facilitate sector-specific trusted threat sharing. Examples: "
                "FS-ISAC (financial services), MS-ISAC (state/local government), "
                "H-ISAC (healthcare), AV-ISAC (aviation). They provide vetted "
                "intelligence under TLP protocols and are a primary high-quality source."
            ),
            category="Threat Intelligence Sources",
            difficulty="Easy",
        ),
        QuizQuestion(
            question="What is the primary risk of using OSINT for CTI without validation?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "OSINT is always illegal to collect and act upon",
                "Information may be unverified, outdated, or deliberately planted as disinformation",
                "OSINT always requires expensive commercial subscriptions",
                "OSINT cannot technically contain actionable technical indicators",
            ],
            correct_answer="B",
            explanation=(
                "OSINT is powerful but unvetted. Sophisticated actors deliberately seed "
                "false information to mislead defenders (disinformation campaigns). "
                "Validate OSINT through multiple independent sources, assess source "
                "reputation with the Admiralty Scale, and corroborate technical claims "
                "before blocking production assets based on them."
            ),
            category="Threat Intelligence Sources",
            difficulty="Medium",
        ),
        QuizQuestion(
            question="What does TLP:RED mean under the Traffic Light Protocol?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "Share freely with the public and on social media",
                "Share within your organization and with trusted partner organizations",
                "Not for disclosure — share only with specific named recipients in this meeting/call",
                "Share with your sector ISAC only",
            ],
            correct_answer="C",
            explanation=(
                "TLP:RED restricts information to specific named recipients only — "
                "it cannot be shared further without explicit permission. It covers the most "
                "sensitive intelligence: active incident details, victim data, or source "
                "protection requirements. Hierarchy: WHITE/CLEAR (public) → GREEN → "
                "AMBER → AMBER+STRICT → RED (most restricted)."
            ),
            category="Threat Intelligence Sources",
            difficulty="Medium",
        ),

        # ── Analysis & Attribution ─────────────────────────────────────
        QuizQuestion(
            question="What does 'attribution' mean in CTI?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "Assigning a CVSS score to a newly discovered vulnerability",
                "Identifying the likely threat actor or group responsible for an intrusion",
                "Calculating the total financial cost of a security breach",
                "Determining which antivirus product detects a malware sample",
            ],
            correct_answer="B",
            explanation=(
                "Attribution identifies who conducted an attack. It is extremely difficult "
                "and uncertain — sophisticated actors deliberately plant false flags. "
                "CTI analysts use linguistic analysis, infrastructure reuse, TTP patterns, "
                "and victimology, always reporting confidence levels. Attribution is "
                "never 100% certain outside of a legal proceeding."
            ),
            category="Analysis & Attribution",
            difficulty="Medium",
        ),
        QuizQuestion(
            question="What is a 'false flag' operation in cyber attribution?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "A phishing email correctly tagged as spam by a mail gateway",
                "Deliberately planted evidence designed to mislead analysts about actor identity",
                "A compromised website showing a defacement banner with a fake group name",
                "An antivirus false positive flagging a legitimate file as malware",
            ],
            correct_answer="B",
            explanation=(
                "False flags are deliberately planted artifacts — Russian language strings, "
                "specific tools, or operational time zones — to implicate another actor. "
                "Example: Olympic Destroyer (2018) planted multiple conflicting attribution "
                "clues pointing to different nation-states. Always require multiple "
                "independent corroborating factors before asserting attribution."
            ),
            category="Analysis & Attribution",
            difficulty="Hard",
        ),
        QuizQuestion(
            question="In the Diamond Model, what does 'pivoting' mean for a CTI analyst?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "An attacker moving laterally from one host to another",
                "Using a known indicator to discover new related unknown features of an intrusion",
                "An analyst changing their attribution hypothesis mid-investigation",
                "Rotating encryption keys to protect analyst communications",
            ],
            correct_answer="B",
            explanation=(
                "Pivoting uses a known feature (e.g., an IP address) to discover connected "
                "unknowns (e.g., other domains on that IP, related malware using the same C2). "
                "This is the core analytical technique for expanding context, uncovering "
                "infrastructure clusters, and tying separate incidents to a single actor."
            ),
            category="Analysis & Attribution",
            difficulty="Medium",
        ),

        # ── Operational CTI ───────────────────────────────────────────
        QuizQuestion(
            question="What is a CTI 'Intelligence Requirement' (IR)?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "A government security clearance required to access classified intelligence",
                "A specific question that intelligence activity should answer to support decision-making",
                "The hardware and software needed to operate a threat intelligence platform",
                "A legal regulatory mandate to collect and report threat intelligence",
            ],
            correct_answer="B",
            explanation=(
                "Intelligence Requirements are specific questions like: "
                "'Which APT groups target our sector?' or 'What CVEs are currently weaponized?' "
                "IRs focus collection and analysis, preventing aimless threat feed consumption. "
                "They are set by stakeholders and revisited quarterly using the feedback loop."
            ),
            category="Operational CTI",
            difficulty="Easy",
        ),
        QuizQuestion(
            question="What is STIX/TAXII?",
            question_type=QuestionType.MULTIPLE_CHOICE,
            options=[
                "A new APT group operating from Southeast Asia",
                "Structured Threat Information Expression (STIX) and Trusted Automated Exchange of Intelligence (TAXII) — CTI sharing standards",
                "A network protocol for secure encrypted DNS resolution",
                "A cloud-based malware sandbox and detonation environment",
            ],
            correct_answer="B",
            explanation=(
                "STIX (v2.1 current) is the standardized language for representing "
                "threat information: indicators, campaigns, threat actors, relationships. "
                "TAXII is the transport protocol for exchanging STIX data over HTTPS. "
                "Together they enable automated, machine-readable CTI sharing between "
                "organizations, tools, and threat intelligence platforms."
            ),
            category="Operational CTI",
            difficulty="Medium",
        ),
        QuizQuestion(
            question="True or False: A CTI analyst should immediately block production assets based on a single IOC from an anonymous online source.",
            question_type=QuestionType.TRUE_FALSE,
            options=["True", "False"],
            correct_answer="B",
            explanation=(
                "False. Blocking on a single unvalidated IOC can cause outages if it is a "
                "false positive or planted disinformation. Always validate through multiple "
                "sources, assess reliability using the Admiralty Scale, check known-good "
                "lists, and assess business impact before blocking production systems."
            ),
            category="Operational CTI",
            difficulty="Hard",
        ),

        # ── Scenario Analysis ─────────────────────────────────────────
        QuizQuestion(
            question=(
                "SCENARIO: A base64-encoded PowerShell command in a phishing email decodes "
                "to download and execute a payload from a Pastebin URL. "
                "What ATT&CK technique best describes the EXECUTION method?"
            ),
            question_type=QuestionType.SCENARIO,
            options=[
                "T1566.001 — Spearphishing Attachment (Initial Access)",
                "T1059.001 — PowerShell (Execution)",
                "T1105 — Ingress Tool Transfer (C2)",
                "T1071.001 — Web Protocols (C2)",
            ],
            correct_answer="B",
            explanation=(
                "T1566 describes the initial access vector (phishing), but the question "
                "asks about the EXECUTION technique. T1059.001 (PowerShell) is the execution "
                "method used. In ATT&CK, each stage is mapped independently. T1105 describes "
                "the download step — but the execution of that download is PowerShell."
            ),
            category="Scenario Analysis",
            difficulty="Hard",
        ),
        QuizQuestion(
            question=(
                "SCENARIO: A threat actor compromises a software vendor's build system "
                "and trojanizes a legitimate update, pushing malware to 18,000 customers. "
                "What MITRE ATT&CK technique is this?"
            ),
            question_type=QuestionType.SCENARIO,
            options=[
                "T1566 — Phishing",
                "T1195 — Supply Chain Compromise",
                "T1078 — Valid Accounts",
                "T1133 — External Remote Services",
            ],
            correct_answer="B",
            explanation=(
                "T1195 — Supply Chain Compromise describes attacking a less-secure element "
                "of the supply chain to compromise intended targets. The SolarWinds/SUNBURST "
                "attack (2020) is the canonical example: a trojanized Orion update was "
                "digitally signed and distributed through legitimate channels."
            ),
            category="Scenario Analysis",
            difficulty="Medium",
        ),
        QuizQuestion(
            question=(
                "SCENARIO: EDR shows: wscript.exe spawns powershell.exe, which runs "
                "Invoke-CredDumper, then sends data to 203.0.113.45. "
                "Map the ATT&CK techniques in order."
            ),
            question_type=QuestionType.SCENARIO,
            options=[
                "T1059.005 → T1059.001 → T1003.001 → T1041",
                "T1566 → T1055 → T1003 → T1021",
                "T1071 → T1005 → T1048 → T1070",
                "T1053 → T1547 → T1083 → T1046",
            ],
            correct_answer="A",
            explanation=(
                "wscript.exe = T1059.005 (Visual Basic Script) "
                "→ powershell.exe = T1059.001 (PowerShell) "
                "→ Invoke-CredDumper = T1003.001 (LSASS Memory credential dumping) "
                "→ data sent to external IP = T1041 (Exfiltration over C2 channel). "
                "This classic chain is seen in pre-ransomware credential theft stages."
            ),
            category="Scenario Analysis",
            difficulty="Hard",
        ),
        QuizQuestion(
            question=(
                "SCENARIO: You receive a TLP:AMBER report warning that a ransomware group "
                "is actively targeting hospitals using your EHR vendor's software. "
                "What is the FIRST correct action?"
            ),
            question_type=QuestionType.SCENARIO,
            options=[
                "Post the IOCs to public threat feeds immediately for maximum community protection",
                "Extract IOCs and TTPs, assess exposure, and brief stakeholders within TLP:AMBER boundaries",
                "Wait for the vendor to issue an official patch advisory before acting",
                "Ignore it unless you see active indicators in your own environment first",
            ],
            correct_answer="B",
            explanation=(
                "TLP:AMBER = share within your organization and direct partners only — NOT publicly. "
                "Correct steps: (1) Extract all IOCs/TTPs, (2) Assess EHR version and exposure, "
                "(3) Push IOCs to SIEM/EDR, (4) Brief CISO and operations, "
                "(5) Contact sector peers via H-ISAC under TLP:AMBER. "
                "Posting publicly violates TLP:AMBER and may alert the threat actor."
            ),
            category="Scenario Analysis",
            difficulty="Hard",
        ),
    ]

    def __init__(self):
        self._categories = sorted(set(q.category for q in self.QUESTIONS))
        self._by_category: Dict[str, List[QuizQuestion]] = {}
        for cat in self._categories:
            self._by_category[cat] = [q for q in self.QUESTIONS if q.category == cat]

    def get_random_questions(self, count=5, category=None, difficulty=None):
        pool = self.QUESTIONS[:]
        if category:
            pool = [q for q in pool if q.category == category]
        if difficulty:
            pool = [q for q in pool if q.difficulty == difficulty]
        if not pool:
            return []
        return random.sample(pool, min(count, len(pool), 20))

    def get_categories(self):
        return self._categories

    def get_difficulties(self):
        return ["Easy", "Medium", "Hard"]

    def check_answer(self, question, user_answer):
        if not isinstance(user_answer, str):
            user_answer = str(user_answer)
        normalized_user = user_answer.strip().upper()[:1]  # Take just first char
        normalized_correct = question.correct_answer.strip().upper()[:1]
        is_correct = normalized_user == normalized_correct
        return {
            "correct": is_correct,
            "correct_answer": question.correct_answer,
            "user_answer": user_answer,
            "explanation": question.explanation,
            "category": question.category,
            "difficulty": question.difficulty,
        }

    def get_learning_paths(self):
        return [
            {
                "name": "CTI Fundamentals",
                "description": "Master the basics: intelligence cycle, IOC types, TLP protocol, and foundational frameworks.",
                "steps": [
                    "Understand the intelligence cycle and feedback loops",
                    "Learn Strategic, Operational, and Tactical intelligence",
                    "Study the Diamond Model and Cyber Kill Chain",
                    "Practice identifying IOC types and their limitations",
                    "Learn TLP classification and responsible sharing",
                ],
                "categories": ["CTI Fundamentals", "IOC Analysis"],
                "difficulty": "Easy",
            },
            {
                "name": "ATT&CK Practitioner",
                "description": "Master MITRE ATT&CK for mapping threats and building detections.",
                "steps": [
                    "Learn the 14 ATT&CK tactics and their objectives",
                    "Study technique/sub-technique structure",
                    "Practice mapping incident reports to ATT&CK",
                    "Build detection logic for specific techniques",
                    "Understand data sources per tactic",
                ],
                "categories": ["MITRE ATT&CK"],
                "difficulty": "Medium",
            },
            {
                "name": "Operational Analyst",
                "description": "Skills for producing and consuming operational threat intelligence.",
                "steps": [
                    "Write effective intelligence requirements (IRs)",
                    "Evaluate source reliability with the Admiralty Scale",
                    "Understand STIX/TAXII and sharing standards",
                    "Practice defanging/re-fanging IOCs",
                    "Attribution analysis with calibrated confidence",
                ],
                "categories": ["Operational CTI", "Threat Intelligence Sources", "Analysis & Attribution"],
                "difficulty": "Hard",
            },
            {
                "name": "Scenario Master",
                "description": "Apply CTI knowledge to realistic incident scenarios.",
                "steps": [
                    "Analyze multi-stage intrusion TTP chains",
                    "Map complex sequences across multiple ATT&CK tactics",
                    "Identify detection gaps from scenario evidence",
                    "Apply TLP protocols to sharing decisions under pressure",
                    "Produce actionable threat assessments for stakeholders",
                ],
                "categories": ["Scenario Analysis"],
                "difficulty": "Hard",
            },
        ]
