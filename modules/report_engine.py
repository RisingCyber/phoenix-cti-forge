"""
CTI Forge - Threat Report Engine
Safe generation of structured threat intelligence reports.
No file system traversal, no command execution, safe HTML generation.
"""
import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from html import escape
import json


@dataclass
class ThreatActor:
    name: str
    aliases: List[str] = field(default_factory=list)
    origin: str = ""
    motivation: str = ""
    first_seen: str = ""
    description: str = ""
    ttps: List[str] = field(default_factory=list)
    targeting: str = ""


@dataclass
class ReportSection:
    title: str
    content: str
    section_type: str  # executive, technical, iocs, mitre, timeline, recommendation


class ReportEngine:
    """
    Generates structured CTI reports with safe output.
    All inputs are sanitized; no shell execution; no file path traversal.
    """
    
    THREAT_ACTORS: Dict[str, ThreatActor] = {
        "apt29": ThreatActor(
            name="APT29",
            aliases=["Cozy Bear", "The Dukes", "YTTRIUM"],
            origin="Russia (SVR)",
            motivation="Espionage, intelligence gathering",
            first_seen="2008",
            description="Highly sophisticated Russian state-sponsored group targeting governments, think tanks, and healthcare. Known for stealthy, long-duration intrusions.",
            ttps=["T1566 - Phishing", "T1059.001 - PowerShell", "T1027 - Obfuscation", "T1070 - Indicator Removal"],
            targeting="Government, Healthcare, Academia, NATO"
        ),
        "apt28": ThreatActor(
            name="APT28",
            aliases=["Fancy Bear", "STRONTIUM", "Sofacy", "TSAR TEAM"],
            origin="Russia (GRU Unit 26165)",
            motivation="Espionage, influence operations, military targeting",
            first_seen="2007",
            description="Russian military intelligence group known for aggressive operations, destructive attacks, and election interference. Less stealthy than APT29.",
            ttps=["T1190 - Exploit Public-Facing App", "T1003 - OS Credential Dumping", "T1055 - Process Injection", "T1486 - Data Encrypted for Impact"],
            targeting="Government, Military, Elections, Sports"
        ),
        "apt41": ThreatActor(
            name="APT41",
            aliases=["BARIUM", "Winnti"],
            origin="China",
            motivation="Espionage and financial gain (dual mission)",
            first_seen="2012",
            description="Unique group conducting both state-sponsored espionage and financially motivated cybercrime. Known for supply chain compromises and software signing certificate abuse.",
            ttps=["T1195 - Supply Chain Compromise", "T1027 - Obfuscation", "T1071 - Application Layer Protocol", "T1574 - Hijack Execution Flow"],
            targeting="Healthcare, Technology, Telecom, Gaming"
        ),
        "lazarus": ThreatActor(
            name="Lazarus Group",
            aliases=["HIDDEN COBRA", "Guardians of Peace", "ZINC"],
            origin="North Korea (Bureau 121)",
            motivation="Financial theft, espionage, destructive operations",
            first_seen="2009",
            description="North Korean state-sponsored group responsible for Sony Pictures hack, SWIFT banking attacks, and WannaCry ransomware. Highly adaptable and financially motivated.",
            ttps=["T1486 - Data Encrypted for Impact", "T1567 - Exfiltration Over Web Service", "T1071 - Application Layer Protocol", "T1190 - Exploit Public-Facing App"],
            targeting="Financial institutions, Entertainment, Cryptocurrency, Critical infrastructure"
        ),
        "wizard_spider": ThreatActor(
            name="Wizard Spider",
            aliases=["TEMP.MixMaster", "UNC2053"],
            origin="Russia/CIS",
            motivation="Financial gain (ransomware)",
            first_seen="2016",
            description="Cybercrime syndicate operating Conti, Ryuk, and TrickBot. Ransomware-as-a-service operators with professional organizational structure.",
            ttps=["T1486 - Data Encrypted for Impact", "T1003 - OS Credential Dumping", "T1021.002 - SMB/Windows Admin Shares", "T1053 - Scheduled Task/Job"],
            targeting="Healthcare, Critical infrastructure, Education, Corporations"
        ),
        "apt32": ThreatActor(
            name="APT32",
            aliases=["OceanLotus", "SeaLotus", "Cobalt Kitty"],
            origin="Vietnam",
            motivation="Espionage targeting foreign corporations in Vietnam",
            first_seen="2012",
            description="Vietnamese state-sponsored group targeting foreign businesses with interests in Vietnam. Known for sophisticated macOS malware and watering hole attacks.",
            ttps=["T1566 - Phishing", "T1059.002 - AppleScript", "T1071 - Application Layer Protocol", "T1027 - Obfuscated Files"],
            targeting="Foreign corporations in Vietnam, Automotive, Consumer products"
        ),
    }
    
    def __init__(self):
        """Initialize report engine."""
        self._report_templates = {
            "incident_response": self._get_ir_template,
            "threat_actor_profile": self._get_actor_template,
            "ioc_bulletin": self._get_ioc_template,
            "vulnerability_alert": self._get_vuln_template,
        }
    
    def get_threat_actor(self, actor_key: str) -> Optional[ThreatActor]:
        """Retrieve threat actor profile safely."""
        if not isinstance(actor_key, str):
            return None
        actor_key = actor_key.lower().strip()
        # Prevent injection via actor_key
        if not re.match(r'^[a-z0-9_]+$', actor_key):
            return None
        return self.THREAT_ACTORS.get(actor_key)
    
    def list_actors(self) -> List[Dict]:
        """List all available threat actor profiles."""
        actors = []
        for key, actor in self.THREAT_ACTORS.items():
            actors.append({
                "key": key,
                "name": actor.name,
                "aliases": actor.aliases,
                "origin": actor.origin,
                "motivation": actor.motivation,
                "targeting": actor.targeting
            })
        return actors
    
    def create_report(self, template_type: str, data: Dict) -> List[ReportSection]:
        """
        Create a structured report from template.
        All user data is sanitized.
        """
        if template_type not in self._report_templates:
            return [ReportSection("Error", "Invalid report template.", "error")]
        
        template_func = self._report_templates[template_type]
        return template_func(data)
    
    def _sanitize_text(self, text: str, max_length: int = 10000) -> str:
        """Sanitize user input for safe report inclusion."""
        if not isinstance(text, str):
            text = str(text)
        text = text.strip()
        if len(text) > max_length:
            text = text[:max_length]
        # Remove control characters except newlines and tabs
        text = ''.join(c for c in text if c == '\n' or c == '\t' or (c >= ' ' and c <= '~') or c.isprintable())
        return text
    
    def _get_ir_template(self, data: Dict) -> List[ReportSection]:
        """Incident Response report template."""
        sections = [
            ReportSection(
                title="Executive Summary",
                content="This incident response report documents a security incident involving " + self._sanitize_text(data.get("incident_type", "unknown malicious activity")) + ". Immediate containment actions have been taken. This report provides tactical intelligence for stakeholders and detection engineering teams.",
                section_type="executive"
            ),
            ReportSection(
                title="Incident Timeline",
                content=self._sanitize_text(data.get("timeline", "Timeline data pending collection.")),
                section_type="timeline"
            ),
            ReportSection(
                title="Technical Analysis",
                content="Initial access vector: " + self._sanitize_text(data.get("initial_access", "Unknown")) + 
                        "\n\nPersistence mechanism: " + self._sanitize_text(data.get("persistence", "Unknown")) +
                        "\n\nLateral movement: " + self._sanitize_text(data.get("lateral_movement", "Unknown")) +
                        "\n\nImpact assessment: " + self._sanitize_text(data.get("impact", "Under investigation.")),
                section_type="technical"
            ),
            ReportSection(
                title="Indicators of Compromise",
                content=self._sanitize_text(data.get("iocs", "No IOCs available at this time.")),
                section_type="iocs"
            ),
            ReportSection(
                title="MITRE ATT&CK Mapping",
                content="Mapped techniques:\n" + self._sanitize_text(data.get("mitre_mapping", "Mapping in progress.")),
                section_type="mitre"
            ),
            ReportSection(
                title="Recommendations",
                content=self._sanitize_text(data.get("recommendations", 
                    "1. Isolate affected systems\n2. Reset compromised credentials\n3. Deploy detection rules for identified TTPs\n4. Hunt for related IOCs across environment")),
                section_type="recommendation"
            ),
        ]
        return sections
    
    def _get_actor_template(self, data: Dict) -> List[ReportSection]:
        """Threat Actor Profile template."""
        actor_key = self._sanitize_text(data.get("actor", "unknown"), 50).lower()
        actor = self.get_threat_actor(actor_key)
        
        if not actor:
            return [ReportSection("Error", "Threat actor profile not found.", "error")]
        
        sections = [
            ReportSection(
                title=f"Actor Profile: {actor.name}",
                content=f"Aliases: {', '.join(actor.aliases)}\nOrigin: {actor.origin}\nMotivation: {actor.motivation}\nFirst Seen: {actor.first_seen}\n\nDescription: {actor.description}",
                section_type="executive"
            ),
            ReportSection(
                title="Targeted Sectors",
                content=actor.targeting,
                section_type="technical"
            ),
            ReportSection(
                title="Observed TTPs",
                content="\n".join(f"- {ttp}" for ttp in actor.ttps),
                section_type="mitre"
            ),
            ReportSection(
                title="CTI Assessment",
                content=f"{actor.name} represents a {actor.motivation.lower()} threat with demonstrated capability against {actor.targeting}. Organizations in these sectors should prioritize detection for the observed TTPs and monitor for infrastructure associated with this actor.",
                section_type="recommendation"
            ),
        ]
        return sections
    
    def _get_ioc_template(self, data: Dict) -> List[ReportSection]:
        """IOC Bulletin template."""
        sections = [
            ReportSection(
                title="IOC Bulletin",
                content="Alert Type: " + self._sanitize_text(data.get("alert_type", "General Threat")) +
                        "\nSeverity: " + self._sanitize_text(data.get("severity", "Medium")) +
                        "\nConfidence: " + self._sanitize_text(data.get("confidence", "Medium")) +
                        "\n\nSummary: " + self._sanitize_text(data.get("summary", "New indicators have been identified.")),
                section_type="executive"
            ),
            ReportSection(
                title="Extracted Indicators",
                content=self._sanitize_text(data.get("iocs", "No indicators provided.")),
                section_type="iocs"
            ),
            ReportSection(
                title="Recommended Actions",
                content=self._sanitize_text(data.get("actions", 
                    "1. Block listed IPs at perimeter\n2. Add hashes to endpoint denylist\n3. Hunt for related behaviors\n4. Update detection rules")),
                section_type="recommendation"
            ),
        ]
        return sections
    
    def _get_vuln_template(self, data: Dict) -> List[ReportSection]:
        """Vulnerability Alert template."""
        sections = [
            ReportSection(
                title="Vulnerability Alert",
                content="CVE: " + self._sanitize_text(data.get("cve", "Unknown"), 20) +
                        "\nProduct: " + self._sanitize_text(data.get("product", "Unknown"), 100) +
                        "\nCVSS Score: " + self._sanitize_text(data.get("cvss", "Unknown"), 10) +
                        "\nExploit Status: " + self._sanitize_text(data.get("exploit_status", "Unknown"), 50) +
                        "\n\nDescription: " + self._sanitize_text(data.get("description", "No description provided.")),
                section_type="executive"
            ),
            ReportSection(
                title="Threat Context",
                content=self._sanitize_text(data.get("threat_context", 
                    "This vulnerability is being actively exploited in the wild according to CISA KEV catalog."), 5000),
                section_type="technical"
            ),
            ReportSection(
                title="Remediation",
                content=self._sanitize_text(data.get("remediation", 
                    "1. Apply vendor patch immediately\n2. Implement compensating controls\n3. Monitor for exploitation attempts\n4. Scan environment for vulnerable assets")),
                section_type="recommendation"
            ),
        ]
        return sections
    
    def report_to_markdown(self, sections: List[ReportSection]) -> str:
        """Convert report sections to Markdown safely."""
        lines = []
        lines.append("# CTI Forge - Threat Intelligence Report")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("---\n")
        
        for section in sections:
            lines.append(f"## {escape(section.title)}")
            lines.append(f"*{section.section_type.upper()}*\n")
            # Preserve newlines but escape HTML
            content = escape(section.content)
            content = content.replace('\n', '\n\n')
            lines.append(content)
            lines.append("\n---\n")
        
        return "\n".join(lines)
    
    def report_to_dict(self, sections: List[ReportSection]) -> Dict:
        """Convert report to serializable dictionary."""
        return {
            "generated": datetime.now().isoformat(),
            "sections": [
                {
                    "title": s.title,
                    "type": s.section_type,
                    "content": s.content
                }
                for s in sections
            ]
        }
