"""
Phoenix CTI Forge - IOC Analysis Engine
Securely extracts and analyzes Indicators of Compromise from text.
NO external command execution - pure Python regex and string processing.
Created by Australian Phoenix CyberOps
"""
import re
import ipaddress
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
import validators


class IOCType(Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    REGISTRY_KEY = "registry_key"
    BITCOIN = "bitcoin"
    UNKNOWN = "unknown"


@dataclass
class IOC:
    value: str
    ioc_type: IOCType
    position: int
    context: str
    educational_note: str = ""
    risk_context: str = ""
    defanged: str = ""


class IOCEngine:
    """
    Secure IOC extraction engine.
    Uses only Python standard library and safe regex patterns.
    No shell execution, no eval/exec, no external process calls.
    """

    PATTERNS = {
        IOCType.IPV4: re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        IOCType.IPV6: re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        ),
        IOCType.URL: re.compile(
            r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.]*)?)?(?:#(?:[\w.])*)?)?'
        ),
        IOCType.DOMAIN: re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        ),
        IOCType.SHA256: re.compile(r'\b[a-fA-F0-9]{64}\b'),
        IOCType.SHA1: re.compile(r'\b[a-fA-F0-9]{40}\b'),
        IOCType.MD5: re.compile(r'\b[a-fA-F0-9]{32}\b'),
        IOCType.EMAIL: re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ),
        IOCType.CVE: re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE),
        IOCType.REGISTRY_KEY: re.compile(
            r'\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|'
            r'HKEY_USERS|HKEY_CURRENT_CONFIG)\\[\w\\\.\- ]+\b',
            re.IGNORECASE
        ),
        IOCType.BITCOIN: re.compile(
            r'\b(?:1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-z0-9]{39,59}\b'
        ),
    }

    EDUCATION = {
        IOCType.IPV4: {
            "description": "IPv4 addresses identify C2 servers, infected hosts, or scanning sources. Analysts check reputation databases and geolocation to assess risk.",
            "analysis_tips": [
                "Check against threat intel feeds (VirusTotal, AbuseIPDB)",
                "Review geolocation and ASN ownership",
                "Correlate with network logs for lateral movement",
                "Check for sinkhole IPs vs active C2"
            ],
            "example_mitre": "Command and Control (TA0011), Exfiltration (TA0010)"
        },
        IOCType.IPV6: {
            "description": "IPv6 addresses serve the same function as IPv4. Often overlooked by defenders - threat actors may use IPv6 for covert channels.",
            "analysis_tips": [
                "IPv6 abuse is growing; ensure your sensors capture it",
                "Check for tunneling (6to4, Teredo) as evasion",
                "Validate neighbor discovery protocol anomalies"
            ],
            "example_mitre": "Command and Control (TA0011)"
        },
        IOCType.DOMAIN: {
            "description": "Domains are used for C2 infrastructure, phishing lures, and malware distribution. Threat actors use DGAs and domain fronting.",
            "analysis_tips": [
                "Check WHOIS registration date and registrar reputation",
                "Analyze DNS resolution patterns (fast-flux, double-flux)",
                "Look for typosquatting or homograph attacks",
                "Check certificate transparency logs"
            ],
            "example_mitre": "Initial Access (TA0001), Command and Control (TA0011)"
        },
        IOCType.URL: {
            "description": "URLs deliver malware payloads, host phishing pages, or serve as C2 endpoints. Path analysis can reveal exploit kit structure.",
            "analysis_tips": [
                "URL decode and analyze parameters for structure",
                "Check URL reputation services",
                "Analyze path patterns for exploit kits",
                "Look for URI paths matching known malware families"
            ],
            "example_mitre": "Initial Access (TA0001), Execution (TA0002)"
        },
        IOCType.MD5: {
            "description": "MD5 hashes identify files but are cryptographically broken. Still used for legacy matching in threat intel feeds.",
            "analysis_tips": [
                "WARNING: MD5 is vulnerable to collisions - use SHA256 for verification",
                "Match against known malware databases",
                "Correlate with sandbox analysis reports"
            ],
            "example_mitre": "Defense Evasion (TA0005), Impact (TA0040)"
        },
        IOCType.SHA1: {
            "description": "SHA1 provides stronger file identification than MD5 but is also deprecated. Still widely used in CTI feeds.",
            "analysis_tips": [
                "More collision-resistant than MD5 but being phased out",
                "Use for historical feed correlation",
                "Cross-reference with VirusTotal, MalwareBazaar"
            ],
            "example_mitre": "Defense Evasion (TA0005)"
        },
        IOCType.SHA256: {
            "description": "SHA256 is the current standard for file hash identification in CTI. Provides unique identification for malware samples.",
            "analysis_tips": [
                "Submit to VirusTotal, Intezer, or Joe Sandbox for analysis",
                "Check code similarity for family attribution",
                "Correlate with ATT&CK technique mapping",
                "Use in YARA rules and endpoint detection"
            ],
            "example_mitre": "Defense Evasion (TA0005), Discovery (TA0007)"
        },
        IOCType.EMAIL: {
            "description": "Email addresses appear in phishing campaigns, BEC attacks, and as registration contacts for malicious infrastructure.",
            "analysis_tips": [
                "Check if domain is legitimate or typosquatted",
                "Look for display name spoofing",
                "Analyze headers for SPF/DKIM/DMARC failures",
                "Correlate with breach databases"
            ],
            "example_mitre": "Initial Access (TA0001) - Phishing"
        },
        IOCType.CVE: {
            "description": "CVE identifiers track publicly disclosed vulnerabilities. Threat actors exploit known CVEs (1-day/n-day exploitation).",
            "analysis_tips": [
                "Check CVSS score and exploit availability",
                "Review CISA KEV catalog for actively exploited CVEs",
                "Map to your asset inventory for exposure assessment",
                "Check for proof-of-concept code on GitHub"
            ],
            "example_mitre": "Initial Access (TA0001), Privilege Escalation (TA0004)"
        },
        IOCType.REGISTRY_KEY: {
            "description": "Registry keys indicate persistence mechanisms, configuration storage, or anti-forensics activity. Critical for Windows forensics.",
            "analysis_tips": [
                "Map to known persistence techniques (MITRE ATT&CK T1547)",
                "Check for redundant entries across hives",
                "Look for entropy in value names (possible encoded config)",
                "Correlate with temporal artifacts"
            ],
            "example_mitre": "Persistence (TA0003), Defense Evasion (TA0005)"
        },
        IOCType.BITCOIN: {
            "description": "Cryptocurrency addresses appear in ransomware notes and extortion demands. Tracking wallet activity reveals victim payments.",
            "analysis_tips": [
                "Monitor blockchain for transaction activity",
                "Cluster addresses using open-source intelligence",
                "Check Chainalysis or Elliptic reports for attribution",
                "Correlate with ransom notes and leak sites"
            ],
            "example_mitre": "Impact (TA0040) - Financial Theft"
        },
    }

    # Defang patterns for safe sharing
    DEFANG_RULES = [
        (re.compile(r'\.'), '[.]'),
        (re.compile(r'http', re.IGNORECASE), 'hxxp'),
        (re.compile(r'@'), '[@]'),
    ]

    def __init__(self):
        self.validated_iocs: List[IOC] = []

    def defang(self, value: str, ioc_type: IOCType) -> str:
        """Defang an IOC for safe sharing in reports."""
        result = value
        if ioc_type in (IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN):
            result = result.replace('.', '[.]')
        elif ioc_type == IOCType.URL:
            result = re.sub(r'https?://', lambda m: m.group(0).replace('http', 'hxxp'), result)
            result = result.replace('.', '[.]')
        elif ioc_type == IOCType.EMAIL:
            result = result.replace('@', '[@]').replace('.', '[.]')
        return result

    def refang(self, value: str) -> str:
        """Re-fang a defanged IOC for analysis."""
        result = value
        result = result.replace('[.]', '.').replace('[dot]', '.').replace('(dot)', '.')
        result = result.replace('[@]', '@').replace('[at]', '@').replace('(at)', '@')
        result = re.sub(r'hxxp(s?)', r'http\1', result, flags=re.IGNORECASE)
        result = re.sub(r'hXXp(s?)', r'http\1', result, flags=re.IGNORECASE)
        return result

    def extract_iocs(self, text: str, context_radius: int = 40) -> List[IOC]:
        """Securely extract IOCs from input text."""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")
        if len(text) > 524288:
            raise ValueError("Input exceeds maximum size of 512KB")

        # Auto-refang before extraction (handles defanged IOCs in reports)
        text_for_extraction = self.refang(text)

        found_iocs: List[IOC] = []
        seen_positions = set()

        for ioc_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text_for_extraction):
                start, end = match.start(), match.end()

                if any(start < pos[1] and end > pos[0] for pos in seen_positions):
                    continue

                value = match.group(0)

                if not self._validate_ioc(value, ioc_type):
                    continue

                context_start = max(0, start - context_radius)
                context_end = min(len(text_for_extraction), end + context_radius)
                context = text_for_extraction[context_start:context_end]

                edu = self.EDUCATION.get(ioc_type, {})

                ioc = IOC(
                    value=value,
                    ioc_type=ioc_type,
                    position=start,
                    context=context,
                    educational_note=edu.get("description", "No description available."),
                    risk_context=edu.get("example_mitre", ""),
                    defanged=self.defang(value, ioc_type)
                )

                found_iocs.append(ioc)
                seen_positions.add((start, end))

        found_iocs.sort(key=lambda x: x.position)
        self.validated_iocs = found_iocs
        return found_iocs

    def _validate_ioc(self, value: str, ioc_type: IOCType) -> bool:
        """Validate extracted IOC to reduce false positives."""
        if not value or len(value) > 500:
            return False

        try:
            if ioc_type == IOCType.IPV4:
                ipaddress.IPv4Address(value)
                return True
            elif ioc_type == IOCType.IPV6:
                ipaddress.IPv6Address(value)
                return True
            elif ioc_type == IOCType.DOMAIN:
                lower_val = value.lower()
                false_positives = {
                    'example.com', 'localhost', 'domain.com', 'test.com',
                    'yourdomain.com', 'email.com', 'company.com'
                }
                if lower_val in false_positives:
                    return False
                return validators.domain(value) is True
            elif ioc_type == IOCType.EMAIL:
                return validators.email(value) is True
            elif ioc_type == IOCType.URL:
                return validators.url(value) is True
            elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
                if len(set(value)) == 1:
                    return False
                return True
            elif ioc_type == IOCType.CVE:
                parts = value.upper().split('-')
                if len(parts) != 3 or parts[0] != 'CVE':
                    return False
                try:
                    year = int(parts[1])
                    num = int(parts[2])
                    return 1999 <= year <= 2030 and num > 0
                except ValueError:
                    return False
            return True
        except Exception:
            return False

    def get_statistics(self) -> Dict[str, int]:
        """Return count statistics for each IOC type found."""
        stats = {}
        for ioc_type in IOCType:
            count = sum(1 for ioc in self.validated_iocs if ioc.ioc_type == ioc_type)
            if count > 0:
                stats[ioc_type.value] = count
        return stats

    def generate_hunt_query(self, ioc_type: IOCType, iocs: List[str]) -> Dict[str, str]:
        """Generate safe detection/hunting queries for SIEM/EDR."""
        if not all(isinstance(i, str) for i in iocs):
            raise ValueError("All IOCs must be strings")

        safe_iocs = []
        for ioc in iocs[:50]:
            safe_ioc = ioc.replace('"', '\\"').replace("'", "\\'")
            safe_iocs.append(safe_ioc)

        if ioc_type == IOCType.SHA256:
            # FIX: Corrected indentation (original had tab character \t\t})
            return {
                "yara": (
                    "rule PhoenixCTI_Hash_Match {\n"
                    "  strings:\n"
                    + "\n".join(f"    $h{i} = \"{h}\"" for i, h in enumerate(safe_iocs[:5]))
                    + "\n  condition:\n    any of them\n}"
                ),
                "sigma": (
                    "title: Phoenix CTI - File Hash Match\n"
                    "selection:\n  sha256:\n    - "
                    + "\n    - ".join(safe_iocs[:10])
                ),
                "splunk": (
                    "index=* [| inputlookup hashes.csv] sha256 IN ("
                    + ", ".join(f'"{h}"' for h in safe_iocs[:10])
                    + ")"
                ),
                "kql": (
                    "let hashes = dynamic(["
                    + ", ".join(f'"{h}"' for h in safe_iocs[:10])
                    + "]);\nDeviceFileEvents\n| where SHA256 in (hashes)"
                ),
            }
        elif ioc_type == IOCType.IPV4:
            # FIX: Corrected sigma key from 'sha256' to 'DestinationIp'
            return {
                "sigma": (
                    "title: Phoenix CTI - Suspicious IP Communication\n"
                    "selection:\n  DestinationIp:\n    - "
                    + "\n    - ".join(safe_iocs[:10])
                ),
                "splunk": (
                    "index=network dest_ip IN ("
                    + ", ".join(f'"{ip}"' for ip in safe_iocs[:10])
                    + ")"
                ),
                "kql": (
                    "let ips = dynamic(["
                    + ", ".join(f'"{ip}"' for ip in safe_iocs[:10])
                    + "]);\nDeviceNetworkEvents\n| where RemoteIP in (ips)"
                ),
            }
        elif ioc_type == IOCType.DOMAIN:
            return {
                "sigma": (
                    "title: Phoenix CTI - Suspicious Domain Query\n"
                    "selection:\n  QueryName|endswith:\n    - "
                    + "\n    - ".join(f'"{d}"' for d in safe_iocs[:10])
                ),
                "splunk": (
                    "index=dns query IN ("
                    + ", ".join(f'"{d}"' for d in safe_iocs[:10])
                    + ")"
                ),
                "kql": (
                    "let domains = dynamic(["
                    + ", ".join(f'"{d}"' for d in safe_iocs[:10])
                    + "]);\nDnsEvents\n| where Name in (domains)"
                ),
            }
        elif ioc_type == IOCType.EMAIL:
            return {
                "splunk": (
                    "index=email (sender IN ("
                    + ", ".join(f'"{e}"' for e in safe_iocs[:10])
                    + "))"
                ),
                "kql": (
                    "let senders = dynamic(["
                    + ", ".join(f'"{e}"' for e in safe_iocs[:10])
                    + "]);\nEmailEvents\n| where SenderFromAddress in (senders)"
                ),
            }
        elif ioc_type == IOCType.CVE:
            return {
                "note": (
                    "CVE hunting: Check patch status with your vulnerability scanner. "
                    "CVEs to prioritize: " + ", ".join(safe_iocs[:10])
                ),
                "splunk": (
                    "index=vuln_scan cve IN ("
                    + ", ".join(f'"{c}"' for c in safe_iocs[:10])
                    + ")"
                ),
            }
        return {"note": "Hunting query generation not available for this IOC type yet."}


def defang_text(text: str) -> str:
    """
    Defang all IOCs in a block of text for safe sharing.
    Order matters: URLs first (to capture full path), then IPs, then emails/domains.
    """
    # Step 1: Defang URLs — replace protocol AND dots inside URL
    def defang_url(m):
        url = m.group(0)
        proto = 'hxxps' if url.lower().startswith('https') else 'hxxp'
        rest = url[url.index('://'):]          # keep :// and everything after
        rest = rest.replace('.', '[.]')         # defang all dots in URL
        return proto + rest

    text = re.sub(
        r'https?://[^\s,\'"<>\]]+',
        defang_url,
        text,
        flags=re.IGNORECASE
    )

    # Step 2: Defang IPv4 addresses (dots → [.])
    text = re.sub(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        lambda m: m.group(0).replace('.', '[.]'),
        text
    )

    # Step 3: Defang email addresses (@ → [@], dots → [.])
    def defang_email(m):
        return m.group(0).replace('@', '[@]').replace('.', '[.]')

    text = re.sub(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        defang_email,
        text
    )

    # Step 4: Defang remaining standalone domains (simple heuristic)
    # Match word.tld or sub.word.tld that haven't been defanged yet
    def defang_domain(m):
        val = m.group(0)
        if '[.]' in val:      # already defanged
            return val
        return val.replace('.', '[.]')

    text = re.sub(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b',
        defang_domain,
        text
    )

    return text


def refang_text(text: str) -> str:
    """Re-fang all defanged IOCs in a block of text for analysis."""
    text = text.replace('[.]', '.').replace('[dot]', '.').replace('(dot)', '.')
    text = text.replace('[@]', '@').replace('[at]', '@').replace('(at)', '@')
    # Handle hxxp / hXXp / hxxps / hXXps
    text = re.sub(r'hxxps?://', lambda m: 'https://' if 'hxxps' in m.group(0).lower() else 'http://', text, flags=re.IGNORECASE)
    return text
