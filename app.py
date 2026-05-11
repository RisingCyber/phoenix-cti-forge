"""
Phoenix CTI Forge - Main Application
Cyber Threat Intelligence Educational Platform
Created by Australian Phoenix CyberOps
Security-first Flask application with comprehensive protections.
"""
import os
import sys
import logging
from html import escape

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify, abort
from flask_wtf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import RequestEntityTooLarge

from config import config_by_name
from modules.ioc_engine import IOCEngine, IOCType, defang_text, refang_text
from modules.mitre_engine import MITREEngine, Tactic
from modules.educational import TrainingModule
from modules.report_engine import ReportEngine

app = Flask(__name__)
app.config.from_object(config_by_name[os.environ.get('FLASK_ENV', 'default')])

csrf = CSRFProtect(app)

talisman = Talisman(
    app,
    force_https=False,
    strict_transport_security=False,
    content_security_policy=app.config.get('CSP', {}),
    feature_policy={
        'geolocation': "'none'",
        'microphone': "'none'",
        'camera': "'none'",
    }
)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=app.config.get('RATELIMIT_STORAGE_URI', 'memory://'),
    strategy=app.config.get('RATELIMIT_STRATEGY', 'fixed-window'),
    default_limits=["200 per day", "50 per hour"]
)

app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

ioc_engine = IOCEngine()
mitre_engine = MITREEngine()
training_module = TrainingModule()
report_engine = ReportEngine()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('phoenix-cti-forge')


# ── Security Helpers ──────────────────────────────────────────────────────────

def sanitize_input(value, max_length=1000):
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if len(value) > max_length:
        value = value[:max_length]
    value = value.replace('\x00', '').replace('\r', '')
    return value


def validate_json_request():
    if not request.is_json:
        return False
    content_length = request.content_length or 0
    if content_length > 524288:
        return False
    return True


# ── Error Handlers ────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', code=404, message="Page not found"), 404


@app.errorhandler(429)
def rate_limit(error):
    return render_template('error.html', code=429, message="Rate limit exceeded. Please slow down."), 429


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return render_template('error.html', code=500, message="An internal error occurred"), 500


@app.errorhandler(RequestEntityTooLarge)
def too_large(error):
    return render_template('error.html', code=413, message="Request too large. Maximum 5MB."), 413


# ── Page Routes ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    stats = {
        "mitre_techniques": len(mitre_engine.TECHNIQUES),
        "tactics": len(list(Tactic)),
        "training_questions": len(training_module.QUESTIONS),
        "threat_actors": len(report_engine.THREAT_ACTORS)
    }
    return render_template('index.html', stats=stats)


@app.route('/ioc-analyzer')
def ioc_analyzer_page():
    return render_template('ioc_analyzer.html')


@app.route('/mitre-explorer')
def mitre_explorer_page():
    tactics = mitre_engine.get_all_tactics()
    return render_template('mitre_explorer.html', tactics=tactics)


@app.route('/training')
def training_page():
    categories = training_module.get_categories()
    difficulties = training_module.get_difficulties()
    paths = training_module.get_learning_paths()
    # FIX: Pass question count directly so template doesn't reference training_module
    stats = {"questions": len(training_module.QUESTIONS)}
    return render_template(
        'training.html',
        categories=categories,
        difficulties=difficulties,
        paths=paths,
        stats=stats
    )


@app.route('/report-builder')
def report_builder_page():
    actors = report_engine.list_actors()
    templates = ["incident_response", "threat_actor_profile", "ioc_bulletin", "vulnerability_alert"]
    return render_template('report_builder.html', actors=actors, templates=templates)


@app.route('/ttp-mapper')
def ttp_mapper_page():
    return render_template('ttp_mapper.html')


@app.route('/toolkit')
def toolkit_page():
    """CTI Toolkit — CyberChef for CTI analysts."""
    return render_template('toolkit.html')


@app.route('/defang-tool')
def defang_tool_page():
    """IOC Defang / Re-fang tool - essential daily utility for CTI analysts."""
    return render_template('defang_tool.html')


# ── API: IOC Analysis ─────────────────────────────────────────────────────────

@csrf.exempt
@app.route('/api/extract-iocs', methods=['POST'])
@limiter.limit("20 per minute")
def extract_iocs():
    if not validate_json_request():
        return jsonify({"error": "Invalid request. JSON required."}), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON payload."}), 400

    text = data.get('text', '')
    if not isinstance(text, str):
        return jsonify({"error": "Text must be a string."}), 400

    text = sanitize_input(text, max_length=500000)
    if not text:
        return jsonify({"error": "No text provided."}), 400

    try:
        engine = IOCEngine()
        iocs = engine.extract_iocs(text)
        results = []
        for ioc in iocs:
            results.append({
                "value": ioc.value,
                "type": ioc.ioc_type.value,
                "position": ioc.position,
                "context": ioc.context,
                "educational_note": ioc.educational_note,
                "risk_context": ioc.risk_context,
                "defanged": ioc.defanged,
            })

        stats = engine.get_statistics()

        return jsonify({
            "success": True,
            "count": len(results),
            "statistics": stats,
            "iocs": results
        })
    except Exception as e:
        logger.error(f"IOC extraction error: {e}")
        return jsonify({"error": "Analysis failed. Please try again."}), 500


@csrf.exempt
@app.route('/api/generate-hunt', methods=['POST'])
@limiter.limit("10 per minute")
def generate_hunt():
    if not validate_json_request():
        return jsonify({"error": "Invalid request."}), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON."}), 400

    ioc_type_str = sanitize_input(data.get('ioc_type', ''), 50)
    iocs = data.get('iocs', [])

    if not isinstance(iocs, list) or not all(isinstance(i, str) for i in iocs):
        return jsonify({"error": "IOCs must be a list of strings."}), 400

    try:
        ioc_type = IOCType(ioc_type_str)
    except ValueError:
        return jsonify({"error": "Invalid IOC type."}), 400

    safe_iocs = [sanitize_input(i, 500) for i in iocs if sanitize_input(i, 500)]
    if not safe_iocs:
        return jsonify({"error": "No valid IOCs provided."}), 400

    try:
        engine = IOCEngine()
        queries = engine.generate_hunt_query(ioc_type, safe_iocs)
        return jsonify({"success": True, "queries": queries})
    except Exception as e:
        logger.error(f"Hunt generation error: {e}")
        return jsonify({"error": "Query generation failed."}), 500


# ── API: Defang / Re-fang ─────────────────────────────────────────────────────

@csrf.exempt
@app.route('/api/defang', methods=['POST'])
@limiter.limit("30 per minute")
def defang_api():
    """Defang IOCs in a block of text for safe sharing."""
    if not validate_json_request():
        return jsonify({"error": "Invalid request."}), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON."}), 400

    text = sanitize_input(data.get('text', ''), max_length=100000)
    if not text:
        return jsonify({"error": "No text provided."}), 400

    try:
        result = defang_text(text)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Defang error: {e}")
        return jsonify({"error": "Defang operation failed."}), 500


@csrf.exempt
@app.route('/api/refang', methods=['POST'])
@limiter.limit("30 per minute")
def refang_api():
    """Re-fang defanged IOCs in a block of text for analysis."""
    if not validate_json_request():
        return jsonify({"error": "Invalid request."}), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON."}), 400

    text = sanitize_input(data.get('text', ''), max_length=100000)
    if not text:
        return jsonify({"error": "No text provided."}), 400

    try:
        result = refang_text(text)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Refang error: {e}")
        return jsonify({"error": "Re-fang operation failed."}), 500


# ── API: MITRE ATT&CK ─────────────────────────────────────────────────────────

@csrf.exempt
@app.route('/api/mitre/techniques/<tactic_id>')
@limiter.limit("30 per minute")
def get_mitre_techniques(tactic_id):
    tactic_id = sanitize_input(tactic_id, 20)

    tactic = None
    for t in Tactic:
        if t.value == tactic_id:
            tactic = t
            break

    if not tactic:
        return jsonify({"error": "Tactic not found."}), 404

    techniques = mitre_engine.get_tactic_techniques(tactic)
    info = mitre_engine.get_tactic_info(tactic)

    return jsonify({
        "tactic": {
            "id": tactic.value,
            "name": info.get("name", tactic.name),
            "description": info.get("description", ""),
            "ctipearl": info.get("ctipearl", "")
        },
        "techniques": [
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "difficulty": t.difficulty,
                "apt_examples": t.apt_examples
            }
            for t in techniques
        ]
    })


@csrf.exempt
@app.route('/api/mitre/technique/<technique_id>')
@limiter.limit("30 per minute")
def get_mitre_technique(technique_id):
    technique_id = sanitize_input(technique_id, 20)
    technique = mitre_engine.get_technique(technique_id)

    if not technique:
        return jsonify({"error": "Technique not found."}), 404

    tactic_info = mitre_engine.get_tactic_info(technique.tactic)

    return jsonify({
        "id": technique.id,
        "name": technique.name,
        "tactic": {
            "id": technique.tactic.value,
            "name": tactic_info.get("name", technique.tactic.name)
        },
        "description": technique.description,
        "ctipearl": technique.ctipearl,
        "detection_tips": technique.detection_tips,
        "data_sources": technique.data_sources,
        "mitigations": technique.mitigations,
        "apt_examples": technique.apt_examples,
        "difficulty": technique.difficulty
    })


@csrf.exempt
@app.route('/api/mitre/search')
@limiter.limit("20 per minute")
def search_mitre():
    query = sanitize_input(request.args.get('q', ''), 100)
    if not query:
        return jsonify({"error": "Query parameter 'q' required."}), 400

    results = mitre_engine.search_techniques(query)
    return jsonify({
        "count": len(results),
        "results": [
            {
                "id": r.id,
                "name": r.name,
                "tactic": r.tactic.value,
                "description": r.description[:200] + "..." if len(r.description) > 200 else r.description
            }
            for r in results
        ]
    })


# ── API: Training ─────────────────────────────────────────────────────────────

@csrf.exempt
@app.route('/api/training/questions')
@limiter.limit("20 per minute")
def get_training_questions():
    category = sanitize_input(request.args.get('category', ''), 50) or None
    difficulty = sanitize_input(request.args.get('difficulty', ''), 50) or None
    count = request.args.get('count', 5, type=int)

    if not 1 <= count <= 20:
        return jsonify({"error": "Count must be between 1 and 20."}), 400

    questions = training_module.get_random_questions(count, category, difficulty)
    return jsonify({
        "count": len(questions),
        "questions": [
            {
                "question": q.question,
                "type": q.question_type.value,
                "options": q.options,
                "category": q.category,
                "difficulty": q.difficulty
            }
            for q in questions
        ]
    })


@csrf.exempt
@app.route('/api/training/check', methods=['POST'])
@limiter.limit("30 per minute")
def check_training_answer():
    if not validate_json_request():
        return jsonify({"error": "Invalid request."}), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON."}), 400

    question_text = sanitize_input(data.get('question', ''), 1000)
    user_answer = sanitize_input(data.get('answer', ''), 20)

    if not question_text:
        return jsonify({"error": "Question required."}), 400

    question = None
    for q in training_module.QUESTIONS:
        if q.question == question_text:
            question = q
            break

    if not question:
        return jsonify({"error": "Question not found."}), 404

    result = training_module.check_answer(question, user_answer)
    return jsonify(result)


@csrf.exempt
@app.route('/api/training/paths')
@limiter.limit("20 per minute")
def get_learning_paths():
    return jsonify({"paths": training_module.get_learning_paths()})


# ── API: Reports ──────────────────────────────────────────────────────────────

@csrf.exempt
@app.route('/api/report/generate', methods=['POST'])
@limiter.limit("10 per minute")
def generate_report():
    if not validate_json_request():
        return jsonify({"error": "Invalid request."}), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON."}), 400

    template_type = sanitize_input(data.get('template', ''), 50)
    report_data = data.get('data', {})

    if not isinstance(report_data, dict):
        return jsonify({"error": "Report data must be an object."}), 400

    safe_data = {}
    for key, value in report_data.items():
        if isinstance(value, str):
            safe_data[key] = sanitize_input(value, 10000)
        elif isinstance(value, list):
            safe_data[key] = [
                sanitize_input(v, 1000) if isinstance(v, str) else str(v)[:1000]
                for v in value[:50]
            ]
        else:
            safe_data[key] = str(value)[:1000]

    try:
        sections = report_engine.create_report(template_type, safe_data)
        report_dict = report_engine.report_to_dict(sections)
        return jsonify({"success": True, "report": report_dict})
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        return jsonify({"error": "Report generation failed."}), 500


@csrf.exempt
@app.route('/api/report/actors')
@limiter.limit("20 per minute")
def get_threat_actors():
    return jsonify({"actors": report_engine.list_actors()})


@csrf.exempt
@app.route('/api/report/actor/<actor_key>')
@limiter.limit("20 per minute")
def get_actor_profile(actor_key):
    actor = report_engine.get_threat_actor(actor_key)
    if not actor:
        return jsonify({"error": "Actor not found."}), 404

    return jsonify({
        "name": actor.name,
        "aliases": actor.aliases,
        "origin": actor.origin,
        "motivation": actor.motivation,
        "first_seen": actor.first_seen,
        "description": actor.description,
        "ttps": actor.ttps,
        "targeting": actor.targeting
    })


# ── API: TTP Mapper ───────────────────────────────────────────────────────────

@csrf.exempt
@app.route('/api/ttp/analyze', methods=['POST'])
@limiter.limit("15 per minute")
def analyze_ttp():
    if not validate_json_request():
        return jsonify({"error": "Invalid request."}), 400

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON."}), 400

    behavior = sanitize_input(data.get('behavior', ''), 5000)
    if not behavior:
        return jsonify({"error": "Behavior description required."}), 400

    keyword_map = {
        "phishing": [("T1566", "Phishing", "Initial Access")],
        "spearphish": [("T1566.001", "Spearphishing Attachment", "Initial Access")],
        "email": [("T1566", "Phishing", "Initial Access")],
        "powershell": [("T1059.001", "PowerShell", "Execution")],
        "wscript": [("T1059.005", "Visual Basic", "Execution")],
        "cscript": [("T1059.005", "Visual Basic", "Execution")],
        "cmd.exe": [("T1059.003", "Windows Command Shell", "Execution")],
        "command": [("T1059", "Command and Scripting Interpreter", "Execution")],
        "script": [("T1059", "Command and Scripting Interpreter", "Execution")],
        "registry run": [("T1547.001", "Registry Run Keys / Startup Folder", "Persistence")],
        "run key": [("T1547.001", "Registry Run Keys / Startup Folder", "Persistence")],
        "scheduled task": [("T1053.005", "Scheduled Task", "Persistence")],
        "cron": [("T1053.003", "Cron", "Persistence")],
        "service": [("T1543.003", "Windows Service", "Persistence")],
        "mimikatz": [("T1003.001", "LSASS Memory", "Credential Access")],
        "lsass": [("T1003.001", "LSASS Memory", "Credential Access")],
        "credential": [("T1003", "OS Credential Dumping", "Credential Access")],
        "hash": [("T1003", "OS Credential Dumping", "Credential Access")],
        "kerberoast": [("T1558.003", "Kerberoasting", "Credential Access")],
        "lateral": [("T1021", "Remote Services", "Lateral Movement")],
        "smb": [("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement")],
        "rdp": [("T1021.001", "Remote Desktop Protocol", "Lateral Movement")],
        "wmi": [("T1047", "Windows Management Instrumentation", "Execution")],
        "pass-the-hash": [("T1550.002", "Pass the Hash", "Lateral Movement")],
        "discovery": [("T1083", "File and Directory Discovery", "Discovery")],
        "nmap": [("T1046", "Network Service Scanning", "Discovery")],
        "scan": [("T1046", "Network Service Scanning", "Discovery")],
        "enumerate": [("T1083", "File and Directory Discovery", "Discovery")],
        "whoami": [("T1033", "System Owner/User Discovery", "Discovery")],
        "ipconfig": [("T1016", "System Network Configuration Discovery", "Discovery")],
        "exfil": [("T1041", "Exfiltration Over C2 Channel", "Exfiltration")],
        "ftp": [("T1048.003", "Exfiltration Over Unencrypted Protocol", "Exfiltration")],
        "encode": [("T1027", "Obfuscated Files or Information", "Defense Evasion")],
        "base64": [("T1027", "Obfuscated Files or Information", "Defense Evasion")],
        "obfuscat": [("T1027", "Obfuscated Files or Information", "Defense Evasion")],
        "encrypt": [("T1486", "Data Encrypted for Impact", "Impact")],
        "ransom": [("T1486", "Data Encrypted for Impact", "Impact")],
        "delete log": [("T1070", "Indicator Removal", "Defense Evasion")],
        "clear log": [("T1070.001", "Clear Windows Event Logs", "Defense Evasion")],
        "download": [("T1105", "Ingress Tool Transfer", "Command and Control")],
        "beacon": [("T1071", "Application Layer Protocol", "Command and Control")],
        "c2": [("T1071", "Application Layer Protocol", "Command and Control")],
        "dns tunnel": [("T1071.004", "DNS", "Command and Control")],
        "supply chain": [("T1195", "Supply Chain Compromise", "Initial Access")],
        "valid account": [("T1078", "Valid Accounts", "Initial Access")],
        "brute force": [("T1110", "Brute Force", "Credential Access")],
        "process inject": [("T1055", "Process Injection", "Defense Evasion")],
        "dll": [("T1574.001", "DLL Search Order Hijacking", "Privilege Escalation")],
    }

    matches = []
    behavior_lower = behavior.lower()
    for keyword, techniques in keyword_map.items():
        if keyword in behavior_lower:
            for tech_id, tech_name, tactic in techniques:
                if tech_id not in [m["technique_id"] for m in matches]:
                    matches.append({
                        "technique_id": tech_id,
                        "technique_name": tech_name,
                        "tactic": tactic,
                        "keyword_matched": keyword,
                        "confidence": "Low to Medium"
                    })

    return jsonify({
        "behavior_summary": behavior[:200] + "..." if len(behavior) > 200 else behavior,
        "mapped_techniques": matches,
        "count": len(matches),
        "note": (
            "Phoenix CTI Forge uses keyword-based mapping for educational purposes. "
            "For precise ATT&CK mapping, manual review against the full ATT&CK matrix "
            "is recommended. Confidence is Low-Medium without behavioral context."
        )
    })


# ── Security ──────────────────────────────────────────────────────────────────

@app.route('/templates/<path:path>')
@csrf.exempt
def block_templates(path):
    abort(404)


@app.context_processor
def inject_globals():
    return {
        'app_name': app.config.get('APP_NAME', 'Phoenix CTI Forge'),
        # FIX: was 'Phoenix_APP_VERSION' (typo); corrected to 'APP_VERSION'
        'app_version': app.config.get('APP_VERSION', '2.0.0'),
    }


if __name__ == '__main__':
    print("=" * 65)
    print("  Phoenix CTI Forge v2.0")
    print("  Cyber Threat Intelligence Educational Platform")
    print("  Created by Australian Phoenix CyberOps")
    print("=" * 65)
    print("  Starting on http://127.0.0.1:5000")
    print("  SECURITY NOTE: Educational tool only.")
    print("  Do not expose to the internet without hardening.")
    print("=" * 65)
    app.run(host='127.0.0.1', port=5000, debug=False)
