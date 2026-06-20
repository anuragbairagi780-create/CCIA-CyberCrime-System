from legal_knowledge import get_legal_kb
from flask import Flask, render_template, request, redirect, url_for, session, make_response, send_file, jsonify, Response
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

from ai.cyber_ai import analyze_complaint

import os
import re
import sqlite3
import hashlib
import datetime
import json
from functools import wraps
import requests

# Explicit path to .env file
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ─── CONFIG ──────────────────────────────────────────────────────────────────
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'mp3', 'mp4', 'wav', 'doc', 'docx'}
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")  # Optional
ENABLE_SEMANTIC = os.getenv("ENABLE_SEMANTIC", "true").lower() == "true"
ENABLE_CLUSTERING = os.getenv("ENABLE_CLUSTERING", "true").lower() == "true"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ─── DATABASE ────────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect("database/ccia.db")
    db.row_factory = sqlite3.Row
    return db

def init_db():
    os.makedirs("database", exist_ok=True)
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS officers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'officer',
            badge_no TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id TEXT UNIQUE NOT NULL,
            complaint_text TEXT NOT NULL,
            redacted_text TEXT,
            cluster_label TEXT,
            case_summary TEXT,
            crime_category TEXT,
            risk_level TEXT,
            risk_reason TEXT,
            key_indicators TEXT,
            investigation_steps TEXT,
            legal_sections TEXT,
            priority_action TEXT,
            indicators_json TEXT,
            officer_id INTEGER,
            status TEXT DEFAULT 'open',
            language TEXT DEFAULT 'english',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (officer_id) REFERENCES officers(id)
        );

        CREATE TABLE IF NOT EXISTS case_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id TEXT NOT NULL,
            officer_id INTEGER NOT NULL,
            officer_name TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (complaint_id) REFERENCES complaints(complaint_id),
            FOREIGN KEY (officer_id) REFERENCES officers(id)
        );

        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            file_size INTEGER,
            mime_type TEXT,
            uploaded_by INTEGER,
            uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            description TEXT,
            FOREIGN KEY (complaint_id) REFERENCES complaints(complaint_id),
            FOREIGN KEY (uploaded_by) REFERENCES officers(id)
        );

        CREATE TABLE IF NOT EXISTS case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            complaint_id TEXT NOT NULL,
            officer_id INTEGER NOT NULL,
            officer_name TEXT,
            note TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (complaint_id) REFERENCES complaints(complaint_id),
            FOREIGN KEY (officer_id) REFERENCES officers(id)
        );
    """)

    # ─── ADD MISSING COLUMNS (for existing databases) ──────────────────────
    try:
        db.execute("ALTER TABLE complaints ADD COLUMN redacted_text TEXT")
    except sqlite3.OperationalError:
        pass

    try:
        db.execute("ALTER TABLE complaints ADD COLUMN cluster_label TEXT")
    except sqlite3.OperationalError:
        pass

    pw = hashlib.sha256("admin123".encode()).hexdigest()
    try:
        db.execute("INSERT INTO officers (name, username, password, role, badge_no) VALUES (?,?,?,?,?)",
                   ("Administrator", "admin", pw, "admin", "ADMIN-001"))
    except:
        pass

    pw2 = hashlib.sha256("officer123".encode()).hexdigest()
    try:
        db.execute("INSERT INTO officers (name, username, password, role, badge_no) VALUES (?,?,?,?,?)",
                   ("Demo Officer", "officer", pw2, "officer", "CYB-2026-001"))
    except:
        pass

    db.commit()
    db.close()

init_db()

# ─── AUTH ────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "officer_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "officer_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def generate_complaint_id():
    db = get_db()
    count = db.execute("SELECT COUNT(*) as c FROM complaints").fetchone()["c"] + 1
    db.close()
    year = datetime.datetime.now().year
    return f"CCIA-{year}-{str(count).zfill(4)}"

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def extract_indicators(text):
    indicators = {}
    mobile = re.findall(r'\b[6-9]\d{9}\b', text)
    if mobile: indicators['mobile_numbers'] = list(set(mobile))
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
    if emails: indicators['email_ids'] = list(set(emails))
    urls = re.findall(r'http[s]?://\S+', text)
    if urls: indicators['urls'] = list(set(urls))
    upis = re.findall(r'\b[\w.\-]+@(?:paytm|upi|okaxis|okhdfcbank|okicici|oksbi|ybl|ibl|axl|apl|waicici|jupiteraxis|fam|axisbank|sbi|hdfc|icici|kotak|indus|federal|rbl|pnb|boi|canara|bob)\b', text, re.IGNORECASE)
    if upis: indicators['upi_ids'] = list(set(upis))
    accounts = re.findall(r'\b\d{9,18}\b', text)
    if accounts: indicators['possible_account_numbers'] = list(set(accounts[:5]))
    return indicators

def redact_pii(text):
    """Mask PII: phone, email, Aadhaar, PAN, accounts."""
    redacted = text
    
    # Phone: 9876543210 -> XXXXX3210
    redacted = re.sub(r'\b(\d{5})(\d{5})\b', r'XXXXX\2', redacted)
    
    # Email: john@gmail.com -> j****@gmail.com
    redacted = re.sub(r'\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[A-Z|a-z]{2,})\b', 
                      lambda m: m.group(1)[0] + '****' + '@' + m.group(2), redacted)
    
    # Aadhaar: 1234 5678 9012 -> XXXX XXXX 9012
    redacted = re.sub(r'\b(\d{4})\s*(\d{4})\s*(\d{4})\b', r'XXXX XXXX \3', redacted)
    
    # PAN: ABCDE1234F -> XXXXX1234F
    redacted = re.sub(r'\b([A-Z]{5})(\d{4})([A-Z])\b', r'XXXXX\2\3', redacted)
    
    # Bank Account: 123456789012 -> XXXXX9012
    redacted = re.sub(r'\b(\d{8})(\d{4})\b', r'XXXXXXXX\2', redacted)
    
    return redacted

def extract_timeline(text):
    """Extract time-based events from complaint text."""
    time_pattern = r'(\d{1,2}:\d{2}\s*(?:AM|PM)?)'
    times = re.findall(time_pattern, text, re.IGNORECASE)
    
    events = []
    for t in times:
        sentences = re.split(r'[.!?]+', text)
        for sent in sentences:
            if t in sent:
                events.append({
                    'time': t.strip(),
                    'event': sent.strip()
                })
                break
    
    seen = set()
    unique_events = []
    for e in events:
        key = e['time'] + e['event'][:20]
        if key not in seen:
            seen.add(key)
            unique_events.append(e)
    
    return unique_events[:6]

def log_action(complaint_id, action, details='', ip=None):
    """Log an action performed on a case."""
    db = get_db()
    try:
        db.execute(
            """INSERT INTO case_logs 
               (complaint_id, officer_id, officer_name, action, details, ip_address)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                complaint_id,
                session.get('officer_id'),
                session.get('officer_name', 'Unknown'),
                action,
                details,
                ip or request.remote_addr
            )
        )
        db.commit()
    except Exception as e:
        print(f"Logging error: {e}")
    finally:
        db.close()

# ─── FRAUD DNA ENGINE ──────────────────────────────────────────────────────

def generate_fraud_dna(complaint_text, indicators):
    """
    Generate a unique Fraud DNA fingerprint from complaint.
    Combines: language, UPI pattern, keywords, indicators, timing.
    """
    import hashlib
    
    # Extract language indicators
    language_markers = []
    if re.search(r'[हिन्दी]', complaint_text):
        language_markers.append('hindi')
    if re.search(r'[a-zA-Z]', complaint_text):
        language_markers.append('english')
    
    # Extract keywords
    keywords = []
    fraud_keywords = ['otp', 'upi', 'bank', 'account', 'kyc', 'fraud', 'scam', 
                      'investment', 'loan', 'refund', 'coupon', 'lucky draw',
                      'पैसे', 'बैंक', 'ओटीपी', 'यूपीआई', 'खाता']
    for kw in fraud_keywords:
        if kw.lower() in complaint_text.lower():
            keywords.append(kw)
    
    # UPI patterns
    upi_patterns = []
    for upi in indicators.get("upi_ids", []):
        if '@' in upi:
            upi_patterns.append(upi.split('@')[1])  # paytm, gpay, etc.
    
    # Create DNA string
    dna_parts = [
        '-'.join(sorted(language_markers)),
        '-'.join(sorted(keywords[:3])),
        '-'.join(sorted(upi_patterns[:2])),
        str(len(indicators.get("mobile_numbers", []))),
        str(len(indicators.get("upi_ids", [])))
    ]
    dna_string = '|'.join(dna_parts)
    dna_hash = hashlib.sha256(dna_string.encode()).hexdigest()[:12]
    
    return {
        'dna_id': f"FD-{dna_hash.upper()}",
        'dna_string': dna_string,
        'components': {
            'language': language_markers,
            'keywords': keywords[:5],
            'upi_patterns': upi_patterns[:3]
        }
    }

def find_matching_fraud_dna(dna_data, complaint_id):
    """
    Find if this Fraud DNA matches any previous complaints.
    """
    db = get_db()
    
    # Simple matching: check if similar DNA exists
    # For full implementation, we'd store DNA in DB
    matches = []
    
    # Check for similar keywords
    keywords = dna_data['components']['keywords']
    if keywords:
        # Build query to find cases with similar keywords
        conditions = []
        params = []
        for kw in keywords[:3]:
            conditions.append("complaint_text LIKE ?")
            params.append(f"%{kw}%")
        
        if conditions:
            query = f"""
                SELECT complaint_id, crime_category, risk_level, created_at
                FROM complaints
                WHERE complaint_id != ?
                AND ({' OR '.join(conditions)})
                LIMIT 10
            """
            similar_cases = db.execute(query, [complaint_id] + params).fetchall()
            
            for case in similar_cases:
                matches.append({
                    'complaint_id': case['complaint_id'],
                    'crime_category': case['crime_category'],
                    'risk_level': case['risk_level'],
                    'created_at': case['created_at']
                })
    
    db.close()
    return matches

# ─── CRIMINAL INFRASTRUCTURE MAPPER ──────────────────────────────────────

def analyze_criminal_infrastructure(complaint_id):
    """
    Analyze indicators to map criminal infrastructure.
    """
    db = get_db()
    case = db.execute("SELECT * FROM complaints WHERE complaint_id = ?", (complaint_id,)).fetchone()
    if not case:
        return None
    
    indicators = json.loads(case['indicators_json'] or '{}')
    
    # Analyze patterns
    analysis = {
        'gang_size': 0,
        'leader': None,
        'call_center_location': None,
        'mule_network': [],
        'crypto_exit': [],
        'confidence': 0
    }
    
    # Count unique indicators across all cases
    phones = indicators.get('mobile_numbers', [])
    upis = indicators.get('upi_ids', [])
    emails = indicators.get('email_ids', [])
    
    # Estimate gang size based on number of distinct indicators
    if phones:
        # Check how many complaints each phone appears in
        for phone in phones[:3]:
            count = db.execute(
                "SELECT COUNT(*) as c FROM complaints WHERE indicators_json LIKE ?",
                (f"%{phone}%",)
            ).fetchone()["c"]
            if count > 1:
                analysis['gang_size'] += count // 2
    
    # Find possible leader (most connected entity)
    all_indicators = []
    all_indicators.extend(phones)
    all_indicators.extend(upis)
    all_indicators.extend(emails)
    
    if all_indicators:
        # Find most frequent indicator
        max_count = 0
        leader = None
        for ind in set(all_indicators):
            count = db.execute(
                "SELECT COUNT(*) as c FROM complaints WHERE indicators_json LIKE ?",
                (f"%{ind}%",)
            ).fetchone()["c"]
            if count > max_count:
                max_count = count
                leader = ind
        analysis['leader'] = leader
    
    # Detect mule network (UPI IDs appearing in multiple complaints)
    for upi in upis[:3]:
        count = db.execute(
            "SELECT COUNT(*) as c FROM complaints WHERE indicators_json LIKE ?",
            (f"%{upi}%",)
        ).fetchone()["c"]
        if count > 2:
            analysis['mule_network'].append({upi: count})
    
    # Estimate confidence
    analysis['confidence'] = min(95, 50 + (len(phones) * 5) + (len(upis) * 3))
    
    db.close()
    return analysis

# ─── THREAT INTELLIGENCE ────────────────────────────────────────────────────

def enrich_with_threat_intel(indicators):
    threat_data = {}
    db = get_db()
    for indicator_type, items in indicators.items():
        for item in items:
            count = db.execute(
                "SELECT COUNT(*) as c FROM complaints WHERE indicators_json LIKE ?",
                (f"%{item}%",)
            ).fetchone()["c"]
            threat_data[item] = {
                "type": indicator_type,
                "repeat_count": count,
                "risk": "HIGH" if count > 5 else "MEDIUM" if count > 2 else "LOW",
                "virus_total": None
            }
    db.close()

    if VIRUSTOTAL_API_KEY:
        for item in indicators.get("urls", []) + indicators.get("email_ids", []):
            if '.' in item:
                domain = item.split('@')[-1] if '@' in item else item
                url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                try:
                    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
                    resp = requests.get(url, headers=headers, timeout=5)
                    if resp.status_code == 200:
                        data = resp.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        if malicious > 0:
                            threat_data[item]["virus_total"] = {
                                "malicious": malicious,
                                "suspicious": stats.get("suspicious", 0)
                            }
                            threat_data[item]["risk"] = "CRITICAL" if malicious > 3 else "HIGH"
                except:
                    pass
    return threat_data

# ─── SEMANTIC SIMILARITY ─────────────────────────────────────────────────────

_model = None

def get_semantic_model():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer, util
        import torch
        _model = SentenceTransformer('all-MiniLM-L6-v2')
    return _model

def find_semantic_similar_cases(complaint_text, top_n=5):
    if not ENABLE_SEMANTIC:
        return []
    try:
        db = get_db()
        all_cases = db.execute(
            "SELECT complaint_id, complaint_text, crime_category, risk_level, created_at FROM complaints ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
        db.close()
    except:
        return []

    if not all_cases:
        return []

    model = get_semantic_model()
    import torch
    from sentence_transformers import util

    current_embedding = model.encode(complaint_text, convert_to_tensor=True)
    past_texts = [case["complaint_text"] for case in all_cases]
    past_embeddings = model.encode(past_texts, convert_to_tensor=True)
    scores = util.pytorch_cos_sim(current_embedding, past_embeddings)[0]

    results = []
    for idx in torch.argsort(scores, descending=True):
        if scores[idx] > 0.5:
            case = all_cases[idx]
            if case["complaint_text"].strip() == complaint_text.strip():
                continue
            results.append({
                "complaint_id": case["complaint_id"],
                "similarity": float(scores[idx]),
                "crime_category": case["crime_category"],
                "risk_level": case["risk_level"],
                "created_at": case["created_at"]
            })
        if len(results) >= top_n:
            break
    return results

# ─── MODUS OPERANDI CLUSTERING ──────────────────────────────────────────────

_clustering_model = None
_cluster_embeddings = None
_cluster_labels = None

def get_clustering_model():
    global _clustering_model, _cluster_embeddings, _cluster_labels
    if _clustering_model is None and ENABLE_CLUSTERING:
        try:
            from sklearn.cluster import KMeans
            import numpy as np
            from sentence_transformers import SentenceTransformer
            
            db = get_db()
            cases = db.execute(
                "SELECT complaint_text FROM complaints WHERE complaint_text != ''"
            ).fetchall()
            db.close()
            
            if len(cases) < 3:
                return None, None, None
            
            model = SentenceTransformer('all-MiniLM-L6-v2')
            texts = [c["complaint_text"] for c in cases]
            embeddings = model.encode(texts, convert_to_numpy=True)
            
            n_clusters = min(max(2, len(cases) // 3), 6)
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            labels = kmeans.fit_predict(embeddings)
            
            db = get_db()
            for i, case in enumerate(cases):
                db.execute(
                    "UPDATE complaints SET cluster_label = ? WHERE complaint_text = ?",
                    (str(labels[i]), case["complaint_text"])
                )
            db.commit()
            db.close()
            
            _clustering_model = kmeans
            _cluster_embeddings = embeddings
            _cluster_labels = labels
            
            return kmeans, embeddings, labels
        except Exception as e:
            print(f"Clustering error: {e}")
            return None, None, None
    return _clustering_model, _cluster_embeddings, _cluster_labels

def assign_cluster_for_text(complaint_text):
    if not ENABLE_CLUSTERING:
        return "Unknown"
    try:
        from sklearn.cluster import KMeans
        import numpy as np
        from sentence_transformers import SentenceTransformer
        
        db = get_db()
        existing = db.execute(
            "SELECT cluster_label FROM complaints WHERE complaint_text = ?",
            (complaint_text,)
        ).fetchone()
        if existing and existing["cluster_label"]:
            db.close()
            return existing["cluster_label"]
        
        model = get_semantic_model()
        embedding = model.encode(complaint_text, convert_to_numpy=True).reshape(1, -1)
        
        kmeans, _, _ = get_clustering_model()
        if kmeans is None:
            db.close()
            return "Unclassified"
        
        label = kmeans.predict(embedding)[0]
        
        db.execute(
            "UPDATE complaints SET cluster_label = ? WHERE complaint_text = ?",
            (str(label), complaint_text)
        )
        db.commit()
        db.close()
        
        return str(label)
    except Exception as e:
        print(f"Cluster assign error: {e}")
        return "Unclassified"

# ─── FINANCIAL MULE DETECTION ──────────────────────────────────────────────

def detect_mules(indicators):
    """
    Analyze indicators to identify potential mule accounts/UPIs.
    Returns list of potential mules with risk score.
    """
    mules = []
    db = get_db()
    
    # Check UPI IDs
    for upi in indicators.get("upi_ids", []):
        count = db.execute(
            "SELECT COUNT(*) as c FROM complaints WHERE indicators_json LIKE ?",
            (f"%{upi}%",)
        ).fetchone()["c"]
        if count >= 2:
            mules.append({
                "indicator": upi,
                "type": "UPI",
                "count": count,
                "risk": "HIGH" if count > 5 else "MEDIUM"
            })
    
    # Check bank account numbers (if any)
    for acc in indicators.get("possible_account_numbers", []):
        count = db.execute(
            "SELECT COUNT(*) as c FROM complaints WHERE indicators_json LIKE ?",
            (f"%{acc}%",)
        ).fetchone()["c"]
        if count >= 2:
            mules.append({
                "indicator": acc,
                "type": "Bank Account",
                "count": count,
                "risk": "HIGH" if count > 5 else "MEDIUM"
            })
    
    # Check phone numbers that appear as receiver in multiple complaints
    for phone in indicators.get("mobile_numbers", []):
        count = db.execute(
            "SELECT COUNT(*) as c FROM complaints WHERE indicators_json LIKE ?",
            (f"%{phone}%",)
        ).fetchone()["c"]
        if count >= 3:
            mules.append({
                "indicator": phone,
                "type": "Phone",
                "count": count,
                "risk": "HIGH" if count > 5 else "MEDIUM"
            })
    
    db.close()
    return mules

# ─── AI INVESTIGATOR COPILOT (RAG) ──────────────────────────────────────────

# Pre‑defined legal knowledge base (IPC, IT Act, etc.)
LEGAL_KNOWLEDGE = [
    {
        "id": "it_66c",
        "section": "IT Act 66C",
        "text": "Punishment for identity theft: Whoever fraudulently or dishonestly makes use of the electronic signature, password or any other unique identification feature of any other person shall be punished with imprisonment of either description for a term which may extend to three years and shall also be liable to fine which may extend to rupees one lakh.",
        "keywords": ["identity theft", "password", "electronic signature", "unique identification"]
    },
    {
        "id": "it_66d",
        "section": "IT Act 66D",
        "text": "Punishment for cheating by personation by using computer resource: Whoever, by means of any communication device or computer resource, cheats by personation shall be punished with imprisonment of either description for a term which may extend to three years and shall also be liable to fine which may extend to one lakh rupees.",
        "keywords": ["cheating", "personation", "computer resource", "communication device"]
    },
    {
        "id": "ipc_420",
        "section": "IPC 420",
        "text": "Cheating and dishonestly inducing delivery of property: Whoever cheats and thereby dishonestly induces the person deceived to deliver any property to any person, or to make, alter or destroy the whole or any part of a valuable security, or anything which is signed or sealed, and which is capable of being converted into a valuable security, shall be punished with imprisonment of either description for a term which may extend to seven years, and shall also be liable to fine.",
        "keywords": ["cheating", "inducing delivery", "property", "valuable security"]
    },
    {
        "id": "ipc_419",
        "section": "IPC 419",
        "text": "Punishment for cheating by personation: Whoever cheats by personation shall be punished with imprisonment of either description for a term which may extend to three years, or with fine, or with both.",
        "keywords": ["personation", "cheating"]
    },
    {
        "id": "it_43",
        "section": "IT Act 43",
        "text": "Penalty for damage to computer, computer system, etc.: If any person without permission of the owner or any other person who is in-charge of a computer, computer system or computer network, accesses or secures access to such computer, computer system or computer network, he shall be liable to pay damages by way of compensation not exceeding one crore rupees to the person so affected.",
        "keywords": ["unauthorized access", "computer system", "damage", "compensation"]
    },
    {
        "id": "it_66",
        "section": "IT Act 66",
        "text": "Computer related offences: If any person, dishonestly or fraudulently, does any act referred to in section 43, he shall be punishable with imprisonment for a term which may extend to three years or with fine which may extend to five lakh rupees or with both.",
        "keywords": ["computer related offences", "dishonest", "fraudulent"]
    },
    {
        "id": "bnss_154",
        "section": "BNSS 154",
        "text": "Information in cognizable offences: Every information relating to the commission of a cognizable offence, if given orally to an officer in charge of a police station, shall be reduced to writing and be read over to the informant, and shall be signed by the person giving it.",
        "keywords": ["cognizable offence", "information", "police station", "FIR"]
    },
    {
        "id": "bnss_157",
        "section": "BNSS 157",
        "text": "Procedure for investigation: If, from information received or otherwise, an officer in charge of a police station has reason to suspect the commission of an offence which he is empowered to investigate, he shall proceed to the spot to investigate the facts and circumstances of the case.",
        "keywords": ["investigation", "suspect", "commission of offence", "spot investigation"]
    },
    {
        "id": "fema_laws",
        "section": "FEMA & PMLA",
        "text": "For financial frauds involving money laundering, the Prevention of Money Laundering Act (PMLA) 2002 and Foreign Exchange Management Act (FEMA) provisions may apply. Investigation should involve FIU reporting and seizure of assets.",
        "keywords": ["money laundering", "FIU", "PMLA", "FEMA", "asset seizure"]
    }
]

def get_copilot_response(question, complaint_text=""):
    """
    Updated with scoring mechanism to accurately detect case type.
    """
    question_lower = question.lower()
    context = question + " " + complaint_text
    context_lower = context.lower()
    
    # ─── SCORING SYSTEM ──────────────────────────────────────────────────
    scores = {
        "otp_fraud": 0,
        "investment_scam": 0,
        "call_center_fraud": 0,
        "kyc_fraud": 0,
        "romance_scam": 0,
        "job_scam": 0,
        "general": 10  # default
    }
    
    # OTP / UPI Fraud keywords
    if any(word in context_lower for word in ["otp", "upi", "debit", "transaction", "fraud@", "payment", "account number", "bank account"]):
        scores["otp_fraud"] += 15
    if "otp" in context_lower:
        scores["otp_fraud"] += 10
    if "upi" in context_lower:
        scores["otp_fraud"] += 10
    
    # Investment Scam keywords
    if any(word in context_lower for word in ["investment", "profit", "return", "stock", "share", "trading", "crypto", "bitcoin", "scheme", "lakh", "crore", "sebi", "share market", "mutual fund", "dividend"]):
        scores["investment_scam"] += 25
    if "investment" in context_lower or "profit" in context_lower:
        scores["investment_scam"] += 15
    
    # Call Center / Vishing keywords
    if any(word in context_lower for word in ["call", "phone", "number", "dial", "helpline", "customer care", "agent", "vishing", "telephone"]):
        scores["call_center_fraud"] += 15
    if "call" in context_lower or "phone" in context_lower:
        scores["call_center_fraud"] += 10
    
    # KYC Fraud keywords
    if any(word in context_lower for word in ["kyc", "update", "verify", "aadhaar", "pan", "document", "identity", "know your customer"]):
        scores["kyc_fraud"] += 20
    if "kyc" in context_lower:
        scores["kyc_fraud"] += 10
    
    # Romance Scam keywords
    if any(word in context_lower for word in ["girl", "boy", "love", "marriage", "dating", "relationship", "match", "tinder", "bumble", "chat", "affection"]):
        scores["romance_scam"] += 20
    if "love" in context_lower or "marriage" in context_lower:
        scores["romance_scam"] += 15
    
    # Job Scam keywords
    if any(word in context_lower for word in ["job", "employment", "recruitment", "offer", "salary", "interview", "hiring", "vacancy", "placement", "career"]):
        scores["job_scam"] += 20
    if "job" in context_lower or "salary" in context_lower:
        scores["job_scam"] += 15
    
    # ─── SELECT HIGHEST SCORE ────────────────────────────────────────────
    case_type = max(scores, key=scores.get)
    case_confidence = min(95, scores[case_type] + 70)
    
    # Ensure confidence is not too low
    if case_confidence < 60:
        case_confidence = 60
    
    # ─── RESPONSE BUILDING ──────────────────────────────────────────────
    
    # ─── OTP / UPI FRAUD ──────────────────────────────────────────────────
    if case_type == "otp_fraud" and ("bns" in question_lower or "section" in question_lower or "act" in question_lower or "law" in question_lower or "apply" in question_lower or "ipc" in question_lower):
        return f"""
**🔍 Case Type: OTP / UPI Fraud**
**Confidence: {case_confidence}%**

**Applicable Legal Framework (BNS/IT Act):**

• **BNS Section 318** – Cheating *(replaces IPC 420)*  
  *"Whoever cheats and thereby dishonestly induces delivery of property..."*

• **BNS Section 319** – Cheating by Personation *(replaces IPC 419)*

• **IT Act 66C** – Identity Theft  
  *"Fraudulent use of electronic signature, password, or unique identification feature"*

• **IT Act 66D** – Cheating by Personation using computer resource

• **BNSS Section 173** – Registration of FIR *(replaces CrPC 154)*

---

**📋 Recommended Actions:**

1. **Immediate:** Report to bank & NPCI to freeze beneficiary account.
2. **Preserve Evidence:** Transaction ID, SMS logs, call recordings, screenshots.
3. **File FIR:** Under BNS 318/319 and IT Act 66C/66D.
4. **Cyber Cell:** Approach nearest cyber police station.
5. **NCRP:** File complaint at www.cybercrime.gov.in.
"""

    # ─── INVESTMENT SCAM ──────────────────────────────────────────────────
    elif case_type == "investment_scam" and ("bns" in question_lower or "section" in question_lower or "act" in question_lower or "law" in question_lower or "apply" in question_lower or "ipc" in question_lower):
        return f"""
**🔍 Case Type: Investment / Trading Scam**
**Confidence: {case_confidence}%**

**Applicable Legal Framework (BNS/IT Act/PMLA/SEBI):**

• **BNS Section 318** – Cheating *(replaces IPC 420)*

• **BNS Section 316** – Criminal Breach of Trust *(replaces IPC 406)*

• **BNS Section 319** – Cheating by Personation *(replaces IPC 419)*

• **PMLA 2002** – Prevention of Money Laundering Act *(for money trail & layering)*

• **SEBI Act** – if unregistered investment schemes or stock market fraud

• **IT Act 66D** – Cheating by Personation using computer resource

• **BNSS Section 173** – FIR Registration *(replaces CrPC 154)*

---

**📋 Recommended Actions:**

1. **Immediate:** Report to Economic Offences Wing (EOW) and SEBI.
2. **Freeze Accounts:** Report to bank to freeze beneficiary accounts.
3. **Preserve Evidence:** Investment documents, payment receipts, WhatsApp/Telegram chats, website screenshots.
4. **File FIR:** Under BNS 318/316/319 and IT Act 66D.
5. **FIU Reporting:** If money laundering suspected, report to Financial Intelligence Unit (FIU-IND).
6. **NCRP:** File complaint at www.cybercrime.gov.in.
"""

    # ─── CALL CENTER FRAUD ────────────────────────────────────────────────
    elif case_type == "call_center_fraud" and ("bns" in question_lower or "section" in question_lower or "act" in question_lower or "law" in question_lower or "apply" in question_lower or "ipc" in question_lower):
        return f"""
**🔍 Case Type: Call Center / Vishing Fraud**
**Confidence: {case_confidence}%**

**Applicable Legal Framework (BNS/IT Act/TRAI):**

• **BNS Section 319** – Cheating by Personation *(replaces IPC 419)*

• **BNS Section 318** – Cheating *(replaces IPC 420)*

• **IT Act 66D** – Cheating by Personation using computer resource

• **IT Act 43** – Unauthorized access to computer system

• **TRAI Guidelines** – Misuse of telecom resources

• **BNSS Section 173** – FIR Registration *(replaces CrPC 154)*

---

**📋 Recommended Actions:**

1. **Immediate:** Report to telecom provider to block the number.
2. **Preserve Evidence:** Call recordings, caller ID logs, SMS logs.
3. **File FIR:** Under BNS 319/318 and IT Act 66D.
4. **Sanchar Saathi:** Report on Sanchar Saathi portal (SIM/IMEI tracking).
5. **Cyber Cell:** Approach nearest cyber police station.
"""

    # ─── KYC FRAUD ────────────────────────────────────────────────────────
    elif case_type == "kyc_fraud" and ("bns" in question_lower or "section" in question_lower or "act" in question_lower or "law" in question_lower or "apply" in question_lower or "ipc" in question_lower):
        return f"""
**🔍 Case Type: Fake KYC / Identity Theft Fraud**
**Confidence: {case_confidence}%**

**Applicable Legal Framework (BNS/IT Act/Aadhaar Act):**

• **BNS Section 318** – Cheating *(replaces IPC 420)*

• **BNS Section 319** – Cheating by Personation *(replaces IPC 419)*

• **IT Act 66C** – Identity Theft

• **IT Act 66D** – Cheating by Personation

• **Aadhaar Act** – Misuse of Aadhaar credentials

• **BNSS Section 173** – FIR Registration *(replaces CrPC 154)*

---

**📋 Recommended Actions:**

1. **Immediate:** Report to bank and freeze accounts.
2. **Preserve Evidence:** SMS logs, fake KYC links, communication.
3. **File FIR:** Under BNS 318/319 and IT Act 66C/66D.
4. **UIDAI:** Report unauthorized Aadhaar use to UIDAI.
5. **Cyber Cell:** Approach nearest cyber police station.
"""

    # ─── ROMANCE SCAM ─────────────────────────────────────────────────────
    elif case_type == "romance_scam" and ("bns" in question_lower or "section" in question_lower or "act" in question_lower or "law" in question_lower or "apply" in question_lower or "ipc" in question_lower):
        return f"""
**🔍 Case Type: Romance / Dating Scam**
**Confidence: {case_confidence}%**

**Applicable Legal Framework (BNS/IT Act):**

• **BNS Section 318** – Cheating *(replaces IPC 420)*

• **BNS Section 319** – Cheating by Personation *(replaces IPC 419)*

• **BNS Section 316** – Criminal Breach of Trust *(replaces IPC 406)*

• **IT Act 66D** – Cheating by Personation

• **BNSS Section 173** – FIR Registration *(replaces CrPC 154)*

---

**📋 Recommended Actions:**

1. **Immediate:** Report to nearest police station.
2. **Preserve Evidence:** Chat logs, call recordings, photos, transaction details.
3. **File FIR:** Under BNS 318/319/316 and IT Act 66D.
4. **Social Media:** Report profile to the platform.
5. **Cyber Cell:** Approach nearest cyber police station.
"""

    # ─── JOB SCAM ─────────────────────────────────────────────────────────
    elif case_type == "job_scam" and ("bns" in question_lower or "section" in question_lower or "act" in question_lower or "law" in question_lower or "apply" in question_lower or "ipc" in question_lower):
        return f"""
**🔍 Case Type: Fake Job / Employment Scam**
**Confidence: {case_confidence}%**

**Applicable Legal Framework (BNS/IT Act):**

• **BNS Section 318** – Cheating *(replaces IPC 420)*

• **BNS Section 316** – Criminal Breach of Trust *(replaces IPC 406)*

• **IT Act 66D** – Cheating by Personation

• **BNSS Section 173** – FIR Registration *(replaces CrPC 154)*

---

**📋 Recommended Actions:**

1. **Immediate:** Report to nearest police station.
2. **Preserve Evidence:** Job offer emails, payment receipts, company details, communication.
3. **File FIR:** Under BNS 318/316 and IT Act 66D.
4. **Labour Department:** Report fraudulent recruitment to state labour dept.
5. **Cyber Cell:** Approach nearest cyber police station.
"""

    # ─── GENERAL / FALLBACK ──────────────────────────────────────────────
    else:
        if any(word in question_lower for word in ["bns", "section", "act", "law", "legal", "apply", "ipc"]):
            return """
**📜 Updated Legal Framework (BNS/BNSS/BSA 2023):**

*Effective from 1st July 2024.*

**General Cybercrime Sections:**

• **BNS Section 318** – Cheating (replaces IPC 420)
• **BNS Section 319** – Cheating by Personation (replaces IPC 419)
• **BNS Section 316** – Criminal Breach of Trust (replaces IPC 406)
• **IT Act 66C** – Identity Theft
• **IT Act 66D** – Cheating by Personation using Computer Resource
• **BNSS Section 173** – FIR Registration (replaces CrPC 154)

---

**Recommended Actions:**

1. File FIR under BNS 318/319/316 and IT Act 66C/66D.
2. Preserve all evidence.
3. Approach nearest cyber police station.
4. File complaint on NCRP portal.

*Please provide more details about the case for specific legal advice.*
"""
        
        return "I couldn't determine the specific case type. Please provide more details about the complaint, or consult with a legal expert."
#---------REBUILD KNOWLEDGE --------
@app.route("/admin/rebuild-knowledge")
@admin_required
def rebuild_knowledge():
    import os
    from legal_knowledge import get_legal_kb
    kb = get_legal_kb()
    folder = os.path.join(os.path.dirname(__file__), 'legal_docs')
    if not os.path.exists(folder):
        return "Create a folder 'legal_docs' and place your PDF files (BNS, IT Act, etc.) inside."
    success = kb.load_documents(folder)
    if success:
        return "Knowledge base rebuilt successfully!"
    else:
        return "Failed to rebuild. Check logs."
# ─── CYBERCRIME COMMAND CENTER ────────────────────────────────────────────

@app.route("/command-center")
@login_required
def command_center():
    return render_template("command_center.html")

@app.route("/api/command-center-data")
@login_required
def command_center_data():
    db = get_db()
    
    # State-wise statistics
    state_data = {}
    states = ['Uttar Pradesh', 'Maharashtra', 'Delhi', 'Rajasthan', 
              'Bihar', 'West Bengal', 'Tamil Nadu', 'Karnataka']
    
    for state in states:
        count = db.execute(
            "SELECT COUNT(*) as c FROM complaints WHERE complaint_text LIKE ?",
            (f"%{state}%",)
        ).fetchone()["c"]
        if count > 0:
            state_data[state] = count
    
    # Latest 10 complaints for live feed
    latest = db.execute(
        "SELECT complaint_id, crime_category, risk_level, created_at FROM complaints ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    
    # Active campaigns (clusters)
    clusters = db.execute("""
        SELECT cluster_label, COUNT(*) as count FROM complaints
        WHERE cluster_label IS NOT NULL AND cluster_label != ''
        GROUP BY cluster_label ORDER BY count DESC LIMIT 5
    """).fetchall()
    
    db.close()
    
    return jsonify({
        'state_data': state_data,
        'latest': [dict(row) for row in latest],
        'clusters': [dict(row) for row in clusters]
    })

# ─── ROUTES ──────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET","POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        db = get_db()
        officer = db.execute("SELECT * FROM officers WHERE username=? AND password=?",
                             (username, hash_password(password))).fetchone()
        db.close()
        if officer:
            session["officer_id"] = officer["id"]
            session["officer_name"] = officer["name"]
            session["role"] = officer["role"]
            session["badge_no"] = officer["badge_no"]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    db = get_db()
    total = db.execute("SELECT COUNT(*) as c FROM complaints").fetchone()["c"]
    critical = db.execute("SELECT COUNT(*) as c FROM complaints WHERE risk_level='CRITICAL'").fetchone()["c"]
    high = db.execute("SELECT COUNT(*) as c FROM complaints WHERE risk_level='HIGH'").fetchone()["c"]
    open_cases = db.execute("SELECT COUNT(*) as c FROM complaints WHERE status='open'").fetchone()["c"]
    recent = db.execute("""
        SELECT c.*, o.name as officer_name FROM complaints c
        LEFT JOIN officers o ON c.officer_id = o.id
        ORDER BY c.created_at DESC LIMIT 5
    """).fetchall()
    categories = db.execute("""
        SELECT crime_category, COUNT(*) as count FROM complaints
        GROUP BY crime_category ORDER BY count DESC LIMIT 6
    """).fetchall()

    monthly = db.execute("""
        SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as count
        FROM complaints
        WHERE created_at >= date('now', '-5 months')
        GROUP BY month
        ORDER BY month ASC
    """).fetchall()

    clusters = db.execute("""
        SELECT cluster_label, COUNT(*) as count FROM complaints
        WHERE cluster_label IS NOT NULL AND cluster_label != ''
        GROUP BY cluster_label ORDER BY count DESC
    """).fetchall()

    cluster_labels = [c["cluster_label"] for c in clusters]
    cluster_counts = [c["count"] for c in clusters]

    monthly_labels = [m['month'] for m in monthly]
    monthly_counts = [m['count'] for m in monthly]
    cat_labels = [c['crime_category'] or 'Unknown' for c in categories]
    cat_counts = [c['count'] for c in categories]

    db.close()
    return render_template("dashboard.html",
        total=total, critical=critical, high=high,
        open_cases=open_cases, recent=recent, categories=categories,
        monthly_labels=monthly_labels, monthly_counts=monthly_counts,
        cat_labels=cat_labels, cat_counts=cat_counts,
        cluster_labels=cluster_labels, cluster_counts=cluster_counts
    )

@app.route("/analyze", methods=["GET","POST"])
@login_required
def analyze():
    result = None
    complaint = ""
    error = ""
    indicators = {}
    saved_id = None
    language = "english"

    if request.method == "POST":
        complaint = request.form.get("complaint","").strip()
        language = request.form.get("language","english")
        if not complaint:
            error = "Please enter a complaint."
        elif len(complaint) < 20:
            error = "Complaint is too short. Please provide more details."
        else:
            indicators = extract_indicators(complaint)
            result = analyze_complaint(complaint)

            # Repeat Offender Check
            db = get_db()
            repeat_details = {}

            for upi in indicators.get("upi_ids", []):
                count = db.execute(
                    "SELECT COUNT(*) as c FROM complaints WHERE indicators_json LIKE ?",
                    (f"%{upi}%",),
                ).fetchone()["c"]
                if count > 0:
                    repeat_details[upi] = {"type": "UPI", "count": count}

            for phone in indicators.get("mobile_numbers", []):
                count = db.execute(
                    "SELECT COUNT(*) as c FROM complaints WHERE indicators_json LIKE ?",
                    (f"%{phone}%",),
                ).fetchone()["c"]
                if count > 0:
                    repeat_details[phone] = {"type": "Phone", "count": count}

            for email in indicators.get("email_ids", []):
                count = db.execute(
                    "SELECT COUNT(*) as c FROM complaints WHERE indicators_json LIKE ?",
                    (f"%{email}%",),
                ).fetchone()["c"]
                if count > 0:
                    repeat_details[email] = {"type": "Email", "count": count}

            db.close()

            result["repeat_details"] = repeat_details
            if repeat_details:
                total_repeats = sum(v["count"] for v in repeat_details.values())
                result["repeat_alert"] = f"⚠️ {len(repeat_details)} fraud indicator(s) found in {total_repeats} previous complaints"
                if result.get("risk_level") in ["MEDIUM", "LOW"]:
                    result["risk_level"] = "HIGH"
                    result["risk_reason"] = "Escalated due to repeat indicators"
            else:
                result["repeat_alert"] = None

            redacted = redact_pii(complaint)
            cluster = assign_cluster_for_text(complaint)

            cid = generate_complaint_id()
            db = get_db()
            db.execute(
                """
                INSERT INTO complaints
                (complaint_id, complaint_text, redacted_text, cluster_label, case_summary, crime_category,
                 risk_level, risk_reason, key_indicators, investigation_steps,
                 legal_sections, priority_action, indicators_json, officer_id, language)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    cid,
                    complaint,
                    redacted,
                    cluster,
                    result["case_summary"],
                    result["crime_category"],
                    result["risk_level"],
                    result["risk_reason"],
                    json.dumps(result["key_indicators"]),
                    json.dumps(result["investigation_steps"]),
                    result["legal_sections"],
                    result["priority_action"],
                    json.dumps(indicators),
                    session["officer_id"],
                    language,
                ),
            )
            db.commit()
            db.close()
            saved_id = cid

    return render_template("analyze.html",
        result=result, complaint=complaint, error=error,
        indicators=indicators, saved_id=saved_id, language=language)

@app.route("/history")
@login_required
def history():
    search = request.args.get("search","").strip()
    risk_filter = request.args.get("risk","")
    category_filter = request.args.get("category","")
    status_filter = request.args.get("status","")
    page = int(request.args.get("page", 1))
    per_page = 10

    db = get_db()
    query = "SELECT c.*, o.name as officer_name FROM complaints c LEFT JOIN officers o ON c.officer_id = o.id WHERE 1=1"
    params = []

    if search:
        query += " AND (c.complaint_id LIKE ? OR c.complaint_text LIKE ? OR c.crime_category LIKE ?)"
        params += [f"%{search}%", f"%{search}%", f"%{search}%"]
    if risk_filter:
        query += " AND c.risk_level = ?"
        params.append(risk_filter)
    if category_filter:
        query += " AND c.crime_category LIKE ?"
        params.append(f"%{category_filter}%")
    if status_filter:
        query += " AND c.status = ?"
        params.append(status_filter)

    total_count = db.execute(f"SELECT COUNT(*) as c FROM ({query})", params).fetchone()["c"]
    query += " ORDER BY c.created_at DESC LIMIT ? OFFSET ?"
    params += [per_page, (page-1)*per_page]

    complaints = db.execute(query, params).fetchall()
    categories = db.execute("SELECT DISTINCT crime_category FROM complaints WHERE crime_category != ''").fetchall()
    db.close()

    total_pages = (total_count + per_page - 1) // per_page
    return render_template("history.html",
        complaints=complaints, search=search, risk_filter=risk_filter,
        category_filter=category_filter, status_filter=status_filter,
        page=page, total_pages=total_pages, total_count=total_count,
        categories=categories)

@app.route("/case/<complaint_id>")
@login_required
def view_case(complaint_id):
    db = get_db()
    case = db.execute("""
        SELECT c.*, o.name as officer_name, o.badge_no FROM complaints c
        LEFT JOIN officers o ON c.officer_id = o.id
        WHERE c.complaint_id = ?
    """, (complaint_id,)).fetchone()
    if not case:
        return redirect(url_for("history"))

    case = dict(case)
    case['key_indicators'] = json.loads(case['key_indicators'] or '[]')
    case['investigation_steps'] = json.loads(case['investigation_steps'] or '[]')
    case['indicators_json'] = json.loads(case['indicators_json'] or '{}')
    case['timeline'] = extract_timeline(case['complaint_text'])

    # Similar Cases (keyword-based)
    similar_cases = []
    indicators = case['indicators_json']
    search_terms = []
    search_terms.extend(indicators.get("upi_ids", [])[:2])
    search_terms.extend(indicators.get("mobile_numbers", [])[:2])
    search_terms.extend(indicators.get("email_ids", [])[:2])

    if search_terms:
        conditions = []
        params_similar = [complaint_id]
        for term in search_terms:
            if term:
                conditions.append("indicators_json LIKE ?")
                params_similar.append(f"%{term}%")
        if conditions:
            sql_similar = f"""
                SELECT complaint_id, crime_category, risk_level, created_at
                FROM complaints
                WHERE complaint_id != ?
                AND ({' OR '.join(conditions)})
                LIMIT 5
            """
            similar_cases = db.execute(sql_similar, params_similar).fetchall()

    # Logs and Evidence
    logs = db.execute(
        "SELECT * FROM case_logs WHERE complaint_id = ? ORDER BY created_at DESC LIMIT 50",
        (complaint_id,)
    ).fetchall()

    evidence_list = db.execute(
        "SELECT * FROM evidence WHERE complaint_id = ? ORDER BY uploaded_at DESC",
        (complaint_id,)
    ).fetchall()

    notes = db.execute(
        "SELECT * FROM case_notes WHERE complaint_id = ? ORDER BY created_at DESC",
        (complaint_id,)
    ).fetchall()

    threat_intel = enrich_with_threat_intel(indicators)
    semantic_similar = find_semantic_similar_cases(case["complaint_text"])

    # ─── FINANCIAL MULE DETECTION ──────────────────────────────────────────
    mules = detect_mules(indicators)

    # ─── FRAUD DNA ENGINE ──────────────────────────────────────────────────
    dna_data = generate_fraud_dna(case['complaint_text'], indicators)
    dna_matches = find_matching_fraud_dna(dna_data, complaint_id)

    # ─── CRIMINAL INFRASTRUCTURE MAPPER ──────────────────────────────────
    infrastructure = analyze_criminal_infrastructure(complaint_id)

    db.close()

    log_action(complaint_id, 'viewed', f"Viewed case {complaint_id}")

    return render_template("case_detail.html",
        case=case,
        similar_cases=similar_cases,
        semantic_similar=semantic_similar,
        case_logs=logs,
        evidence_list=evidence_list,
        threat_intel=threat_intel,
        notes=notes,
        mules=mules,
        dna_matches=dna_matches,          # Pass to template
        infrastructure=infrastructure     # Pass to template
    )

# ─── ADD NOTE ────────────────────────────────────────────────────────────────

@app.route("/case/<complaint_id>/note", methods=["POST"])
@login_required
def add_note(complaint_id):
    note_text = request.form.get("note", "").strip()
    if note_text:
        db = get_db()
        db.execute(
            """INSERT INTO case_notes (complaint_id, officer_id, officer_name, note)
               VALUES (?, ?, ?, ?)""",
            (complaint_id, session['officer_id'], session['officer_name'], note_text)
        )
        db.commit()
        db.close()
        log_action(complaint_id, 'added_note', f"Added note: {note_text[:50]}...")
    return redirect(url_for("view_case", complaint_id=complaint_id))

# ─── AI COPILOT ROUTE ──────────────────────────────────────────────────────

@app.route("/case/<complaint_id>/copilot", methods=["POST"])
@login_required
def copilot(complaint_id):
    data = request.get_json()
    question = data.get("question", "").strip()
    if not question:
        return jsonify({"error": "Please enter a question"}), 400

    db = get_db()
    case = db.execute("SELECT complaint_text FROM complaints WHERE complaint_id = ?", (complaint_id,)).fetchone()
    db.close()
    if not case:
        return jsonify({"error": "Case not found"}), 404

    # ─── RAG SEARCH ──────────────────────────────────────────────────────
    kb = get_legal_kb()
    results = kb.query(question, top_k=5)
    
    if results:
        response = "**📜 Relevant Legal Provisions Found (from official documents):**\n\n"
        for i, res in enumerate(results, 1):
            chunk = res['chunk']
            source = chunk['source']
            text = chunk['text'][:600]  # limit for readability
            response += f"**{i}. Source: {source}** (Relevance: {1/(res['score']+0.1):.2f})\n{text}...\n\n"
        response += "\n*Please consult with a legal expert for exact applicability.*"
    else:
        # Fallback to rule‑based templates
        response = get_copilot_response(question, case["complaint_text"])
    
    return jsonify({"response": response})

# ─── GLOBAL THREAT GRAPH ──────────────────────────────────────────────────

@app.route("/global-network")
@login_required
def global_network():
    from pyvis.network import Network
    import networkx as nx

    db = get_db()
    all_cases = db.execute(
        "SELECT complaint_id, indicators_json FROM complaints ORDER BY created_at DESC LIMIT 100"
    ).fetchall()
    db.close()

    G = nx.Graph()

    # Build nodes and edges
    for case in all_cases:
        indicators = json.loads(case["indicators_json"] or "{}")
        nodes = []
        for typ, items in indicators.items():
            for item in items[:2]:  # limit per case to keep graph manageable
                node_id = f"{typ}_{item}"
                if not G.has_node(node_id):
                    G.add_node(node_id, label=item, type=typ)
                nodes.append(node_id)
        # Connect all nodes in this case
        for i in range(len(nodes)):
            for j in range(i+1, len(nodes)):
                G.add_edge(nodes[i], nodes[j])

    # Limit to top 30 nodes by degree
    degrees = dict(G.degree())
    top_nodes = sorted(degrees, key=degrees.get, reverse=True)[:30]
    G_sub = G.subgraph(top_nodes)

    net = Network(height="600px", width="100%", bgcolor="#1a1035", font_color="white", notebook=False)

    for node in G_sub.nodes(data=True):
        net.add_node(node[0], label=node[1].get('label', node[0]), title=node[1].get('type', ''), shape="dot")

    for edge in G_sub.edges():
        net.add_edge(edge[0], edge[1])

    html_content = net.generate_html()

    return render_template("global_network.html", network_html=html_content)

# ─── OTHER ROUTES (unchanged) ──────────────────────────────────────────────

@app.route("/case/<complaint_id>/status", methods=["POST"])
@login_required
def update_status(complaint_id):
    new_status = request.form.get("status")
    db = get_db()
    old = db.execute("SELECT status FROM complaints WHERE complaint_id=?", (complaint_id,)).fetchone()
    db.execute("UPDATE complaints SET status=? WHERE complaint_id=?", (new_status, complaint_id))
    db.commit()
    db.close()
    log_action(complaint_id, 'status_changed', f"Changed from {old['status']} to {new_status}")
    return redirect(url_for("view_case", complaint_id=complaint_id))

@app.route("/case/<complaint_id>/evidence/upload", methods=["GET","POST"])
@login_required
def upload_evidence(complaint_id):
    if request.method == "POST":
        file = request.files.get('file')
        description = request.form.get('description', '')
        if not file:
            return redirect(url_for('view_case', complaint_id=complaint_id))

        if not allowed_file(file.filename):
            return redirect(url_for('view_case', complaint_id=complaint_id))

        upload_dir = os.path.join(UPLOAD_FOLDER, complaint_id)
        os.makedirs(upload_dir, exist_ok=True)

        filename = secure_filename(file.filename)
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)

        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()

        db = get_db()
        db.execute(
            """INSERT INTO evidence 
               (complaint_id, filename, filepath, file_hash, file_size, mime_type, uploaded_by, description)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                complaint_id,
                filename,
                filepath,
                file_hash,
                os.path.getsize(filepath),
                file.content_type,
                session['officer_id'],
                description
            )
        )
        db.commit()
        db.close()

        log_action(complaint_id, 'evidence_uploaded', f"Uploaded {filename} (hash: {file_hash[:8]}...)")
        return redirect(url_for('view_case', complaint_id=complaint_id))

    return render_template("upload_evidence.html", complaint_id=complaint_id)

@app.route("/evidence/<int:evidence_id>/download")
@login_required
def download_evidence(evidence_id):
    db = get_db()
    ev = db.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    db.close()
    if not ev:
        return "Evidence not found", 404
    log_action(ev['complaint_id'], 'evidence_downloaded', f"Downloaded {ev['filename']}")
    return send_file(ev['filepath'], as_attachment=True, download_name=ev['filename'])

@app.route("/case/<complaint_id>/logs/export")
@login_required
def export_logs(complaint_id):
    import csv
    from io import StringIO

    db = get_db()
    logs = db.execute(
        "SELECT * FROM case_logs WHERE complaint_id = ? ORDER BY created_at DESC",
        (complaint_id,)
    ).fetchall()
    db.close()

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Timestamp', 'Officer', 'Action', 'Details', 'IP Address'])
    for log in logs:
        writer.writerow([log['created_at'], log['officer_name'], log['action'], log['details'], log['ip_address']])

    output = si.getvalue()
    return Response(output, mimetype='text/csv', headers={
        'Content-Disposition': f'attachment; filename=CustodyLog_{complaint_id}.csv'
    })

@app.route("/admin/officers")
@admin_required
def manage_officers():
    db = get_db()
    officers = db.execute("SELECT * FROM officers ORDER BY created_at DESC").fetchall()
    db.close()
    return render_template("officers.html", officers=officers)

@app.route("/admin/officers/add", methods=["POST"])
@admin_required
def add_officer():
    name = request.form.get("name","").strip()
    username = request.form.get("username","").strip()
    password = request.form.get("password","")
    role = request.form.get("role","officer")
    badge = request.form.get("badge","").strip()
    db = get_db()
    try:
        db.execute("INSERT INTO officers (name,username,password,role,badge_no) VALUES (?,?,?,?,?)",
                   (name, username, hash_password(password), role, badge))
        db.commit()
    except:
        pass
    db.close()
    return redirect(url_for("manage_officers"))

@app.route("/admin/officers/delete/<int:oid>", methods=["POST"])
@admin_required
def delete_officer(oid):
    db = get_db()
    db.execute("DELETE FROM officers WHERE id=? AND role != 'admin'", (oid,))
    db.commit()
    db.close()
    return redirect(url_for("manage_officers"))

@app.route("/download/<complaint_id>")
@login_required
def download_report(complaint_id):
    db = get_db()
    case = db.execute(
        """
        SELECT complaint_text, case_summary, crime_category,
               risk_level, risk_reason, legal_sections, priority_action,
               indicators_json, investigation_steps
        FROM complaints
        WHERE complaint_id = ?
        """,
        (complaint_id,),
    ).fetchone()
    db.close()

    if not case:
        return "Report not found", 404

    indicators = json.loads(case["indicators_json"] or "{}")
    steps = json.loads(case["investigation_steps"] or "[]")

    result = {
        "complaint_id": complaint_id,
        "crime_category": case["crime_category"] or "Unknown",
        "risk_level": case["risk_level"] or "",
        "risk_reason": case["risk_reason"] or "",
        "case_summary": case["case_summary"] or "",
        "legal_sections": case["legal_sections"] or "",
        "priority_action": case["priority_action"] or "",
        "key_indicators": indicators,
        "investigation_steps": steps,
    }

    from pdf_generator import create_report_pdf
    import tempfile

    safe_level = (result["risk_level"] or "").replace(" ", "_")
    filename = f"CCIA_{complaint_id}_{safe_level}.pdf"

    tmp_dir = tempfile.gettempdir()
    tmp_path = os.path.join(tmp_dir, filename)
    create_report_pdf(tmp_path, result, case["complaint_text"] or "")

    log_action(complaint_id, 'downloaded_report', f"Downloaded PDF report")

    return send_file(
        tmp_path,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
    )

@app.route("/fir/<complaint_id>")
@login_required
def generate_fir(complaint_id):
    db = get_db()
    case = db.execute("""
        SELECT c.*, o.name as officer_name, o.badge_no 
        FROM complaints c
        LEFT JOIN officers o ON c.officer_id = o.id
        WHERE c.complaint_id = ?
    """, (complaint_id,)).fetchone()
    db.close()
    
    if not case:
        return "Case not found", 404
    
    indicators = json.loads(case["indicators_json"] or "{}")
    
    fir = f"""
    ========================================
    FIRST INFORMATION REPORT (FIR)
    Cyber Crime Cell, UP Police
    ========================================
    
    FIR No.: {case['complaint_id']}
    Date: {case['created_at'][:10]}
    Time: {case['created_at'][11:16]}
    
    ---------------------------------------------------
    1. COMPLAINANT DETAILS
    ---------------------------------------------------
    Name: (To be filled)
    Address: (To be filled)
    Contact: (To be filled)
    
    ---------------------------------------------------
    2. INCIDENT DETAILS
    ---------------------------------------------------
    Crime Category: {case['crime_category']}
    Risk Level: {case['risk_level']}
    
    Summary:
    {case['case_summary']}
    
    ---------------------------------------------------
    3. INDICATORS EXTRACTED
    ---------------------------------------------------
    """
    
    if indicators.get("mobile_numbers"):
        fir += f"   Mobile Numbers: {', '.join(indicators['mobile_numbers'])}\n"
    if indicators.get("upi_ids"):
        fir += f"   UPI IDs: {', '.join(indicators['upi_ids'])}\n"
    if indicators.get("email_ids"):
        fir += f"   Email IDs: {', '.join(indicators['email_ids'])}\n"
    if indicators.get("urls"):
        fir += f"   URLs: {', '.join(indicators['urls'])}\n"
    
    fir += f"""
    ---------------------------------------------------
    4. LEGAL SECTIONS
    ---------------------------------------------------
    {case['legal_sections'] or 'To be determined'}
    
    ---------------------------------------------------
    5. RECOMMENDED ACTIONS
    ---------------------------------------------------
    {case['priority_action'] or 'Investigation required'}
    
    ---------------------------------------------------
    6. INVESTIGATION STEPS
    ---------------------------------------------------
    """
    
    steps = json.loads(case["investigation_steps"] or "[]")
    for i, step in enumerate(steps, 1):
        fir += f"   {i}. {step}\n"
    
    fir += f"""
    ---------------------------------------------------
    7. OFFICER DETAILS
    ---------------------------------------------------
    Investigating Officer: {case['officer_name']}
    Badge No.: {case['badge_no']}
    
    ---------------------------------------------------
    (This is a system-generated draft. Verify before filing.)
    ========================================
    """
    
    return Response(fir, mimetype='text/plain', 
                    headers={'Content-Disposition': f'attachment; filename=FIR_{complaint_id}.txt'})

@app.route("/heatmap")
@login_required
def heatmap():
    return render_template("heatmap.html")

@app.route("/api/heatmap-data")
@login_required
def heatmap_data():
    db = get_db()
    cases = db.execute("""
        SELECT complaint_id, crime_category, risk_level, created_at, complaint_text
        FROM complaints
    """).fetchall()
    db.close()
    
    cities = {
        'Lucknow': 0, 'Delhi': 0, 'Mumbai': 0, 'Bangalore': 0,
        'Jaipur': 0, 'Kota': 0, 'Ajmer': 0, 'Noida': 0,
        'Ghaziabad': 0, 'Agra': 0, 'Varanasi': 0, 'Allahabad': 0
    }
    
    for case in cases:
        text = case['complaint_text']
        for city in cities.keys():
            if city.lower() in text.lower():
                cities[city] += 1
    
    data = [{"city": k, "count": v} for k, v in cities.items() if v > 0]
    
    if not data:
        data = [
            {"city": "Lucknow", "count": 5},
            {"city": "Jaipur", "count": 3},
            {"city": "Delhi", "count": 7},
            {"city": "Mumbai", "count": 4},
            {"city": "Bangalore", "count": 2}
        ]
    
    return jsonify(data)

@app.route("/case/<complaint_id>/network")
@login_required
def network_graph(complaint_id):
    from pyvis.network import Network
    
    db = get_db()
    case = db.execute("SELECT * FROM complaints WHERE complaint_id = ?", (complaint_id,)).fetchone()
    db.close()
    
    if not case:
        return "Case not found", 404
    
    indicators = json.loads(case["indicators_json"] or "{}")
    
    net = Network(height="600px", width="100%", bgcolor="#1a1035", font_color="white", notebook=False)
    
    phones = indicators.get("mobile_numbers", [])[:3]
    upis = indicators.get("upi_ids", [])[:3]
    emails = indicators.get("email_ids", [])[:3]
    accounts = indicators.get("possible_account_numbers", [])[:3]
    
    all_items = []
    for p in phones:
        all_items.append(("📱 " + p, "phone"))
    for u in upis:
        all_items.append(("💳 " + u, "upi"))
    for e in emails:
        all_items.append(("📧 " + e, "email"))
    for a in accounts:
        all_items.append(("🏦 " + a, "account"))
    
    if len(all_items) < 2:
        all_items = [
            ("📱 9876543210", "phone"),
            ("💳 fraud@paytm", "upi"),
            ("📧 scammer@gmail.com", "email"),
            ("🏦 123456789012", "account")
        ]
    
    for i, (label, type_) in enumerate(all_items):
        net.add_node(i, label=label, title=type_, shape="dot" if i==0 else "box")
    
    for i in range(len(all_items) - 1):
        net.add_edge(i, i+1)
    if len(all_items) > 2:
        net.add_edge(0, len(all_items)-1)
    
    html_content = net.generate_html()
    
    return render_template("network_view.html", network_html=html_content, complaint_id=complaint_id)

if __name__ == "__main__":
    app.run(debug=True)