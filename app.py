from flask import Flask, render_template, request, redirect, url_for, session, make_response
from dotenv import load_dotenv
from google import genai
import os
import re
import sqlite3
import hashlib
import datetime
import json
from functools import wraps

# Explicit path to .env file
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

app = Flask(__name__)
app.secret_key = os.urandom(24)

API_KEY = os.getenv("GEMINI_API_KEY")
if not API_KEY:
    raise ValueError("GEMINI_API_KEY not found in .env file")

client = genai.Client(api_key=API_KEY)

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
    """)

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

def parse_ai_response(text):
    sections = {
        'case_summary': '', 'crime_category': '', 'risk_level': '',
        'risk_reason': '', 'key_indicators': [], 'investigation_steps': [],
        'legal_sections': '', 'priority_action': '', 'raw': text
    }
    current = None
    for line in text.split('\n'):
        line = line.strip()
        if not line: continue
        if '---CASE SUMMARY---' in line: current = 'case_summary'
        elif '---CRIME CATEGORY---' in line: current = 'crime_category'
        elif '---RISK LEVEL---' in line: current = 'risk_level'
        elif '---KEY INDICATORS---' in line: current = 'key_indicators'
        elif '---RECOMMENDED INVESTIGATION STEPS---' in line: current = 'investigation_steps'
        elif '---LEGAL SECTIONS---' in line: current = 'legal_sections'
        elif '---PRIORITY ACTION---' in line: current = 'priority_action'
        elif current:
            if current == 'case_summary': sections['case_summary'] += ' ' + line
            elif current == 'crime_category': sections['crime_category'] += line
            elif current == 'risk_level':
                if line.startswith('Reason:') or line.startswith('[Reason:'):
                    sections['risk_reason'] = line.replace('Reason:', '').replace('[','').replace(']','').strip()
                else:
                    clean = line.replace('[','').replace(']','').strip()
                    if clean in ['CRITICAL','HIGH','MEDIUM','LOW']:
                        sections['risk_level'] = clean
            elif current == 'key_indicators':
                if line.startswith(('•','-','*')): sections['key_indicators'].append(line.lstrip('•-* '))
            elif current == 'investigation_steps':
                if line and (line[0].isdigit() or line.startswith('-')):
                    clean = re.sub(r'^\d+[\.\)]\s*','',line).lstrip('- ')
                    if clean: sections['investigation_steps'].append(clean)
            elif current == 'legal_sections': sections['legal_sections'] += ' ' + line
            elif current == 'priority_action': sections['priority_action'] += ' ' + line

    for key in ['case_summary','crime_category','legal_sections','priority_action']:
        sections[key] = sections[key].strip().replace('[','').replace(']','')
    return sections

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
    db.close()
    return render_template("dashboard.html",
        total=total, critical=critical, high=high,
        open_cases=open_cases, recent=recent, categories=categories)

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
            error = "Please enter a complaint to analyze."
        elif len(complaint) < 20:
            error = "Complaint is too short. Please provide more details."
        else:
            try:
                indicators = extract_indicators(complaint)

                lang_instruction = ""
                if language == "hindi":
                    lang_instruction = "Respond ENTIRELY in Hindi language."
                elif language == "both":
                    lang_instruction = "Respond in both Hindi and English. First write in Hindi, then English."

                prompt = f"""
You are a Cyber Crime Investigation Assistant for Indian Law Enforcement (Cyber Police).
{lang_instruction}

Analyze the following cyber crime complaint and provide a structured investigation report in this EXACT format:

---CASE SUMMARY---
[Write 2-3 sentences summarizing what happened, who is the victim, what was the method used, and the approximate loss if mentioned]

---CRIME CATEGORY---
[Choose ONE from: Investment Fraud / Online Banking Fraud / UPI Fraud / Social Engineering / Phishing / Ransomware / Identity Theft / Sextortion / Job Fraud / Matrimonial Fraud / OTP Fraud / Cyber Stalking / Hacking / E-commerce Fraud / Other]

---RISK LEVEL---
[Choose ONE: CRITICAL / HIGH / MEDIUM / LOW]
[Reason: brief explanation]

---KEY INDICATORS---
[List all suspicious elements. Format as bullet points starting with •]

---RECOMMENDED INVESTIGATION STEPS---
[List 5-7 specific actionable steps. Number them 1, 2, 3...]

---LEGAL SECTIONS---
[List applicable IPC/IT Act sections]

---PRIORITY ACTION---
[The SINGLE most important immediate action]

Complaint:
{complaint}

Respond ONLY in the format above. Be specific, professional, and actionable.
"""
                response = client.models.generate_content(
                    model="gemini-2.0-flash",
                    contents=prompt
                )
                result = parse_ai_response(response.text)

                cid = generate_complaint_id()
                db = get_db()
                db.execute("""
                    INSERT INTO complaints
                    (complaint_id, complaint_text, case_summary, crime_category,
                     risk_level, risk_reason, key_indicators, investigation_steps,
                     legal_sections, priority_action, indicators_json, officer_id, language)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    cid, complaint,
                    result['case_summary'], result['crime_category'],
                    result['risk_level'], result['risk_reason'],
                    json.dumps(result['key_indicators']),
                    json.dumps(result['investigation_steps']),
                    result['legal_sections'], result['priority_action'],
                    json.dumps(indicators),
                    session['officer_id'], language
                ))
                db.commit()
                db.close()
                saved_id = cid

            except Exception as e:
                error = f"AI Analysis Error: {str(e)}"

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
    db.close()
    if not case:
        return redirect(url_for("history"))

    case = dict(case)
    case['key_indicators'] = json.loads(case['key_indicators'] or '[]')
    case['investigation_steps'] = json.loads(case['investigation_steps'] or '[]')
    case['indicators_json'] = json.loads(case['indicators_json'] or '{}')
    return render_template("case_detail.html", case=case)

@app.route("/case/<complaint_id>/status", methods=["POST"])
@login_required
def update_status(complaint_id):
    new_status = request.form.get("status")
    db = get_db()
    db.execute("UPDATE complaints SET status=? WHERE complaint_id=?", (new_status, complaint_id))
    db.commit()
    db.close()
    return redirect(url_for("view_case", complaint_id=complaint_id))

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

if __name__ == "__main__":
    app.run(debug=True)
