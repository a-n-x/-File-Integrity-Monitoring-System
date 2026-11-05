import os
import hashlib
import sqlite3
import requests
from datetime import datetime
from flask import Flask, render_template_string, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex()
DB_NAME = os.environ.get("FIM_DB_PATH", "fim.db")

VT_API_KEY = os.environ.get("VT_API_KEY", "")
HA_API_KEY = os.environ.get("HA_API_KEY", "")

def check_virustotal(file_hash):
    """
    Queries VirusTotal v3 API using SHA-256 hash.
    """
    if not VT_API_KEY:
        return False, "VT API key not configured"

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            if malicious > 0:
                return True, f"VT Flagged: {malicious} engine(s) detected malware"
            return False, "Clean according to VirusTotal"
        elif response.status_code == 404:
            return False, "Hash unknown to VirusTotal"
        return False, f"VT Status: {response.status_code}"
    except Exception as e:
        return False, f"VT Error: {str(e)}"

def check_hybrid_analysis(file_hash):
    """
    Queries Hybrid Analysis v2 API to retrieve threat scores and sandbox verdicts.
    """
    if not HA_API_KEY:
        return False, "Hybrid Analysis API key not configured"

    url = f"https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {
        "api-key": HA_API_KEY,
        "User-Agent": "Falcon Sandbox FIM System",
        "Accept": "application/json"
    }
    data = {"hash": file_hash}

    try:
        response = requests.post(url, headers=headers, data=data, timeout=5)
        if response.status_code == 200:
            results = response.json()
            if results and len(results) > 0:
                threat_score = results[0].get('threat_score', 0)
                verdict = results[0].get('verdict', 'unknown')
                if threat_score > 50 or verdict in ['malicious', 'suspicious']:
                    return True, f"Hybrid Analysis Alert: Threat Score {threat_score}/100 ({verdict})"
                return False, f"Hybrid Analysis: Clean (Score: {threat_score})"
            return False, "No sandbox history found in Hybrid Analysis"
        return False, f"HA Status Code: {response.status_code}"
    except Exception as e:
        return False, f"HA Error: {str(e)}"

def check_nvd_vulnerabilities(filename):
    """
    Queries NIST National Vulnerability Database API v2 for keywords matching 
    software configuration or dependency files.
    """
    keyword = os.path.basename(filename).split('.')[0]
    
    if len(keyword) < 4 or keyword in ["test", "data", "file", "index"]:
        return False, "Skipped CVE check for generic name"

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            total = data.get('totalResults', 0)
            if total > 0:
                cve_items = data.get('vulnerabilities', [])
                cve_id = cve_items[0]['cve']['id'] if cve_items else "CVE-Found"
                return True, f"NVD Alert: {total} vulnerability match(es) found for '{keyword}' (e.g., {cve_id})"
            return False, "No known CVEs in NVD database"
        return False, f"NVD API Code: {response.status_code}"
    except Exception as e:
        return False, f"NVD Error: {str(e)}"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE,
            hash_value TEXT,
            last_scanned TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP,
            event_type TEXT,
            file_path TEXT,
            details TEXT,
            status TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS monitored_folders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            folder_path TEXT UNIQUE
        )
    ''')
    conn.commit()
    conn.close()

def calculate_sha256(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None

def log_event(event_type, file_path, details, status="ALERT"):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO logs (timestamp, event_type, file_path, details, status) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_type, file_path, details, status)
    )
    conn.commit()
    conn.close()

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ title }} - Multi-Threat FIM System</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', sans-serif; }
        body { background-color: #f4f6f9; color: #333; display: flex; min-height: 100vh; }
        .sidebar { width: 260px; background-color: #0f172a; color: #fff; padding: 20px 0; flex-shrink: 0; }
        .sidebar h2 { font-size: 1.1rem; text-align: center; padding-bottom: 20px; border-bottom: 1px solid #334155; color: #38bdf8; }
        .sidebar ul { list-style: none; margin-top: 20px; }
        .sidebar li a { display: block; padding: 12px 20px; color: #94a3b8; text-decoration: none; }
        .sidebar li a:hover, .sidebar li a.active { background-color: #1e293b; color: #38bdf8; border-left: 4px solid #38bdf8; }
        .main-content { flex: 1; padding: 30px; display: flex; flex-direction: column; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; background: #fff; padding: 15px 25px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 25px; }
        .card { background: #fff; padding: 20px; border-radius: 8px; border-left: 5px solid #38bdf8; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .card.alert { border-left-color: #ef4444; }
        .card.success { border-left-color: #22c55e; }
        .table-container { background: #fff; border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 25px; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.88rem; }
        th, td { padding: 12px 15px; border-bottom: 1px solid #e2e8f0; }
        th { background-color: #f8fafc; color: #475569; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
        .badge-critical { background-color: #7f1d1d; color: #ffffff; }
        .badge-danger { background-color: #fee2e2; color: #dc2626; }
        .badge-warning { background-color: #fef3c7; color: #d97706; }
        .btn { padding: 8px 16px; border: none; border-radius: 5px; background: #0284c7; color: white; cursor: pointer; text-decoration: none; font-size: 0.9rem; }
        .btn:hover { background: #0369a1; }
        .btn-danger { background: #ef4444; }
        .input-group { display: flex; gap: 10px; margin-bottom: 20px; }
        input[type="text"], input[type="password"] { padding: 10px; border: 1px solid #cbd5e1; border-radius: 5px; width: 100%; }
        .login-body { display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #0f172a; width: 100%; }
        .login-card { background: #fff; padding: 40px; border-radius: 8px; width: 350px; }
        .alert-messages { margin-bottom: 15px; }
        .alert-msg { padding: 10px; background-color: #e0f2fe; border: 1px solid #7dd3fc; color: #0369a1; border-radius: 5px; font-size: 0.85rem; }
    </style>
</head>
<body>

{% if page == 'login' %}
    <div class="login-body">
        <div class="login-card">
            <h2 style="margin-bottom: 20px; text-align: center;">FIM Security Suite</h2>
            <form method="POST" action="{{ url_for('login') }}">
                <div style="margin-bottom: 15px;">
                    <label>Username</label>
                    <input type="text" name="username" required style="margin-top: 5px;">
                </div>
                <div style="margin-bottom: 20px;">
                    <label>Password</label>
                    <input type="password" name="password" required style="margin-top: 5px;">
                </div>
                <button type="submit" class="btn" style="width: 100%;">Sign In</button>
            </form>
        </div>
    </div>
{% else %}
    <div class="sidebar">
        <h2>Multi-Threat FIM Engine</h2>
        <ul>
            <li><a href="{{ url_for('dashboard') }}" class="{% if page == 'dashboard' %}active{% endif %}">Dashboard</a></li>
            <li><a href="{{ url_for('events') }}" class="{% if page == 'events' %}active{% endif %}">Audit Logs</a></li>
            <li><a href="{{ url_for('integrity_report') }}" class="{% if page == 'integrity' %}active{% endif %}">Integrity Hashes</a></li>
            <li><a href="{{ url_for('files') }}" class="{% if page == 'files' %}active{% endif %}">Monitored Folders</a></li>
            <li><a href="{{ url_for('baseline') }}" class="{% if page == 'baseline' %}active{% endif %}">Baseline Config</a></li>
            <li><a href="{{ url_for('settings') }}" class="{% if page == 'settings' %}active{% endif %}">API Status</a></li>
            <li><a href="{{ url_for('about') }}" class="{% if page == 'about' %}active{% endif %}">About</a></li>
            <li><a href="{{ url_for('logout') }}" style="color: #f87171; margin-top: 20px;">Logout</a></li>
        </ul>
    </div>

    <div class="main-content">
        <header>
            <h1>{{ title }}</h1>
            <div style="font-size: 0.9rem; color: #64748b;">User: <strong>{{ session['user'] }}</strong></div>
        </header>

        {% with messages = get_flashed_messages() %}
            {% if messages %}
                <div class="alert-messages">
                    {% for msg in messages %}
                        <div class="alert-msg">{{ msg }}</div>
                    {% endfor %}
                </div>
            {% endif %}
        {% endwith %}

        {% if page == 'dashboard' %}
            <div class="grid">
                <div class="card">
                    <h3>Monitored Folders</h3>
                    <p style="font-size: 1.8rem; font-weight: bold;">{{ folder_count }}</p>
                </div>
                <div class="card">
                    <h3>Tracked Files</h3>
                    <p style="font-size: 1.8rem; font-weight: bold;">{{ file_count }}</p>
                </div>
                <div class="card alert">
                    <h3>Security Alerts</h3>
                    <p style="font-size: 1.8rem; font-weight: bold;">{{ alert_count }}</p>
                </div>
            </div>

            <div class="table-container">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h3>Real-Time Threat & Vulnerability Intelligence</h3>
                    <a href="{{ url_for('run_scan') }}" class="btn">Run Deep Multi-API Scan</a>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Threat Level</th>
                            <th>File Path</th>
                            <th>Combined Threat Intelligence</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for log in logs %}
                        <tr>
                            <td>{{ log[1] }}</td>
                            <td>
                                {% if log[5] == 'CRITICAL' %}
                                    <span class="badge badge-critical">{{ log[2] }}</span>
                                {% elif log[5] == 'VULNERABILITY' %}
                                    <span class="badge badge-warning">{{ log[2] }}</span>
                                {% else %}
                                    <span class="badge badge-danger">{{ log[2] }}</span>
                                {% endif %}
                            </td>
                            <td>{{ log[3] }}</td>
                            <td>{{ log[4] }}</td>
                        </tr>
                        {% else %}
                        <tr><td colspan="4" style="text-align: center; color: #94a3b8;">No alerts registered. System fully protected.</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>

        {% elif page == 'events' %}
            <div class="table-container">
                <h3>System Logs</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Event</th>
                            <th>File Path</th>
                            <th>Details</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for log in logs %}
                        <tr>
                            <td>{{ log[1] }}</td>
                            <td>{{ log[2] }}</td>
                            <td>{{ log[3] }}</td>
                            <td>{{ log[4] }}</td>
                            <td><span class="badge badge-danger">{{ log[5] }}</span></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>

        {% elif page == 'integrity' %}
            <div class="table-container">
                <h3>Baseline Hashes</h3>
                <table>
                    <thead>
                        <tr><th>Path</th><th>SHA-256 Hash</th><th>Last Scanned</th></tr>
                    </thead>
                    <tbody>
                        {% for item in baselines %}
                        <tr>
                            <td>{{ item[1] }}</td>
                            <td><code>{{ item[2] }}</code></td>
                            <td>{{ item[3] }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>

        {% elif page == 'files' %}
            <div class="table-container">
                <h3>Add Folder</h3>
                <form method="POST" action="{{ url_for('add_folder') }}" class="input-group">
                    <input type="text" name="folder_path" placeholder="e.g. C:\Users\Public\Documents" required>
                    <button type="submit" class="btn">Add Directory</button>
                </form>
            </div>
            <div class="table-container">
                <h3>Monitored Folders</h3>
                <table>
                    <thead><tr><th>ID</th><th>Path</th><th>Action</th></tr></thead>
                    <tbody>
                        {% for folder in folders %}
                        <tr>
                            <td>{{ folder[0] }}</td>
                            <td>{{ folder[1] }}</td>
                            <td><a href="{{ url_for('remove_folder', id=folder[0]) }}" class="btn btn-danger">Remove</a></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>

        {% elif page == 'baseline' %}
            <div class="table-container">
                <h3>Generate Baseline</h3>
                <p style="margin-bottom: 15px; color: #64748b;">Recalculate target state signatures across all folders.</p>
                <a href="{{ url_for('generate_baseline') }}" class="btn">Calculate Hashes</a>
            </div>

        {% elif page == 'settings' %}
            <div class="table-container">
                <h3>Threat Intelligence Integrations</h3>
                <ul style="margin-left: 20px; line-height: 2;">
                    <li><strong>VirusTotal v3 API:</strong> Checks static file hash against 70+ antivirus engines.</li>
                    <li><strong>Hybrid Analysis v2 API:</strong> Checks behavioral sandbox execution threat scores.</li>
                    <li><strong>NIST NVD REST API v2:</strong> Scans software filenames against the CVE database.</li>
                </ul>
            </div>

        {% elif page == 'about' %}
            <div class="table-container">
                <h3>System Information</h3>
                <p><strong>Student Name:</strong> Anex Sebastian Joy<br><strong>Reg No:</strong> 24BCAR0299</p>
            </div>
        {% endif %}
    </div>
{% endif %}

</body>
</html>
"""

@app.route('/')
def index():
    if 'user' in session: return redirect(url_for('dashboard'))
    return render_template_string(HTML_TEMPLATE, title="Login", page="login")

@app.route('/login', methods=['POST'])
def login():
    if (request.form.get('username') == os.environ.get('FIM_USERNAME', '') and os.environ.get('FIM_PASSWORD') and request.form.get('password') == os.environ.get('FIM_PASSWORD')):
        session['user'] = 'admin'
        return redirect(url_for('dashboard'))
    flash('Invalid credentials.')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session: return redirect(url_for('index'))
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM monitored_folders")
    folder_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM baselines")
    file_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM logs WHERE status IN ('ALERT', 'CRITICAL', 'VULNERABILITY')")
    alert_count = cursor.fetchone()[0]
    cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 5")
    recent_logs = cursor.fetchall()
    conn.close()
    return render_template_string(HTML_TEMPLATE, title="Dashboard", page="dashboard", 
                                  folder_count=folder_count, file_count=file_count, 
                                  alert_count=alert_count, logs=recent_logs)

@app.route('/events')
def events():
    if 'user' not in session: return redirect(url_for('index'))
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY id DESC")
    logs = cursor.fetchall()
    conn.close()
    return render_template_string(HTML_TEMPLATE, title="Audit Log", page="events", logs=logs)

@app.route('/integrity')
def integrity_report():
    if 'user' not in session: return redirect(url_for('index'))
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM baselines")
    baselines = cursor.fetchall()
    conn.close()
    return render_template_string(HTML_TEMPLATE, title="Integrity Hashes", page="integrity", baselines=baselines)

@app.route('/files')
def files():
    if 'user' not in session: return redirect(url_for('index'))
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM monitored_folders")
    folders = cursor.fetchall()
    conn.close()
    return render_template_string(HTML_TEMPLATE, title="Monitored Folders", page="files", folders=folders)

@app.route('/add_folder', methods=['POST'])
def add_folder():
    if 'user' not in session: return redirect(url_for('index'))
    folder_path = request.form.get('folder_path')
    if folder_path and os.path.exists(folder_path):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO monitored_folders (folder_path) VALUES (?)", (folder_path,))
            conn.commit()
            flash('Folder added successfully!')
        except sqlite3.IntegrityError:
            flash('Folder is already being monitored.')
        conn.close()
    return redirect(url_for('files'))

@app.route('/remove_folder/<int:id>')
def remove_folder(id):
    if 'user' not in session: return redirect(url_for('index'))
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM monitored_folders WHERE id=?", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('files'))

@app.route('/baseline')
def baseline():
    if 'user' not in session: return redirect(url_for('index'))
    return render_template_string(HTML_TEMPLATE, title="Baseline", page="baseline")

@app.route('/generate_baseline')
def generate_baseline():
    if 'user' not in session: return redirect(url_for('index'))
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT folder_path FROM monitored_folders")
    folders = cursor.fetchall()
    cursor.execute("DELETE FROM baselines")
    
    count = 0
    for folder in folders:
        path = folder[0]
        if os.path.exists(path):
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    file_hash = calculate_sha256(full_path)
                    if file_hash:
                        cursor.execute(
                            "INSERT OR REPLACE INTO baselines (file_path, hash_value, last_scanned) VALUES (?, ?, ?)",
                            (full_path, file_hash, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                        )
                        count += 1
    conn.commit()
    conn.close()
    flash(f"Baseline established for {count} files.")
    return redirect(url_for('baseline'))

@app.route('/run_scan')
def run_scan():
    if 'user' not in session: return redirect(url_for('index'))
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT file_path, hash_value FROM baselines")
    baselines = dict(cursor.fetchall())
    
    current_files = set()
    alerts = 0
    
    cursor.execute("SELECT folder_path FROM monitored_folders")
    folders = cursor.fetchall()
    
    for folder in folders:
        path = folder[0]
        if os.path.exists(path):
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    current_files.add(full_path)
                    current_hash = calculate_sha256(full_path)
                    if not current_hash: continue
                    
                    vt_is_mal, vt_msg = check_virustotal(current_hash)
                    ha_is_mal, ha_msg = check_hybrid_analysis(current_hash)
                    nvd_has_vuln, nvd_msg = check_nvd_vulnerabilities(file)

                    combined_details = f"[{vt_msg}] | [{ha_msg}] | [{nvd_msg}]"

                    if full_path not in baselines:
                        status = "CRITICAL" if (vt_is_mal or ha_is_mal) else ("VULNERABILITY" if nvd_has_vuln else "ALERT")
                        log_event("FILE_CREATED", full_path, combined_details, status=status)
                        alerts += 1

                    elif baselines[full_path] != current_hash:
                        status = "CRITICAL" if (vt_is_mal or ha_is_mal) else ("VULNERABILITY" if nvd_has_vuln else "ALERT")
                        log_event("FILE_MODIFIED", full_path, combined_details, status=status)
                        alerts += 1

    conn.close()
    flash(f"Multi-API Scan complete. Processed checks across VT, Hybrid Analysis, & NIST NVD.")
    return redirect(url_for('dashboard'))

@app.route('/settings')
def settings():
    if 'user' not in session: return redirect(url_for('index'))
    return render_template_string(HTML_TEMPLATE, title="API Settings", page="settings")

@app.route('/about')
def about():
    if 'user' not in session: return redirect(url_for('index'))
    return render_template_string(HTML_TEMPLATE, title="About", page="about")

init_db()  # Initialize the database for both local runs and Gunicorn.

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')), debug=False)