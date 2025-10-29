# app.py
from flask import Flask, request, render_template_string, redirect, url_for
import re
import requests
from urllib.parse import urlparse, urlunparse
import tldextract
import socket


app = Flask(__name__)

# -------------------------
# Helper and safety config
# -------------------------
MAX_REDIRECTS = 3
REQUEST_TIMEOUT = 3  # seconds for HEAD requests
ALLOW_FOLLOW = True   # change to False to disable any network calls

# Known legitimate domains (whitelist)
TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com',
    'github.com', 'stackoverflow.com', 'reddit.com', 'netflix.com', 'paypal.com'
]

# -------------------------
# URL normalization & validation
# -------------------------
def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if raw_url == "":
        return ""
    # If user pasted something like "example.com" -> add scheme
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', raw_url):
        raw_url = "http://" + raw_url
    parsed = urlparse(raw_url)
    # If still no netloc, try to salvage
    if parsed.netloc == "" and parsed.path != "":
        # maybe they gave "example.com/path"
        parsed = urlparse("http://" + raw_url)
    # recompose canonical
    return urlunparse(parsed)

def is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        return False

def is_trusted_domain(domain: str, host: str) -> bool:
    """Check if domain is in trusted list"""
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or host == trusted or host.endswith('.' + trusted):
            return True
    return False

# -------------------------
# Heuristic features
# -------------------------
def extract_features(url: str):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    ext = tldextract.extract(host)
    domain = ext.domain + (("." + ext.suffix) if ext.suffix else "")
    features = {}
    features['url_len'] = len(url)
    features['host_len'] = len(host)
    features['num_dots'] = host.count('.')
    features['has_at'] = '@' in url
    features['has_dash_in_host'] = '-' in host
    features['num_subdirs'] = path.count('/')
    features['has_ip'] = is_ip(host)
    features['has_port'] = (parsed.port is not None)
    features['scheme'] = parsed.scheme
    features['suspicious_keywords'] = sum(k in url.lower() for k in ['login', 'secure', 'account', 'wp-admin', 'verify', 'bank', 'update', 'signin', 'password', 'confirm', 'suspend', 'locked', 'urgent'])
    features['domain'] = domain
    features['host'] = host
    features['is_trusted'] = is_trusted_domain(domain, host)
    
    # Check for suspicious domain patterns
    features['suspicious_domain_words'] = sum(word in host.lower() for word in ['verify', 'secure', 'account', 'login', 'confirm', 'update', 'validation', 'authentication'])
    
    return features

# -------------------------
# Simple scoring classifier (heuristic)
# -------------------------
def score_url(features: dict) -> (float, dict): # type: ignore
    score = 0.0
    reasons = {}

    # If it's a trusted domain, give it a pass (low score)
    if features['is_trusted']:
        return 0.0, {"raw_score": 0.0, "reasons": {"trusted_domain": True}, "verdict": "Safe"}

    # CRITICAL: IP address with sensitive paths is highly suspicious
    if features['has_ip']:
        score += 6.0
        reasons['ip_address_host'] = True
        # If IP + sensitive keywords = extremely suspicious
        if features['suspicious_keywords'] > 0:
            score += 4.0
            reasons['ip_with_sensitive_path'] = True

    # Suspicious domain words (like "account-verification-required.com")
    if features['suspicious_domain_words'] > 0:
        score += 3.0 * features['suspicious_domain_words']
        reasons['suspicious_words_in_domain'] = features['suspicious_domain_words']

    # Base weights (tweakable)
    if features['url_len'] > 75:
        score += 2.0
        reasons['long_url'] = True
    if features['host_len'] > 30:
        score += 2.0
        reasons['long_host'] = True
    if features['num_dots'] > 3:
        score += 2.0
        reasons['many_subdomains'] = True
    if features['has_at']:
        score += 5.0
        reasons['has_at_symbol'] = True
    if features['has_dash_in_host'] and features['host_len'] > 20:
        score += 1.5  # Only suspicious if domain is long with dashes
        reasons['dash_in_long_host'] = True
    if features['num_subdirs'] > 4:
        score += 1.5
        reasons['deep_path'] = True
    if features['has_port']:
        score += 1.5
        reasons['contains_port'] = True
    
    # Suspicious keywords in path/query
    if features['suspicious_keywords'] > 0:
        keyword_score = 1.5 * features['suspicious_keywords']
        score += keyword_score
        reasons['suspicious_keywords_count'] = features['suspicious_keywords']

    # scheme check
    if features['scheme'] not in ['http', 'https', 'ftp', 'ftps']:
        score += 2.5
        reasons['weird_scheme'] = True

    # Private/Local IP ranges are especially suspicious
    host = features['host']
    if features['has_ip']:
        if host.startswith('192.168.') or host.startswith('10.') or host.startswith('172.'):
            score += 3.0
            reasons['private_ip_address'] = True

    # normalize score roughly between 0 and ~20
    max_possible = 20.0
    normalized = max(0.0, min(1.0, score / max_possible))

    verdict = "Safe"
    if normalized > 0.45:
        verdict = "Phishing/Malicious"
    elif normalized > 0.20:
        verdict = "Suspicious"

    return normalized, {"raw_score": score, "reasons": reasons, "verdict": verdict}

# -------------------------
# Safe redirect following (HEAD only)
# -------------------------
def safe_follow_redirects(url: str, max_redirects=MAX_REDIRECTS):
    if not ALLOW_FOLLOW:
        return {"error": "Network follow disabled", "final_url": None, "chain": []}
    try:
        chain = []
        resp = requests.head(url, allow_redirects=True, timeout=REQUEST_TIMEOUT)
        # record chain from response.history + final
        for r in resp.history:
            chain.append({"status": r.status_code, "url": r.headers.get('Location') or r.url})
        chain.append({"status": resp.status_code, "url": resp.url})
        return {"final_url": resp.url, "chain": chain, "status_code": resp.status_code}
    except Exception as e:
        return {"error": str(e), "final_url": None, "chain": []}

# -------------------------
# Flask routes + UI
# -------------------------
INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>🛡️ ScamShield AI — URL Phishing Detector</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">

  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --text: #f1f5f9;
      --subtext: #94a3b8;
      --safe: #22c55e;
      --warning: #f59e0b;
      --danger: #ef4444;
    }

    body {
      font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 30px 16px;
      min-height: 100vh;
    }

    .container {
      width: 100%;
      max-width: 850px;
    }

    h1 {
      text-align: center;
      font-size: 2rem;
      margin-bottom: 8px;
    }

    p.subtitle {
      text-align: center;
      color: var(--subtext);
      margin-bottom: 24px;
    }

    .card {
      background: var(--card-bg);
      border-radius: 16px;
      padding: 24px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
    }

    form {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    input[type=text] {
      padding: 14px 16px;
      border-radius: 10px;
      border: 1px solid #334155;
      background: #0f172a;
      color: var(--text);
      font-size: 15px;
      transition: border 0.2s ease;
    }

    input[type=text]:focus {
      border-color: var(--accent);
      outline: none;
    }

    .buttons {
      display: flex;
      gap: 10px;
    }

    button {
      flex: 1;
      padding: 12px 16px;
      border: none;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s ease;
    }

    button.submit {
      background: var(--accent);
      color: white;
    }

    button.submit:hover {
      background: var(--accent-hover);
    }

    button.clear {
      background: #334155;
      color: var(--text);
    }

    .result {
      margin-top: 30px;
      background: var(--card-bg);
      border-radius: 16px;
      padding: 24px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.3);
    }

    .tag {
      display: inline-block;
      padding: 6px 12px;
      border-radius: 6px;
      font-weight: 600;
      font-size: 14px;
      margin-bottom: 12px;
    }

    .tag.safe { background: rgba(34,197,94,0.15); color: var(--safe); }
    .tag.suspicious { background: rgba(245,158,11,0.15); color: var(--warning); }
    .tag.danger { background: rgba(239,68,68,0.15); color: var(--danger); }

    pre {
      background: #0f172a;
      padding: 12px;
      border-radius: 8px;
      font-size: 12px;
      overflow-x: auto;
    }

    ul {
      padding-left: 20px;
    }

    .footer {
      margin-top: 40px;
      text-align: center;
      color: var(--subtext);
      font-size: 13px;
    }
  </style>
</head>

<body>
  <div class="container">
    <h1>🛡️ ScamShield AI</h1>
    <p class="subtitle">Smart heuristic phishing URL detector prototype — built for security & awareness</p>

    <div class="card">
      <form method="post" action="/">
        <input name="raw_url" type="text" placeholder="Enter a URL to scan (e.g. http://paypal-login-secure.com)" required>
        <div class="buttons">
          <button type="submit" class="submit">🔍 Scan URL</button>
          <button type="button" class="clear" onclick="document.querySelector('input[name=raw_url]').value=''">Clear</button>
        </div>
      </form>
    </div>

    {% if result %}
    <div class="result">
      {% if result.verdict == "Safe" %}
        <span class="tag safe">✅ SAFE</span>
      {% elif result.verdict == "Suspicious" %}
        <span class="tag suspicious">⚠️ SUSPICIOUS</span>
      {% else %}
        <span class="tag danger">🚫 PHISHING / MALICIOUS</span>
      {% endif %}

      <h2>Analysis Summary</h2>
      <p><strong>Input:</strong> {{ raw_input }}</p>
      <p><strong>Normalized URL:</strong> {{ normalized }}</p>
      <p><strong>Domain:</strong> {{ features.domain }} (host: {{ features.host }})</p>
      <p><strong>Scheme:</strong> {{ features.scheme }}</p>

      <h3>Threat Score:</h3>
      {% if result.normalized_score >= 0.45 %}
        <p style="color:var(--danger);font-weight:700;font-size:20px;">{{ (result.normalized_score*100)|round(0) }}% — {{ result.verdict }}</p>
      {% elif result.normalized_score >= 0.20 %}
        <p style="color:var(--warning);font-weight:700;font-size:20px;">{{ (result.normalized_score*100)|round(0) }}% — {{ result.verdict }}</p>
      {% else %}
        <p style="color:var(--safe);font-weight:700;font-size:20px;">{{ (result.normalized_score*100)|round(0) }}% — {{ result.verdict }}</p>
      {% endif %}

      <h3>🚩 Detection Flags</h3>
      {% if result.reasons %}
        <ul>
        {% for k,v in result.reasons.items() %}
          <li><strong>{{ k }}</strong>: {{ v }}</li>
        {% endfor %}
        </ul>
      {% else %}
        <p>No suspicious flags detected.</p>
      {% endif %}

      <h3>📊 Technical Features</h3>
      <pre>{{ features | tojson(indent=2) }}</pre>

      <h3>🔗 Redirect Chain</h3>
      {% if follow_result.error %}
        <p>Follow failed: {{ follow_result.error }}</p>
      {% else %}
        {% if follow_result.chain|length == 0 %}
          <p>No redirects recorded.</p>
        {% else %}
          <ul>
          {% for step in follow_result.chain %}
            <li>[{{ step.status }}] {{ step.url }}</li>
          {% endfor %}
          </ul>
        {% endif %}
      {% endif %}
    </div>
    {% endif %}

    <div class="footer">
      ⚙️ Prototype built for Smart India Hackathon — Flask + Heuristic Scoring | Modify weights in <code>score_url()</code>
    </div>
  </div>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        raw = request.form.get("raw_url", "")
        normalized = normalize_url(raw)
        if normalized == "":
            return render_template_string(INDEX_HTML, result=None)
        features = extract_features(normalized)
        normalized_score, score_info = score_url(features)
        follow_result = safe_follow_redirects(normalized)
        # prepare result
        res = {
            "normalized_score": normalized_score,
            "raw_score": score_info["raw_score"],
            "reasons": score_info["reasons"],
            "verdict": score_info["verdict"]
        }
        return render_template_string(INDEX_HTML, result=res, raw_input=raw, normalized=normalized, features=features, follow_result=follow_result)
    return render_template_string(INDEX_HTML, result=None)

if __name__ == "__main__":
    app.run(debug=True, port=5000)