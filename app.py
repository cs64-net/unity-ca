#!/usr/bin/env python3
"""
Unity-CA Flask app (single-file)

Auth behavior:
 - If UNITY_CA_PASSWORD is set (non-empty), basic auth is enforced but **only the password is checked**.
   The username is ignored (you can supply any username; browsers will still prompt for it).
 - If UNITY_CA_PASSWORD is not set or empty, auth is disabled (open access).

Storage:
 - Default local storage: /data/issued, /data/root, /data/config
 - Override with env vars:
     UNITY_CA_ISSUED  (e.g. /mnt/encrypted/pki/issued)
     UNITY_CA_ROOT
     UNITY_CA_CONFIG

Other env:
 - UNITY_CA_SECRET_KEY  (Flask secret key; if not set a dev secret is used)
 - UNITY_CA_PORT        (port to run on; default 5000)
 - UNITY_CA_DEBUG       (set to "1" to enable Flask debug)
"""

from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from flask_httpauth import HTTPBasicAuth
import subprocess
import os
import re
import json
from werkzeug.utils import safe_join
import logging
import time
import ipaddress

app = Flask(__name__)

# ---------------- Environment / config ----------------
# Secret key (replace in production)
app.secret_key = os.environ.get("UNITY_CA_SECRET_KEY") or "dev-secret-unity-ca"

# Password-only auth: treat empty string as "not set"
PASSWORD = os.environ.get("UNITY_CA_PASSWORD") or None

# Storage directories (override via env)
certs_dir = os.environ.get("UNITY_CA_ISSUED", "/data/issued")
ca_dir = os.environ.get("UNITY_CA_ROOT", "/data/root")
config_dir = os.environ.get("UNITY_CA_CONFIG", "/data/config")

# Ensure directories exist
for d in (certs_dir, ca_dir, config_dir):
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        # Best-effort creation; continue (may fail in some container setups)
        pass

# Logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("unity-ca")

# ---------------- Authentication ----------------
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    """
    Password-only authentication:
    - If PASSWORD is not set -> authentication disabled (this function won't be used).
    - If PASSWORD is set -> username is ignored, only password is validated.
    Returns a truthy user-object (we return a string) on success, else False/None.
    """
    if PASSWORD is None:
        # If auth disabled, treat as successful; note: auth.login_required won't be used in that case.
        return username or "anonymous"
    # BasicAuth passes username and password (both could be empty strings).
    if password and password == PASSWORD:
        # return username if present so g.current_user is meaningful; else return a placeholder
        return username or "password-only-user"
    return None

def auth_required(func):
    """
    Decorator that enforces authentication only if PASSWORD is set.
    If PASSWORD is None => returns the original view (no auth).
    """
    if PASSWORD is None:
        return func
    return auth.login_required(func)

# ---------------- Validation and helpers ----------------
DISPLAY_NAME_RE = re.compile(r'^[a-zA-Z0-9 ._\-]{1,120}$')
SUBJECT_FIELD_RE = re.compile(r'^[a-zA-Z0-9 .,\-()]{0,128}$')
CN_RE = re.compile(r'^[a-zA-Z0-9 ._\-]{1,128}$')  # allow spaces in CN for display

def safe_name(name: str) -> str:
    """Sanitize an arbitrary display name into a safe filename part."""
    if not name:
        return ''
    sanitized = re.sub(r'[^A-Za-z0-9._-]', '_', name)
    return sanitized[:64]

def validate_display_name(name: str) -> bool:
    return bool(name) and bool(DISPLAY_NAME_RE.match(name))

def validate_subject_field(val: str) -> bool:
    if val is None:
        return True
    if val == '':
        return True
    return bool(SUBJECT_FIELD_RE.match(val))

def validate_country_code(c: str) -> bool:
    if c is None or c == '':
        return True
    return bool(re.match(r'^[A-Za-z]{2}$', c))

def build_subject(c: str, o: str, ou: str, cn: str) -> str:
    parts = []
    if c:
        parts.append(f"/C={c}")
    if o:
        parts.append(f"/O={o}")
    if ou:
        parts.append(f"/OU={ou}")
    if cn:
        parts.append(f"/CN={cn}")
    return ''.join(parts)

# ---------------- CA metadata ----------------
def ca_metadata_path(safe: str) -> str:
    return os.path.join(ca_dir, f"{safe}.json")

def write_ca_metadata(safe: str, metadata: dict):
    with open(ca_metadata_path(safe), 'w') as fh:
        json.dump(metadata, fh, indent=2)

def read_ca_metadata(safe: str) -> dict:
    path = ca_metadata_path(safe)
    if not os.path.exists(path):
        return {}
    with open(path, 'r') as fh:
        return json.load(fh)

def list_available_cas():
    cas = []
    try:
        files = os.listdir(ca_dir)
    except Exception:
        files = []
    for file in files:
        if file.endswith('.crt'):
            safe = file[:-4]
            cert_path = os.path.join(ca_dir, file)
            key_path = os.path.join(ca_dir, f"{safe}.key")
            meta = read_ca_metadata(safe)
            display = meta.get('display_name', safe)
            # only list if key exists (we expect both cert + key for signing)
            if os.path.exists(key_path):
                cas.append({
                    'display': display,
                    'safe': safe,
                    'cert': cert_path,
                    'key': key_path,
                    'metadata': meta
                })
    cas.sort(key=lambda x: x['display'].lower())
    return cas

# ---------------- Signing profile management ----------------
def profile_path(name: str) -> str:
    safe = safe_name(name)
    return os.path.join(config_dir, f"{safe}.json")

def write_profile(name: str, profile: dict):
    with open(profile_path(name), 'w') as fh:
        json.dump(profile, fh, indent=2)

def read_profile_by_safe(safe: str) -> dict:
    path = os.path.join(config_dir, f"{safe}.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r') as fh:
            return json.load(fh)
    except Exception:
        return {}

def list_signing_profiles():
    profiles = []
    try:
        files = os.listdir(config_dir)
    except Exception:
        files = []
    for file in files:
        if file.endswith('.json'):
            safe = file[:-5]
            path = os.path.join(config_dir, file)
            try:
                with open(path, 'r') as fh:
                    data = json.load(fh)
            except Exception:
                data = {}
            display = data.get('display_name', safe)
            profiles.append({'display': display, 'safe': safe, 'data': data})
    profiles.sort(key=lambda x: x['display'].lower())
    return profiles

def ensure_default_profile():
    default_name = "unity-default"
    path = profile_path(default_name)
    if not os.path.exists(path):
        default = {
            "display_name": "unity-default",
            "C": "GB",
            "O": "UNITY",
            "OU": "UNITY TRUST SERVICES",
            "days": 365
        }
        write_profile(default_name, default)

ensure_default_profile()

# Inject lists into templates (if you're using Jinja templates)
@app.context_processor
def inject_globals():
    return dict(available_cas=list_available_cas(), signing_profiles=list_signing_profiles())

# ---------------- Certificate helpers ----------------
def is_ip_address(value: str) -> bool:
    """Return True if value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except Exception:
        return False

def parse_san_input(raw: str):
    """
    Parse a comma-separated SAN string from the UI into a clean list,
    preserving order and de-duplicating.
    """
    if not raw:
        return []
    parts = re.split(r'[,\n]+', raw)
    cleaned = []
    seen = set()
    for p in parts:
        item = p.strip()
        if not item:
            continue
        if item not in seen:
            cleaned.append(item)
            seen.add(item)
    return cleaned[:100]

def generate_private_key(key_path: str):
    cmd = ['openssl', 'ecparam', '-genkey', '-name', 'prime256v1', '-noout', '-out', key_path]
    subprocess.run(cmd, check=True, capture_output=True)

def create_cert_config(domain_name: str, san_list: list, config_path: str, profile: dict):
    """
    Create OpenSSL req config file for generating CSR with multiple SANs.
    """
    lines = [
        "[ req ]",
        "default_bits       = 2048",
        "prompt             = no",
        "default_md         = sha256",
        "distinguished_name = dn",
        "req_extensions     = req_ext",
        "",
        "[ dn ]"
    ]
    if profile.get('C'):
        lines.append(f"C  = {profile.get('C')}")
    if profile.get('O'):
        lines.append(f"O  = {profile.get('O')}")
    if profile.get('OU'):
        lines.append(f"OU = {profile.get('OU')}")
    lines.append(f"CN = {domain_name}")

    lines.extend(["", "[ req_ext ]", "subjectAltName = @alt_names", "", "[ alt_names ]"])

    dns_i = 0
    ip_i = 0
    for entry in san_list:
        if is_ip_address(entry):
            ip_i += 1
            lines.append(f"IP.{ip_i} = {entry}")
        else:
            dns_i += 1
            lines.append(f"DNS.{dns_i} = {entry}")

    with open(config_path, 'w') as fh:
        fh.write("\n".join(lines))

def generate_csr_from_key(domain_name: str, key_path: str, config_path: str, csr_path: str):
    cmd = ['openssl', 'req', '-new', '-key', key_path, '-out', csr_path, '-config', config_path]
    subprocess.run(cmd, check=True, capture_output=True)

def create_cert_ext(san_list: list, ext_path: str):
    """
    Create x509 extensions file for signing, mirroring the same SANs.
    """
    lines = [
        "authorityKeyIdentifier=keyid,issuer",
        "basicConstraints=CA:FALSE",
        "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment",
        "extendedKeyUsage = serverAuth",
        "subjectAltName = @alt_names",
        "",
        "[ alt_names ]"
    ]

    dns_i = 0
    ip_i = 0
    for entry in san_list:
        if is_ip_address(entry):
            ip_i += 1
            lines.append(f"IP.{ip_i} = {entry}")
        else:
            dns_i += 1
            lines.append(f"DNS.{dns_i} = {entry}")

    with open(ext_path, 'w') as fh:
        fh.write("\n".join(lines))

def sign_csr_with_ca(csr_path: str, ext_path: str, out_cert_path: str, ca_cert: str, ca_key: str, days: int):
    cmd = [
        'openssl', 'x509', '-req', '-in', csr_path,
        '-CA', ca_cert, '-CAkey', ca_key,
        '-CAcreateserial', '-out', out_cert_path,
        '-days', str(days), '-sha256', '-extfile', ext_path
    ]
    subprocess.run(cmd, check=True, capture_output=True)

def get_certificate_expiry(cert_path: str) -> str:
    try:
        result = subprocess.run(['openssl', 'x509', '-enddate', '-noout', '-in', cert_path],
                                 capture_output=True, text=True, check=True)
        return result.stdout.strip().split('=', 1)[1]
    except Exception:
        return "Unknown"

# ---------------- Routes ----------------
@app.route('/', methods=['GET', 'POST'])
@auth_required
def index():
    # POST => generate cert from CN + SAN
    if request.method == 'POST':
        cn = request.form.get('cn', '').strip()
        san_raw = request.form.get('san', '').strip()
        selected_ca_safe = request.form.get('ca')
        selected_profile_safe = request.form.get('profile', 'unity-default')

        if not cn or not CN_RE.match(cn):
            flash("Invalid Common Name (CN). Avoid control chars and very long values.")
            return redirect(url_for('index'))

        san_list = parse_san_input(san_raw)
        if not san_list:
            flash("Invalid SAN. Enter one or more values, comma-separated (e.g., 1.1.1.1, test.example.com).")
            return redirect(url_for('index'))
        if len(",".join(san_list)) > 2048:
            flash("SAN list too long.")
            return redirect(url_for('index'))

        profile = read_profile_by_safe(selected_profile_safe)
        if not profile:
            flash("Selected signing profile not found.")
            return redirect(url_for('index'))

        if not validate_country_code(profile.get('C', '')):
            flash("Profile country code (C) must be two letters if provided.")
            return redirect(url_for('index'))

        ca = next((c for c in list_available_cas() if c['safe'] == selected_ca_safe), None)
        if not ca:
            flash("Invalid CA selected to sign certificate.")
            return redirect(url_for('index'))

        safe_base = safe_name(cn)
        key_path = os.path.join(certs_dir, f"{safe_base}.key")
        csr_config = os.path.join(certs_dir, f"{safe_base}.csr.cnf")
        csr_path = os.path.join(certs_dir, f"{safe_base}.csr")
        ext_path = os.path.join(certs_dir, f"{safe_base}.ext")
        cert_path = os.path.join(certs_dir, f"{safe_base}.crt")

        try:
            generate_private_key(key_path)
            create_cert_config(cn, san_list, csr_config, profile)
            generate_csr_from_key(cn, key_path, csr_config, csr_path)
            create_cert_ext(san_list, ext_path)
            days = int(profile.get('days', 365))
            sign_csr_with_ca(csr_path, ext_path, cert_path, ca['cert'], ca['key'], days)
            # cleanup intermediate files
            for f in (csr_config, csr_path, ext_path):
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except Exception:
                    pass
            flash(f"Certificate for '{cn}' generated and signed by CA '{ca['display']}'.")
        except subprocess.CalledProcessError as e:
            stderr = (e.stderr.decode() if hasattr(e, 'stderr') and e.stderr else str(e))
            logger.exception("OpenSSL error creating certificate")
            flash(f"OpenSSL error during certificate creation: {stderr}")
        except Exception as e:
            logger.exception("General error creating certificate")
            flash(f"Error creating certificate: {str(e)}")

        return redirect(url_for('index'))

    # GET -> list issued certs
    issued_certs = []
    try:
        for f in os.listdir(certs_dir):
            if f.endswith('.crt'):
                p = os.path.join(certs_dir, f)
                try:
                    expiry = get_certificate_expiry(p)
                except Exception:
                    expiry = "Unknown"
                issued_certs.append({'name': f, 'expiry': expiry})
        issued_certs.sort(key=lambda x: x['name'])
    except Exception:
        issued_certs = []

    # render_template expects an index.html in templates/ — keep your current templates
    return render_template('index.html', certs=issued_certs)

@app.route('/create_ca', methods=['POST'])
@auth_required
def create_ca():
    display_name = request.form.get('display_name', '').strip()
    ca_type = request.form.get('ca_type', 'root')
    c = request.form.get('C', '').strip()
    o = request.form.get('O', '').strip()
    ou = request.form.get('OU', '').strip()
    cn = request.form.get('CN', '').strip()

    if not validate_display_name(display_name):
        flash("Invalid CA display name. Allowed: letters, numbers, spaces, ., _, - (1-120 chars).")
        return redirect(url_for('index'))
    if not cn:
        flash("CN is required for CA subject.")
        return redirect(url_for('index'))
    if not validate_subject_field(c) or not validate_subject_field(o) or not validate_subject_field(ou) or not validate_subject_field(cn):
        flash("Invalid characters in subject fields.")
        return redirect(url_for('index'))
    if not validate_country_code(c):
        flash("Country (C) must be two letters if provided.")
        return redirect(url_for('index'))

    safe = safe_name(display_name)
    key_path = os.path.join(ca_dir, f"{safe}.key")
    cert_path = os.path.join(ca_dir, f"{safe}.crt")

    # prevent overwrite
    if os.path.exists(key_path) or os.path.exists(cert_path) or os.path.exists(ca_metadata_path(safe)):
        flash("A CA with that name already exists. Choose a different display name.")
        return redirect(url_for('index'))

    subject = build_subject(c, o, ou, cn)
    if not subject:
        flash("Subject construction failed; provide at least CN.")
        return redirect(url_for('index'))

    try:
        # generate key
        generate_private_key(key_path)

        if ca_type == 'root':
            # create self-signed root with provided subject
            cmd = [
                'openssl', 'req', '-x509', '-new', '-nodes',
                '-key', key_path, '-sha256', '-days', '3650',
                '-subj', subject,
                '-out', cert_path
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            metadata = {'display_name': display_name, 'safe_name': safe, 'type': 'root', 'subject': subject}
            write_ca_metadata(safe, metadata)
            flash(f"Root CA '{display_name}' created successfully.")

        elif ca_type == 'issuing':
            parent_safe = request.form.get('parent_ca', '')
            parent = next((c for c in list_available_cas() if c['safe'] == parent_safe), None)
            if not parent:
                # cleanup key
                try:
                    if os.path.exists(key_path):
                        os.remove(key_path)
                except Exception:
                    pass
                flash("Parent Root CA not found. Choose an existing Root CA to sign this Issuing CA.")
                return redirect(url_for('index'))

            csr_path = os.path.join(ca_dir, f"{safe}.csr")
            cmd_req = ['openssl', 'req', '-new', '-key', key_path, '-subj', subject, '-out', csr_path]
            subprocess.run(cmd_req, check=True, capture_output=True)

            cmd_sign = [
                'openssl', 'x509', '-req', '-in', csr_path,
                '-CA', parent['cert'], '-CAkey', parent['key'],
                '-CAcreateserial', '-out', cert_path,
                '-days', '1825', '-sha256'
            ]
            subprocess.run(cmd_sign, check=True, capture_output=True)

            try:
                if os.path.exists(csr_path):
                    os.remove(csr_path)
            except Exception:
                pass

            metadata = {'display_name': display_name, 'safe_name': safe, 'type': 'issuing', 'subject': subject, 'signed_by': parent['safe']}
            write_ca_metadata(safe, metadata)
            flash(f"Issuing CA '{display_name}' created and signed by '{parent['display']}'.")

        else:
            flash("Unknown CA type.")
            if os.path.exists(key_path):
                os.remove(key_path)

    except subprocess.CalledProcessError as e:
        stderr = (e.stderr.decode() if hasattr(e, 'stderr') and e.stderr else str(e))
        logger.exception("OpenSSL error creating CA")
        # cleanup
        for p in (key_path, cert_path, ca_metadata_path(safe)):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        flash(f"OpenSSL error creating CA: {stderr}")
    except Exception as e:
        logger.exception("Error creating CA")
        for p in (key_path, cert_path, ca_metadata_path(safe)):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        flash(f"Error creating CA: {str(e)}")

    return redirect(url_for('index'))

@app.route('/create_profile', methods=['POST'])
@auth_required
def create_profile():
    display_name = request.form.get('profile_display', '').strip()
    c = request.form.get('profile_C', '').strip()
    o = request.form.get('profile_O', '').strip()
    ou = request.form.get('profile_OU', '').strip()
    days = request.form.get('profile_days', '365').strip()

    if not display_name or not validate_display_name(display_name):
        flash("Invalid profile display name.")
        return redirect(url_for('index'))
    if not validate_subject_field(c) or not validate_subject_field(o) or not validate_subject_field(ou):
        flash("Invalid characters in profile fields.")
        return redirect(url_for('index'))
    if not validate_country_code(c):
        flash("Country (C) in profile must be two letters if provided.")
        return redirect(url_for('index'))
    try:
        days_i = int(days)
    except Exception:
        flash("Invalid days value for profile.")
        return redirect(url_for('index'))

    safe = safe_name(display_name)
    path = profile_path(display_name)
    if os.path.exists(path):
        flash("A profile with that name already exists.")
        return redirect(url_for('index'))

    profile = {
        'display_name': display_name,
        'C': c,
        'O': o,
        'OU': ou,
        'days': days_i
    }
    try:
        write_profile(display_name, profile)
        flash(f"Signing profile '{display_name}' created.")
    except Exception as e:
        logger.exception("Error writing profile")
        flash(f"Error creating profile: {str(e)}")
    return redirect(url_for('index'))

@app.route('/submit_csr', methods=['POST'])
@auth_required
def submit_csr():
    csr_content = request.form.get('csr', '').strip()
    selected_ca_safe = request.form.get('csr_ca')
    selected_profile_safe = request.form.get('csr_profile', 'unity-default')

    if not csr_content:
        flash("CSR content is required.")
        return redirect(url_for('index'))

    ca = next((c for c in list_available_cas() if c['safe'] == selected_ca_safe), None)
    if not ca:
        flash("Invalid CA selected to sign CSR.")
        return redirect(url_for('index'))

    profile = read_profile_by_safe(selected_profile_safe)
    if not profile:
        flash("Signing profile not found.")
        return redirect(url_for('index'))

    temp_csr_path = os.path.join(certs_dir, 'temp_uploaded.csr')
    temp_cert_path = os.path.join(certs_dir, 'temp_signed.crt')
    ext_path = os.path.join(certs_dir, 'temp_uploaded.ext')
    try:
        with open(temp_csr_path, 'w') as fh:
            fh.write(csr_content)

        # minimal ext file
        with open(ext_path, 'w') as fh:
            fh.write("basicConstraints=CA:FALSE\n")

        days = int(profile.get('days', 365))
        cmd = [
            'openssl', 'x509', '-req', '-in', temp_csr_path,
            '-CA', ca['cert'], '-CAkey', ca['key'],
            '-CAcreateserial', '-out', temp_cert_path,
            '-days', str(days), '-sha256'
        ]
        subprocess.run(cmd, check=True, capture_output=True)

        # try to extract CN for filename
        cn = None
        try:
            proc = subprocess.run(['openssl', 'x509', '-noout', '-subject', '-in', temp_cert_path],
                                  capture_output=True, text=True, check=True)
            subj = proc.stdout.strip()
            m = re.search(r'/CN=([^/]+)', subj)
            if m:
                cn = m.group(1)
        except Exception:
            cn = None

        if cn:
            safe_base = safe_name(cn)
            final_cert_path = os.path.join(certs_dir, f"{safe_base}.crt")
        else:
            safe_base = f"csr_signed_{int(time.time())}"
            final_cert_path = os.path.join(certs_dir, f"{safe_base}.crt")

        os.replace(temp_cert_path, final_cert_path)

        for p in (temp_csr_path, ext_path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass

        flash(f"CSR signed by CA '{ca['display']}' and saved as '{os.path.basename(final_cert_path)}'.")

    except subprocess.CalledProcessError as e:
        stderr = (e.stderr.decode() if hasattr(e, 'stderr') and e.stderr else str(e))
        logger.exception("OpenSSL error signing CSR")
        for p in (temp_csr_path, temp_cert_path, ext_path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        flash(f"OpenSSL error signing CSR: {stderr}")
    except Exception as e:
        logger.exception("Error signing CSR")
        for p in (temp_csr_path, temp_cert_path, ext_path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        flash(f"Error signing CSR: {str(e)}")

    return redirect(url_for('index'))

@app.route('/download/cert/<filename>')
@auth_required
def download_cert(filename):
    try:
        full = safe_join(certs_dir, filename)
        if full and os.path.exists(full):
            # Flask's send_from_directory in modern versions takes (directory, path=..., as_attachment=...)
            return send_from_directory(directory=certs_dir, path=filename, as_attachment=True)
        else:
            flash("File not found.")
            return redirect(url_for('index'))
    except Exception as e:
        flash(f"Error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/download/key/<filename>')
@auth_required
def download_key(filename):
    try:
        full = safe_join(certs_dir, filename)
        if full and os.path.exists(full):
            return send_from_directory(directory=certs_dir, path=filename, as_attachment=True)
        else:
            flash("File not found.")
            return redirect(url_for('index'))
    except Exception as e:
        flash(f"Error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/download/ca/<safe>')
@auth_required
def download_ca_cert(safe):
    ca = next((c for c in list_available_cas() if c['safe'] == safe), None)
    if not ca:
        flash("CA not found.")
        return redirect(url_for('index'))
    filename = f"{safe}.crt"
    try:
        full = safe_join(ca_dir, filename)
        if full and os.path.exists(full):
            return send_from_directory(directory=ca_dir, path=filename, as_attachment=True)
        else:
            flash("CA certificate file missing.")
            return redirect(url_for('index'))
    except Exception as e:
        flash(f"Error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/delete/<filename>')
@auth_required
def delete_cert(filename):
    cert_path = os.path.join(certs_dir, filename)
    key_path = cert_path.replace('.crt', '.key')
    csr_path = cert_path.replace('.crt', '.csr')
    ext_path = cert_path.replace('.crt', '.ext')
    try:
        for p in (cert_path, key_path, csr_path, ext_path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        flash(f"Deleted {filename} and related files.")
    except Exception as e:
        flash(f"Error deleting: {str(e)}")
    return redirect(url_for('index'))

# ---------------- App entrypoint ----------------
if __name__ == '__main__':
    port_env = os.environ.get('UNITY_CA_PORT')
    try:
        port = int(port_env) if port_env else 5000
    except Exception:
        port = 5000
    debug_mode = os.environ.get('UNITY_CA_DEBUG', '0') == '1'

    # Bind to 0.0.0.0 so the container is accessible from host
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
