#!/usr/bin/env python3
"""
Seb's Workshop — Port Scanner Backend
Requires: Python 3.8+, Flask, nmap installed on the host
Install:   pip install flask
Run:       python3 port-scanner-server.py
"""

import subprocess, json, re, socket, shutil
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── CORS (allow the HTML page to call this from any origin) ──────────────────
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

@app.route('/options', methods=['OPTIONS'])
def options(): return '', 204

# ── PORT KNOWLEDGE BASE ──────────────────────────────────────────────────────
PORT_INFO = {
    21:  {'name':'FTP',          'risk':'high',   'ce':True,  'desc':'File Transfer Protocol — plaintext, frequently exploited. Should not be internet-facing.'},
    22:  {'name':'SSH',          'risk':'medium', 'ce':True,  'desc':'Secure Shell — legitimate admin use but must be locked down to known IPs only. Brute-force target.'},
    23:  {'name':'Telnet',       'risk':'critical','ce':True, 'desc':'Telnet — completely unencrypted. Must be disabled. Automatic CE concern.'},
    25:  {'name':'SMTP',         'risk':'medium', 'ce':False, 'desc':'SMTP mail relay — should only be open if this server is a mail server. Open relay is a critical issue.'},
    53:  {'name':'DNS',          'risk':'medium', 'ce':False, 'desc':'DNS — should only be open externally if this is an authoritative DNS server.'},
    80:  {'name':'HTTP',         'risk':'low',    'ce':False, 'desc':'HTTP web server — traffic is unencrypted. Ensure it redirects to HTTPS (443).'},
    110: {'name':'POP3',         'risk':'high',   'ce':True,  'desc':'POP3 mail — plaintext email retrieval. Should be replaced with POP3S (995) or IMAP SSL (993).'},
    111: {'name':'RPC',          'risk':'high',   'ce':True,  'desc':'Remote Procedure Call — frequently exploited. Should never be internet-facing.'},
    135: {'name':'MS-RPC',       'risk':'critical','ce':True, 'desc':'Microsoft RPC — should never be internet-facing. Target for many Windows exploits.'},
    139: {'name':'NetBIOS',      'risk':'critical','ce':True, 'desc':'NetBIOS Session Service — should never be internet-facing. Used in many Windows network attacks.'},
    143: {'name':'IMAP',         'risk':'medium', 'ce':False, 'desc':'IMAP mail (unencrypted) — replace with IMAPS (993).'},
    161: {'name':'SNMP',         'risk':'high',   'ce':True,  'desc':'SNMP — if using v1 or v2c, community strings are sent in plaintext. Should not be internet-facing.'},
    389: {'name':'LDAP',         'risk':'high',   'ce':True,  'desc':'LDAP — unencrypted directory access. Should never be internet-facing; use LDAPS (636) internally.'},
    443: {'name':'HTTPS',        'risk':'info',   'ce':False, 'desc':'HTTPS web server — expected if serving a website. Ensure TLS is correctly configured.'},
    445: {'name':'SMB',          'risk':'critical','ce':True, 'desc':'SMB (Windows file sharing) — must never be internet-facing. EternalBlue and many critical exploits target this port.'},
    465: {'name':'SMTPS',        'risk':'low',    'ce':False, 'desc':'SMTP over SSL — legitimate if this is a mail server.'},
    500: {'name':'IKE/IPSec',    'risk':'low',    'ce':False, 'desc':'IPSec/IKE VPN — expected if running a VPN endpoint.'},
    587: {'name':'SMTP Submission','risk':'low',  'ce':False, 'desc':'Mail submission port — legitimate for mail servers. Ensure authentication is required.'},
    636: {'name':'LDAPS',        'risk':'low',    'ce':False, 'desc':'LDAP over SSL — acceptable if directory services are intentionally exposed.'},
    993: {'name':'IMAPS',        'risk':'low',    'ce':False, 'desc':'IMAP over SSL — acceptable for mail servers.'},
    995: {'name':'POP3S',        'risk':'low',    'ce':False, 'desc':'POP3 over SSL — acceptable for mail servers.'},
    1194:{'name':'OpenVPN',      'risk':'low',    'ce':False, 'desc':'OpenVPN — expected if running an OpenVPN endpoint.'},
    1433:{'name':'MSSQL',        'risk':'critical','ce':True, 'desc':'Microsoft SQL Server — should never be internet-facing. Direct DB access from internet is a critical security risk.'},
    1521:{'name':'Oracle DB',    'risk':'critical','ce':True, 'desc':'Oracle Database — should never be internet-facing.'},
    2222:{'name':'SSH (alt)',     'risk':'medium', 'ce':True,  'desc':'SSH on non-standard port — same risk as port 22, "security by obscurity" offers minimal protection.'},
    3306:{'name':'MySQL',        'risk':'critical','ce':True, 'desc':'MySQL — should never be internet-facing. Direct database access is a critical security risk.'},
    3389:{'name':'RDP',          'risk':'critical','ce':True, 'desc':'Remote Desktop Protocol — extremely high risk if internet-facing. Major ransomware entry point. Restrict to VPN only.'},
    4444:{'name':'Metasploit',   'risk':'critical','ce':True, 'desc':'Common malware/Metasploit callback port — if open, this is a major red flag.'},
    4500:{'name':'IPSec NAT-T',  'risk':'low',    'ce':False, 'desc':'IPSec NAT traversal — expected alongside port 500 for VPN.'},
    5432:{'name':'PostgreSQL',   'risk':'critical','ce':True, 'desc':'PostgreSQL — should never be internet-facing.'},
    5900:{'name':'VNC',          'risk':'critical','ce':True, 'desc':'VNC remote desktop — should never be internet-facing without a VPN. Frequently exploited.'},
    5985:{'name':'WinRM HTTP',   'risk':'critical','ce':True, 'desc':'Windows Remote Management — should never be internet-facing.'},
    5986:{'name':'WinRM HTTPS',  'risk':'high',   'ce':True,  'desc':'Windows Remote Management over HTTPS — should not be internet-facing without strict access controls.'},
    6379:{'name':'Redis',        'risk':'critical','ce':True, 'desc':'Redis — should never be internet-facing. Default config has no authentication.'},
    8080:{'name':'HTTP (alt)',    'risk':'medium', 'ce':False, 'desc':'Alternate HTTP port — often used for dev/admin interfaces. Ensure it redirects to HTTPS if serving content.'},
    8443:{'name':'HTTPS (alt)',   'risk':'low',    'ce':False, 'desc':'Alternate HTTPS port — acceptable if intentionally serving content here.'},
    8888:{'name':'HTTP (alt)',    'risk':'medium', 'ce':False, 'desc':'Common dev/proxy port — verify this is intentional.'},
    9200:{'name':'Elasticsearch','risk':'critical','ce':True, 'desc':'Elasticsearch — must never be internet-facing. Numerous data breach incidents from exposed Elasticsearch instances.'},
    27017:{'name':'MongoDB',     'risk':'critical','ce':True, 'desc':'MongoDB — must never be internet-facing. Notorious for misconfigured publicly accessible databases.'},
}

RISK_ORDER = {'critical':0,'high':1,'medium':2,'low':3,'info':4,'unknown':5}

# ── HELPERS ──────────────────────────────────────────────────────────────────
def resolve_host(target):
    try:
        ip = socket.gethostbyname(target)
        return ip, None
    except socket.gaierror as e:
        return None, str(e)

def is_private(ip):
    parts = list(map(int, ip.split('.')))
    return (parts[0]==10 or
            (parts[0]==172 and 16<=parts[1]<=31) or
            (parts[0]==192 and parts[1]==168) or
            parts[0]==127)

# ── SCAN ─────────────────────────────────────────────────────────────────────
@app.route('/scan', methods=['POST', 'OPTIONS'])
def scan():
    if request.method == 'OPTIONS':
        return '', 204

    data   = request.get_json(force=True) or {}
    target = (data.get('target','') or '').strip()
    mode   = data.get('mode', 'common')   # common | full | quick

    if not target:
        return jsonify({'error': 'No target provided'}), 400

    # Strip protocol if accidentally included
    target = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]

    # Check nmap is available
    if not shutil.which('nmap'):
        return jsonify({'error': 'nmap is not installed. Run: sudo apt install nmap  or  brew install nmap'}), 500

    # Resolve
    ip, err = resolve_host(target)
    if not ip:
        return jsonify({'error': f'Could not resolve "{target}": {err}'}), 400

    # Warn but don't block private IPs (user may be scanning their own infra)
    private = is_private(ip)

    # Build nmap command
    if mode == 'quick':
        port_arg = '-F'                        # top 100
        timing   = '-T4'
    elif mode == 'full':
        port_arg = '-p 1-65535'                # all ports
        timing   = '-T4'
    else:  # common — top 1000 + our known risky ones
        risky    = ','.join(str(p) for p in PORT_INFO.keys())
        port_arg = f'--top-ports 1000 -p {risky}'
        timing   = '-T4'

    cmd = ['nmap', timing, '-sV', '--open', '-oX', '-', port_arg, ip]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        xml_out = result.stdout
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Scan timed out (120s). Try "Quick" mode for faster results.'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    ports = parse_nmap_xml(xml_out)

    # Annotate with our knowledge base
    annotated = []
    for p in ports:
        num = p['port']
        info = PORT_INFO.get(num, {})
        annotated.append({
            **p,
            'service_name': info.get('name', p.get('service', 'Unknown')),
            'risk':         info.get('risk', 'unknown'),
            'ce_concern':   info.get('ce', False),
            'description':  info.get('desc', f'Port {num} — no specific guidance available.'),
        })

    annotated.sort(key=lambda x: RISK_ORDER.get(x['risk'], 5))

    summary = {
        'target':   target,
        'ip':       ip,
        'private':  private,
        'mode':     mode,
        'scanned_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
        'open_count': len(annotated),
        'critical':  sum(1 for p in annotated if p['risk']=='critical'),
        'high':      sum(1 for p in annotated if p['risk']=='high'),
        'medium':    sum(1 for p in annotated if p['risk']=='medium'),
        'ce_concerns': sum(1 for p in annotated if p['ce_concern']),
    }

    return jsonify({'summary': summary, 'ports': annotated})


def parse_nmap_xml(xml):
    """Lightweight nmap XML parser — no external deps."""
    ports = []
    for m in re.finditer(r'<port protocol="([^"]+)" portid="(\d+)">(.*?)</port>', xml, re.DOTALL):
        proto, portid, inner = m.group(1), int(m.group(2)), m.group(3)
        state_m  = re.search(r'<state state="([^"]+)"', inner)
        svc_m    = re.search(r'<service name="([^"]*)"[^/]*/>', inner)
        prod_m   = re.search(r'product="([^"]*)"', inner)
        ver_m    = re.search(r'version="([^"]*)"', inner)
        state = state_m.group(1) if state_m else 'unknown'
        if state != 'open':
            continue
        ports.append({
            'port':     portid,
            'protocol': proto,
            'state':    state,
            'service':  svc_m.group(1) if svc_m else '',
            'product':  prod_m.group(1) if prod_m else '',
            'version':  ver_m.group(1)  if ver_m  else '',
        })
    return ports


# ── STATUS ───────────────────────────────────────────────────────────────────
@app.route('/status', methods=['GET'])
def status():
    nmap_ok   = bool(shutil.which('nmap'))
    nmap_ver  = ''
    if nmap_ok:
        try:
            r = subprocess.run(['nmap','--version'], capture_output=True, text=True, timeout=5)
            nmap_ver = r.stdout.splitlines()[0] if r.stdout else ''
        except: pass
    return jsonify({'ok': nmap_ok, 'nmap': nmap_ver})


if __name__ == '__main__':
    print('\n  🔍 Seb\'s Workshop — Port Scanner Backend')
    print('  ─────────────────────────────────────────')
    if not shutil.which('nmap'):
        print('  ⚠  nmap not found. Install it first:')
        print('     Ubuntu/Debian: sudo apt install nmap')
        print('     macOS:         brew install nmap')
        print('     Windows:       https://nmap.org/download.html\n')
    else:
        print('  ✓  nmap found')
    print('  ✓  Listening on http://localhost:5050')
    print('  ✓  Open port-scanner.html in your browser\n')
    app.run(host='127.0.0.1', port=5050, debug=False)
