import requests, re, socket, subprocess

SOURCES = [
    "https://openproxylist.com/latest.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/6.txt"
    # Можно добавить другие источники
]

SNI_VALID = {"www.apple.com", "www.google.com", "cloudflare.com"}
GEO_VALID = {"SE", "DE", "FI", "NL", "EU"}

def parse_vless(line):
    m = re.match(r'vless://([a-zA-Z0-9\-]+)@([0-9A-Za-z\.\-]+):(\d+)\?(.*)', line)
    if not m:
        return None
    uuid, host, port, params = m.groups()
    qs = dict(p.split('=') for p in params.split('&') if '=' in p)
    sni = qs.get('sni') or qs.get('host') or ""
    security = qs.get('security')
    flow = qs.get('flow', '')
    geo = host.split('.')[-1].upper() if host.count('.') == 3 else ''
    return {
        "uuid": uuid, "host": host, "port": int(port), "security": security, "flow": flow,
        "sni": sni, "geo": geo, "line": line.strip()
    }

def check_tcp(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

def check_tls_sni(host, port, sni, timeout=3):
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", sni, "-showcerts"]
    try:
        result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, text=True)
        return "Verify return code: 0" in result.stdout
    except:
        return False

def filter_configs():
    all_lines = []
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=10)
            all_lines.extend(r.text.splitlines())
        except:
            pass
    
    valid = []
    for line in all_lines:
        if not line.strip().startswith('vless://'):
            continue
        cfg = parse_vless(line)
        if not cfg:
            continue
        # Проверка GEO
        if cfg['geo'] and cfg['geo'] not in GEO_VALID:
            continue
        # Проверка TCP
        if not check_tcp(cfg['host'], cfg['port']):
            continue
        # Проверка TLS + SNI
        if cfg['security'] == 'tls' and cfg['sni']:
            if cfg['sni'] not in SNI_VALID:
                continue
            if not check_tls_sni(cfg['host'], cfg['port'], cfg['sni']):
                continue
        valid.append(cfg['line'])
    
    with open('filtered_vless.txt', 'w') as f:
        f.write('\n'.join(valid))

if __name__ == '__main__':
    filter_configs()
