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
        "uuid": uuid, "host": host, "port": int(port), "security": security, "flow": flow, "
