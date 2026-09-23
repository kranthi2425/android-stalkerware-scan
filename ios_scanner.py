#!/usr/bin/env python3
"""Defensive, read-only iPhone stalkerware triage over an unencrypted iTunes/Finder backup.

Pure Python standard library. Nothing on the phone or in the backup is modified.
"""
from __future__ import annotations
import argparse, datetime as dt, ipaddress, json, plistlib, re, sqlite3, sys
from pathlib import Path
from urllib.parse import urlsplit

from scanner import severity

ROOT = Path(__file__).resolve().parent
APPLE_EPOCH = dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc)
PROFILES_DOMAIN = 'SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles'
DOMAIN_ROOTS = {'HomeDomain': '/private/var/mobile', 'RootDomain': '/private/var/root',
                'SystemPreferencesDomain': '/private/var/preferences', 'WirelessDomain': '/private/var/wireless',
                'ManagedPreferencesDomain': '/private/var/Managed Preferences', 'MediaDomain': '/private/var/mobile',
                'KeychainDomain': '/private/var/Keychains', 'DatabaseDomain': '/private/var/db'}
# Payload types that can route, inspect, or filter traffic, or put the phone under remote management.
HIGH_RISK_PAYLOADS = {
    'com.apple.mdm': 'Mobile Device Management (remote management)',
    'com.apple.vpn.managed': 'VPN (can route traffic through a third party)',
    'com.apple.vpn.managed.applayer': 'Per-app VPN',
    'com.apple.proxy.http.global': 'Global HTTP proxy (can inspect web traffic)',
    'com.apple.security.root': 'Trusted root certificate (can enable traffic interception)',
    'com.apple.webcontent-filter': 'Web content filter (can see browsing)',
    'com.apple.dnsSettings.managed': 'Encrypted DNS settings (can see visited domains)',
    'com.apple.dnsProxy.managed': 'DNS proxy (can see visited domains)',
    'com.apple.relay.managed': 'Network relay (can route traffic)',
}
URL_RE = re.compile(r'(?i)\b(?:https?://|www\.)[^\s<>"\']+')
HOST_RE = re.compile(r'(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b')
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

SAFETY = ('SAFETY FIRST: Do not delete profiles, apps, or backups, reset the phone, or confront anyone until you have a safety plan. '
          'Removal can alert an abuser and can destroy evidence. Use a safer device to contact a trusted advocate or local support service.')
CAVEAT = ('A clean scan does not mean a clean phone. Many ways of spying on an iPhone leave nothing in a backup: someone who knows the Apple Account '
          'password or has a shared Apple Account, iCloud backups, Find My or location sharing, family-sharing and "parental" apps, a second '
          'paired device, or a new or unlisted tool. This scan only sees what the backup contains and only matches public indicators.')
ACCOUNT_HYGIENE = [
    'Run Safety Check (iOS 16 or later): Settings > Privacy & Security > Safety Check. Use "Manage Sharing & Access" to review, one by one, who and which apps can see your location, photos, notes, and other data. "Emergency Reset" stops all sharing at once, so only use it when it is safe for sharing to stop suddenly.',
    'Review devices signed in to your Apple Account: Settings > [your name] > scroll to the device list. Remove any device you do not recognize.',
    'Change your Apple Account password and check trusted phone numbers and email: Settings > [your name] > Sign-In & Security. Keep two-factor authentication on.',
    'Change the iPhone passcode if anyone else may know it: Settings > Face ID/Touch ID & Passcode.',
    'Review location sharing in the Find My app (People tab) and in Family Sharing (Settings > [your name] > Family).',
    'Check Settings > General > VPN & Device Management for profiles or management you did not set up.',
    'Apple Personal Safety guide: https://support.apple.com/guide/personal-safety/safety-check-iphone-ios-16-ips2aad835e1/web',
]
LIMITATIONS = [
    'Reads unencrypted backups only in this version. Encrypted backups are refused, not guessed at.',
    'A standard backup does not contain the system partition, so most jailbreak files are only visible as app data, preferences, or leftovers.',
    'Network indicators are matched only against Safari history and message text stored in the backup, not live traffic or other apps.',
    'Apple notes that unencrypted backups can leave out website history, call history, saved passwords, Wi-Fi settings, and Health data (https://support.apple.com/en-us/108353). If "network_iocs" shows safari_databases=0, browsing history was not checked.',
    'Public indicator lists age quickly. See iocs/ for the pinned snapshot dates.',
]

class BackupError(Exception): pass

def load_plist(path):
    try:
        with open(path, 'rb') as fh: return plistlib.load(fh)
    except Exception: return None

def ro_connect(path):
    return sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro&immutable=1', uri=True)

def apple_time(value):
    """Convert Apple absolute time (seconds, or nanoseconds on newer iOS) to ISO 8601."""
    try: v = float(value)
    except (TypeError, ValueError): return None
    if not v: return None
    if abs(v) > 1e11: v /= 1e9
    try: return (APPLE_EPOCH + dt.timedelta(seconds=v)).isoformat()
    except OverflowError: return None

class Backup:
    def __init__(self, path):
        p = Path(path).expanduser()
        if not (p / 'Manifest.db').exists():
            subs = [d for d in p.iterdir() if d.is_dir() and (d / 'Manifest.db').exists()] if p.is_dir() else []
            if len(subs) == 1: p = subs[0]
            elif len(subs) > 1: raise BackupError('Several backups found here. Pass one backup folder: ' + ', '.join(sorted(d.name for d in subs)))
            else: raise BackupError(f'No Manifest.db in {p}. Point --backup at one iPhone backup folder.')
        self.path = p
        self.info = load_plist(p / 'Info.plist') or {}
        self.manifest = load_plist(p / 'Manifest.plist') or {}
        if self.manifest.get('IsEncrypted'):
            raise BackupError('This backup is encrypted. This version reads unencrypted backups only. See README "Make a backup" for options.')
        try:
            con = ro_connect(p / 'Manifest.db')
            self.files = [{'file_id': r[0], 'domain': r[1] or '', 'path': r[2] or '', 'flags': r[3]}
                          for r in con.execute('SELECT fileID, domain, relativePath, flags FROM Files')]
            con.close()
        except sqlite3.DatabaseError as e:
            raise BackupError(f'Manifest.db could not be read ({e}). The backup may be encrypted, incomplete, or damaged.')

    def blob(self, file_id):
        f = self.path / file_id[:2] / file_id
        return f if f.exists() else (self.path / file_id if (self.path / file_id).exists() else None)

    def find(self, domain=None, path=None, suffix=None):
        return [f for f in self.files if (domain is None or f['domain'] == domain)
                and (path is None or f['path'] == path) and (suffix is None or f['path'].endswith(suffix))]

    def apps(self):
        apps = set(self.manifest.get('Applications', {}) or {})
        apps |= set(self.info.get('Installed Applications', []) or [])
        for f in self.files:
            if f['domain'].startswith('AppDomain-'): apps.add(f['domain'][10:])
        return apps

    def device(self):
        lock = self.manifest.get('Lockdown', {}) or {}
        return {'model': self.info.get('Product Type') or lock.get('ProductType') or 'unknown',
                'ios': self.info.get('Product Version') or lock.get('ProductVersion') or 'unknown',
                'name': self.info.get('Device Name') or lock.get('DeviceName') or 'unknown',
                'serial': self.info.get('Serial Number') or lock.get('SerialNumber') or 'unknown'}

def finding(check, indicator, score, reasons, evidence=None, families=None):
    return {'check': check, 'indicator': indicator, 'score': score, 'severity': severity(score),
            'reasons': reasons, 'families': sorted(families or []), 'evidence': evidence or []}

# ---------- check 1: jailbreak artifacts ----------

def device_path(f):
    root = DOMAIN_ROOTS.get(f['domain'])
    return f"{root}/{f['path']}" if root else f"{f['domain']}/{f['path']}"

def _norm(p):
    p = '/' + p.strip('/')
    return p[8:] if p.startswith('/private/') else p

def check_jailbreak(backup, data):
    hits = {}
    bundles = data['bundle_ids']
    apps = backup.apps()
    for bid, meta in bundles.items():
        seen = [f'Installed app list or app container: {bid}'] if bid in apps else []
        seen += [device_path(f) for f in backup.files
                 if f['domain'].endswith('-' + bid) or f['domain'].endswith('.' + bid)
                 or f['path'].rsplit('/', 1)[-1] in (bid + '.plist',) or f['path'].rstrip('/').endswith('/' + bid)]
        if seen: hits.setdefault(meta['name'], {'kind': meta['kind'], 'evidence': []})['evidence'] += seen
    patterns = [(_norm(x['path']), x['tool']) for x in data['paths']]
    for f in backup.files:
        p = _norm(device_path(f))
        for pat, name in patterns:
            if p == pat or p.startswith(pat + '/'):
                hits.setdefault(name, {'kind': 'path', 'evidence': []})['evidence'].append(device_path(f))
    out = []
    multi = len(hits) >= 2  # distinct tools, so one app plus its own leftovers counts once
    for name, h in sorted(hits.items()):
        ev = sorted(set(h['evidence']))[:20]
        if h['kind'] == 'permanent_sideloader':
            score, why = 60, f'{name} found. It installs apps permanently outside the App Store, with extra powers.'
        else:
            score, why = 70, f'Jailbreak artifact found: {name}. Classic iPhone stalkerware needs a jailbroken phone.'
        reasons = [why, 'If you did not jailbreak this phone yourself, treat this as serious.']
        if multi: score += 25; reasons.append(f'{len(hits)} separate jailbreak or sideloading traces found in this backup')
        out.append(finding('jailbreak', name, score, reasons, ev))
    return out, {'status': 'ran', 'bundle_ids_checked': len(bundles), 'paths_checked': len(patterns), 'manifest_entries': len(backup.files)}

# ---------- check 2: configuration profiles and MDM ----------

def _payloads(stub):
    content = stub.get('PayloadContent')
    if isinstance(content, (bytes, bytearray)):
        try: content = plistlib.loads(bytes(content)).get('PayloadContent')
        except Exception: content = None
    return [p for p in content if isinstance(p, dict)] if isinstance(content, list) else []

def check_profiles(backup):
    files = [f for f in backup.files if 'ConfigurationProfiles/' in f['path'] or f['domain'] == PROFILES_DOMAIN]
    out = []
    for f in files:
        name = f['path'].rsplit('/', 1)[-1]
        blob = backup.blob(f['file_id'])
        plist = load_plist(blob) if blob else None
        if name.startswith('profile-') and name.endswith('.stub') and isinstance(plist, dict):
            display = plist.get('PayloadDisplayName') or plist.get('ProfileDisplayName') or 'Unnamed profile'
            ident = plist.get('PayloadIdentifier') or plist.get('ProfileIdentifier') or name
            org = plist.get('PayloadOrganization') or plist.get('ProfileOrganization') or 'unknown'
            types = sorted({p.get('PayloadType', '') for p in _payloads(plist)} - {''})
            risky = [HIGH_RISK_PAYLOADS[t] for t in types if t in HIGH_RISK_PAYLOADS]
            installed = plist.get('InstallDate') or (plist.get('InstallOptions') or {}).get('InstallDate')
            reasons = [f'Configuration profile installed: "{display}" from {org}']
            score = 35
            if risky:
                score = 65; reasons.append('Profile can manage the phone or see traffic: ' + '; '.join(risky))
            reasons.append('Check Settings > General > VPN & Device Management. Work, school, or carrier profiles are common and legitimate.')
            ev = [device_path(f), f'identifier={ident}', 'payloads=' + (', '.join(types) or 'unknown')]
            if installed: ev.append(f'installed={installed.isoformat() if hasattr(installed, "isoformat") else installed}')
            out.append(finding('configuration_profile', str(ident), score, reasons, ev))
        elif name == 'MDM.plist':
            info = plist if isinstance(plist, dict) else {}
            server = info.get('ServerURL') or info.get('CheckInURL') or 'unknown server'
            out.append(finding('mdm', 'MDM enrollment', 70, [
                f'Phone is enrolled in Mobile Device Management ({server})',
                'MDM can install apps and profiles, restrict settings, and locate a supervised phone. It is normal on work or school phones, not on a personal phone you set up yourself.'],
                [device_path(f)]))
        elif name == 'CloudConfigurationDetails.plist' and isinstance(plist, dict):
            if plist.get('IsSupervised') or plist.get('ConfigurationURL') or plist.get('OrganizationName'):
                org = plist.get('OrganizationName') or 'unknown organization'
                reasons = [f'Automated device enrollment or supervision record found (organization: {org})']
                if plist.get('IsSupervised'): reasons.append('The phone is supervised, which gives the managing organization extra control')
                out.append(finding('mdm', 'Supervision / automated enrollment', 60 if plist.get('IsSupervised') else 40, reasons, [device_path(f)]))
    return out, {'status': 'ran' if files else 'no profile data in backup', 'files_checked': len(files)}

# ---------- check 3: network IOC sweep ----------

class NetworkIOCs:
    def __init__(self, data):
        self.domains = {k.lower(): v for k, v in data.get('domains', {}).items()}
        self.ipv4 = data.get('ipv4', {})
        self.urls = {k.lower(): v for k, v in data.get('urls', {}).items()}

    def match_host(self, host):
        host = (host or '').lower().strip('.').split(':')[0]
        if not host: return None
        if host in self.ipv4: return host, self.ipv4[host]
        labels = host.split('.')
        for i in range(len(labels) - 1):
            cand = '.'.join(labels[i:])
            if cand in self.domains: return cand, self.domains[cand]
        return None

    def match_url(self, url):
        raw = url.strip().rstrip('.,;:!?)]}\'"')
        bare = raw.split('://', 1)[-1].lower()
        for u, fam in self.urls.items():
            if bare == u or bare.startswith(u + '/') or bare.startswith(u + '?'): return u, fam
        try: host = urlsplit(raw if '://' in raw else 'http://' + raw).hostname
        except ValueError: host = None
        return self.match_host(host)

    def scan_text(self, text):
        hits, seen = [], set()
        for u in URL_RE.findall(text or ''):
            m = self.match_url(u)
            if m and m[0] not in seen: seen.add(m[0]); hits.append((m[0], m[1], u.rstrip('.,;:!?)]}\'"')))
        for h in HOST_RE.findall(text or ''):
            m = self.match_host(h)
            if m and m[0] not in seen: seen.add(m[0]); hits.append((m[0], m[1], h))
        for ip in IPV4_RE.findall(text or ''):
            try: ipaddress.IPv4Address(ip)
            except ValueError: continue
            m = self.match_host(ip)
            if m and m[0] not in seen: seen.add(m[0]); hits.append((m[0], m[1], ip))
        return hits

def _safari(backup, iocs, record):
    dbs = [f for f in backup.files if f['path'].endswith('Safari/History.db')]
    rows = 0
    for f in dbs:
        blob = backup.blob(f['file_id'])
        if not blob: continue
        try:
            con = ro_connect(blob)
            q = ('SELECT i.url, MIN(v.visit_time), MAX(v.visit_time), COUNT(v.id) FROM history_items i '
                 'LEFT JOIN history_visits v ON v.history_item = i.id GROUP BY i.id')
            for url, first, last, count in con.execute(q):
                rows += 1
                m = iocs.match_url(url or '')
                if m: record(m, 'Safari history', {'url': url, 'first_visit': apple_time(first), 'last_visit': apple_time(last), 'visits': count})
            con.close()
        except sqlite3.DatabaseError: continue
    return len(dbs), rows

def _sms(backup, iocs, record):
    dbs = backup.find(domain='HomeDomain', path='Library/SMS/sms.db')
    rows = 0
    for f in dbs:
        blob = backup.blob(f['file_id'])
        if not blob: continue
        try:
            con = ro_connect(blob)
            cols = {r[1] for r in con.execute('PRAGMA table_info(message)')}
            svc = 'service' if 'service' in cols else "''"
            for rowid, text, date, from_me, service in con.execute(f'SELECT ROWID, text, date, is_from_me, {svc} FROM message WHERE text IS NOT NULL'):
                rows += 1
                for ind, fam, seen in iocs.scan_text(text):
                    record((ind, fam), 'Messages (SMS/iMessage)', {'link': seen, 'date': apple_time(date),
                           'direction': 'sent' if from_me else 'received', 'service': service or 'unknown', 'message_rowid': rowid})
            con.close()
        except sqlite3.DatabaseError: continue
    return len(dbs), rows

def check_network(backup, data):
    iocs = NetworkIOCs(data)
    grouped = {}
    def record(match, source, ev):
        ind, fam = match
        g = grouped.setdefault(ind, {'families': set(fam), 'sources': set(), 'evidence': []})
        g['sources'].add(source); g['evidence'].append(dict(ev, source=source))
    s_db, s_rows = _safari(backup, iocs, record)
    m_db, m_rows = _sms(backup, iocs, record)
    out = []
    for ind, g in sorted(grouped.items()):
        fam = ', '.join(sorted(g['families']))
        reasons = [f'Known stalkerware network indicator ({fam}) found in {" and ".join(sorted(g["sources"]))}: {ind}',
                   'This can mean an install or login page for the tool was opened or sent to this phone. It can also mean someone researched it. Check the dates.']
        out.append(finding('network_ioc', ind, 100, reasons, g['evidence'][:25], g['families']))
    status = 'ran' if (s_db or m_db) else 'no Safari history or messages database in backup'
    return out, {'status': status, 'safari_databases': s_db, 'safari_urls_checked': s_rows,
                 'message_databases': m_db, 'messages_checked': m_rows,
                 'indicators': {k: len(v) for k, v in (('domains', iocs.domains), ('ipv4', iocs.ipv4), ('urls', iocs.urls))}}

# ---------- report ----------

def load_iocs():
    jb = json.loads((ROOT / 'iocs/ios_jailbreak.json').read_text(encoding='utf-8'))
    net = json.loads((ROOT / 'iocs/network.json').read_text(encoding='utf-8'))
    return jb, net

def scan(backup, jb, net):
    findings, checks = [], {}
    for name, fn in (('jailbreak', lambda: check_jailbreak(backup, jb)), ('configuration_profiles', lambda: check_profiles(backup)),
                     ('network_iocs', lambda: check_network(backup, net))):
        f, meta = fn(); findings += f; checks[name] = meta
    return {'generated_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'platform': 'ios', 'device': backup.device(),
            'package_count': len(backup.apps()),
            'backup': {'path': str(backup.path), 'encrypted': False, 'last_backup': str(backup.info.get('Last Backup Date', 'unknown')),
                       'manifest_entries': len(backup.files),
                       'note': 'Only data stored in this backup was examined. Nothing on the phone or in the backup was changed.'},
            'ioc_snapshots': {'jailbreak_paths_version': jb.get('version'), 'network_source': net.get('source'),
                              'network_source_ref': net.get('source_ref'), 'network_retrieved': net.get('retrieved')},
            'checks': checks, 'safety_warning': SAFETY, 'clean_scan_caveat': CAVEAT,
            'account_hygiene': ACCOUNT_HYGIENE, 'limitations': LIMITATIONS,
            'findings': sorted(findings, key=lambda x: (-x['score'], x['check'], x['indicator']))}

def _ev(e):
    if isinstance(e, dict): return ', '.join(f'{k}={v}' for k, v in e.items() if v not in (None, ''))
    return str(e)

def plain(report):
    serious = [x for x in report['findings'] if x['score'] >= 30]
    d = report['device']
    lines = ['IOS STALKERWARE TRIAGE REPORT', '=' * 31, f"Generated: {report['generated_at']}",
             f"Device: {d['model']} (iOS {d['ios']})", f"Backup: {report['backup']['path']} (last backup {report['backup']['last_backup']})",
             f"Apps listed in backup: {report['package_count']}", '', report['safety_warning'], '', f'Priority findings: {len(serious)}', '']
    if not serious: lines += ['No medium/high-confidence findings were produced. This DOES NOT prove the phone is clean. New, renamed, or well-hidden tools can be missed.', '']
    for f in serious:
        lines += [f"[{f['severity']}] {f['indicator']} ({f['check']}) - score {f['score']}"] + [f'  - {r}' for r in f['reasons']]
        lines += [f'    evidence: {_ev(e)}' for e in f['evidence'][:10]] + ['']
    lines += ['OTHER LOW-CONFIDENCE SIGNALS', '']
    low = [f for f in report['findings'] if f['score'] < 30]
    lines += [f"[LOW] {f['indicator']} ({f['check']}) - score {f['score']}: " + '; '.join(f['reasons']) for f in low] or ['(none)']
    lines += ['', 'Checks run:']
    for name, meta in report['checks'].items():
        lines.append(f"  {name}: {meta['status']} (" + ', '.join(f'{k}={v}' for k, v in meta.items() if k != 'status') + ')')
    lines += ['', 'ACCOUNT HYGIENE - do these whatever this scan says, and only when it is safe:'] + [f'  {i}. {s}' for i, s in enumerate(report['account_hygiene'], 1)]
    lines += ['', 'CLEAN SCAN DOES NOT MEAN CLEAN', '  ' + report['clean_scan_caveat'], '', 'Limits of this scan:'] + [f'  - {s}' for s in report['limitations']]
    lines += ['', 'Next steps: preserve this report and a copy of the backup folder somewhere the suspected monitor cannot access; photograph Settings > General > VPN & Device Management with a safer device; record date/time and who handled the phone; seek specialist help before removing anything. For deeper analysis, a qualified examiner can run Amnesty\'s Mobile Verification Toolkit (MVT) on the same backup.']
    return '\n'.join(lines) + '\n'

def main():
    ap = argparse.ArgumentParser(description='Read-only iPhone stalkerware triage over an unencrypted iTunes/Finder backup')
    ap.add_argument('--backup', required=True, help='Path to one backup folder (the one containing Manifest.db), or its parent if it holds a single backup')
    ap.add_argument('--output', default='report_ios.txt'); ap.add_argument('--json-output', default='report_ios.json')
    a = ap.parse_args()
    try: backup = Backup(a.backup)
    except BackupError as e: raise SystemExit(str(e))
    jb, net = load_iocs()
    report = scan(backup, jb, net)
    Path(a.output).write_text(plain(report), encoding='utf-8'); Path(a.json_output).write_text(json.dumps(report, indent=2, default=str) + '\n', encoding='utf-8')
    print(f'Wrote {a.output} and {a.json_output}')
if __name__ == '__main__': main()
