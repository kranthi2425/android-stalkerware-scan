#!/usr/bin/env python3
"""Defensive, read-only iPhone stalkerware triage over an iTunes/Finder backup or a full filesystem dump.

Pure Python standard library for unencrypted backups and filesystem dumps. Encrypted backups need one
optional AES package (cryptography or pycryptodome); see ios_crypto.py. Nothing on the phone, in the
backup, or in the dump is modified.
"""
from __future__ import annotations
import argparse, datetime as dt, getpass, ipaddress, json, os, plistlib, re, shutil, sqlite3, struct, sys, tempfile
from pathlib import Path
from urllib.parse import urlsplit

from scanner import severity
import ios_crypto

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
    'Encrypted backups need the backup password and one optional package (cryptography or pycryptodome). The few files the scan reads are decrypted into a private temporary folder that is deleted when the scan ends.',
    'App matches are dual-use: family, parental, couple, and anti-theft apps are usually installed knowingly and for good reasons. The curated list covers known App Store apps only; renamed, new, or enterprise-signed apps can be missed.',
    'Standard backups normally do not contain provisioning profiles or app bundles, so enterprise and sideloading traces are mostly visible only with --fs-dump.',
    'Getting a full filesystem dump usually means jailbreaking the phone first. With --fs-dump, jailbreak traces may come from the acquisition itself; ask whoever made the dump which tool they used.',
    'A standard backup does not contain the system partition, so most jailbreak files are only visible as app data, preferences, or leftovers.',
    'Network indicators are matched only against Safari history and message text stored in the backup, not live traffic or other apps.',
    'Apple notes that unencrypted backups can leave out website history, call history, saved passwords, Wi-Fi settings, and Health data (https://support.apple.com/en-us/108353); encrypted backups include them. If "network_iocs" shows safari_databases=0, browsing history was not checked.',
    'Public indicator lists age quickly. See iocs/ for the pinned snapshot dates.',
]

MVT_DOCS = ['https://docs.mvt.re/en/latest/ios/backup/check/', 'https://docs.mvt.re/en/latest/ios/filesystem/check/', 'https://docs.mvt.re/en/latest/iocs/']
SQLITE_MAGIC = b'SQLite format 3\x00'

class BackupError(Exception): pass

def is_sqlite(path):
    try:
        with open(path, 'rb') as fh: return fh.read(16) == SQLITE_MAGIC
    except OSError: return False

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
    kind = 'backup'

    def __init__(self, path, password=None, password_prompt=None):
        p = Path(path).expanduser()
        if not (p / 'Manifest.db').exists():
            subs = [d for d in p.iterdir() if d.is_dir() and (d / 'Manifest.db').exists()] if p.is_dir() else []
            if len(subs) == 1: p = subs[0]
            elif len(subs) > 1: raise BackupError('Several backups found here. Pass one backup folder: ' + ', '.join(sorted(d.name for d in subs)))
            else: raise BackupError(f'No Manifest.db in {p}. Point --backup at one iPhone backup folder.')
        self.path = p
        self.info = load_plist(p / 'Info.plist') or {}
        self.manifest = load_plist(p / 'Manifest.plist') or {}
        self.encrypted = bool(self.manifest.get('IsEncrypted'))
        self.decryption = 'not encrypted'
        self._tmp = self._aes = self._keybag = None; self._records = {}; self._plain = {}
        db = p / 'Manifest.db'
        if self.encrypted and is_sqlite(db):
            self.decryption = 'already decrypted (Manifest.db is readable; for example a decrypted copy made with another tool)'
        elif self.encrypted:
            db = self._unlock(password if password is not None else (password_prompt() if password_prompt else None))
        try:
            con = ro_connect(db)
            rows = con.execute('SELECT fileID, domain, relativePath, flags' + (', file' if self._keybag else '') + ' FROM Files').fetchall()
            con.close()
        except sqlite3.DatabaseError as e:
            self.close()
            raise BackupError(f'Manifest.db could not be read ({e}). The backup may be encrypted, incomplete, or damaged.')
        self.files = [{'file_id': r[0], 'domain': r[1] or '', 'path': r[2] or '', 'flags': r[3]} for r in rows]
        if self._keybag: self._records = {r[0]: r[4] for r in rows if r[4]}

    def _unlock(self, password):
        try: self._aes = ios_crypto.AES()
        except ios_crypto.CryptoUnavailable as e: raise BackupError('This backup is encrypted. ' + str(e))
        if not password: raise BackupError('This backup is encrypted. Run again and enter the backup password when asked (or set IOS_BACKUP_PASSWORD).')
        try:
            self._keybag = ios_crypto.Keybag(self.manifest['BackupKeyBag'])
            self._keybag.unlock(self._aes, password)
            mk = self.manifest['ManifestKey']
            key = self._keybag.unwrap(self._aes, struct.unpack('<l', mk[:4])[0], mk[4:])
        except ios_crypto.WrongPassword: raise BackupError('Wrong backup password. It is the password set for encrypted backups in Finder/iTunes, not the phone passcode.')
        except (KeyError, ValueError, TypeError) as e: raise BackupError(f'Encrypted backup keys could not be read ({e}). The backup may be damaged or from an unsupported iOS version.')
        self._tmp = Path(tempfile.mkdtemp(prefix='ios-scan-'))
        out = self._tmp / 'Manifest.db'
        ios_crypto.decrypt_stream(self._aes, key, self.path / 'Manifest.db', out)
        if not is_sqlite(out):
            self.close(); raise BackupError('Manifest.db did not decrypt to a database. The backup may be damaged or use an unsupported format.')
        self.decryption = f'decrypted by this tool ({self._aes.name}); temporary copies deleted after the scan'
        return out

    def close(self):
        if self._tmp: shutil.rmtree(self._tmp, ignore_errors=True); self._tmp = None

    def __enter__(self): return self
    def __exit__(self, *a): self.close()

    def _raw(self, file_id):
        f = self.path / file_id[:2] / file_id
        return f if f.exists() else (self.path / file_id if (self.path / file_id).exists() else None)

    def blob(self, file_id):
        raw = self._raw(file_id)
        if not self._keybag or not raw: return raw
        if file_id in self._plain: return self._plain[file_id]
        rec = self._records.get(file_id); out = None
        try:
            cls, wrapped, size = ios_crypto.file_record(rec) if rec else (None, None, 0)
            if wrapped:
                out = self._tmp / file_id
                ios_crypto.decrypt_stream(self._aes, self._keybag.unwrap(self._aes, cls, wrapped), raw, out, size)
        except Exception: out = None  # unreadable entry: treated like a missing file
        self._plain[file_id] = out
        return out

    def path_hits(self, patterns):
        for f in self.files:
            p = _norm(device_path(f))
            for pat, name in patterns:
                if p == pat or p.startswith(pat + '/'): yield device_path(f), name

    def app_details(self):
        """Per-app metadata from Manifest.plist and Info.plist, keyed by bundle ID."""
        out = {bid: {'bundle_id': bid, 'seen_in': []} for bid in self.apps()}
        for bid, meta in (self.manifest.get('Applications', {}) or {}).items():
            d = out.setdefault(bid, {'bundle_id': bid, 'seen_in': []}); d['seen_in'].append('Manifest.plist')
            if isinstance(meta, dict):
                if meta.get('CFBundleVersion'): d['version'] = str(meta['CFBundleVersion'])
                if isinstance(meta.get('Path'), str) and meta['Path'].endswith('.app'): d['name'] = meta['Path'].rsplit('/', 1)[-1][:-4]
        for bid in self.info.get('Installed Applications', []) or []:
            out.setdefault(bid, {'bundle_id': bid, 'seen_in': []})['seen_in'].append('Info.plist')
        for bid, meta in (self.info.get('Applications', {}) or {}).items():
            d = out.setdefault(bid, {'bundle_id': bid, 'seen_in': []})
            md = meta.get('iTunesMetadata') if isinstance(meta, dict) else None
            try: md = plistlib.loads(md) if isinstance(md, (bytes, bytearray)) else md
            except Exception: md = None
            if isinstance(md, dict):
                if md.get('itemName'): d['name'] = str(md['itemName'])
                if md.get('artistName'): d['developer'] = str(md['artistName'])
        for f in self.files:
            if f['domain'].startswith('AppDomain-'):
                d = out.get(f['domain'][10:])
                if d is not None and 'app data container' not in d['seen_in']: d['seen_in'].append('app data container')
        for d in out.values(): d['seen_in'] = sorted(set(d['seen_in']))
        return out

    def source_info(self):
        return {'type': 'backup', 'path': str(self.path), 'encrypted': self.encrypted, 'decryption': self.decryption,
                'last_backup': str(self.info.get('Last Backup Date', 'unknown')), 'manifest_entries': len(self.files),
                'note': 'Only data stored in this backup was examined. Nothing on the phone or in the backup was changed.'}

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

class FilesystemDump:
    """A full filesystem dump (extracted folder or mount point). Reads only a targeted set of paths."""
    kind = 'filesystem_dump'
    encrypted = False

    def __init__(self, path):
        p = Path(path).expanduser()
        if (p / 'private' / 'var').is_dir(): self.var, self.sysroot = p / 'private' / 'var', p
        elif (p / 'var' / 'mobile').is_dir(): self.var, self.sysroot = p / 'var', None  # dump of /private only
        else: raise BackupError(f'No private/var folder in {p}. Point --fs-dump at the root of an extracted iPhone filesystem dump.')
        self.path = p; self.info = {}; self.manifest = {}; self._apps = None
        self.files = []
        add = lambda real, domain, rel: self.files.append({'file_id': str(real), 'domain': domain, 'path': rel, 'flags': 1, 'device_path': self._dev(real)})
        mob = self.var / 'mobile'
        for rel in ('Library/SMS/sms.db', 'Library/Safari/History.db'):
            if (mob / rel).is_file(): add(mob / rel, 'HomeDomain', rel)
        for f in sorted(self.var.glob('mobile/Containers/Data/Application/*/Library/Safari/History.db')): add(f, '', 'Library/Safari/History.db')
        for d in sorted(self.var.glob('containers/Shared/SystemGroup/*/Library/ConfigurationProfiles')) + [mob / 'Library/ConfigurationProfiles']:
            if d.is_dir():
                for f in sorted(d.iterdir()):
                    if f.is_file(): add(f, PROFILES_DOMAIN, 'Library/ConfigurationProfiles/' + f.name)
        for f in sorted(self.var.glob('MobileDevice/ProvisioningProfiles/*.mobileprovision')): add(f, '', 'MobileDevice/ProvisioningProfiles/' + f.name)

    def _dev(self, real):
        real = Path(real)
        for base, prefix in ((self.var, '/private/var/'), (self.var.parent, '/private/'), (self.sysroot, '/')):
            if base is None: continue
            try: return prefix + real.relative_to(base).as_posix()
            except ValueError: continue
        return str(real)

    def blob(self, file_id):
        f = Path(file_id)
        return f if f.is_file() else None

    def find(self, domain=None, path=None, suffix=None):
        return [f for f in self.files if (domain is None or f['domain'] == domain)
                and (path is None or f['path'] == path) and (suffix is None or f['path'].endswith(suffix))]

    def path_hits(self, patterns):
        for pat, name in patterns:
            if pat.startswith('/var/'): cands = [self.var / pat[5:]]
            else: cands = [self.var.parent / pat.lstrip('/')] + ([self.sysroot / pat.lstrip('/')] if self.sysroot is not None else [])
            for real in cands:
                if real.exists() or real.is_symlink(): yield self._dev(real), name; break

    def app_details(self):
        if self._apps is not None: return self._apps
        out = {}
        bundles = sorted(self.var.glob('containers/Bundle/Application/*/*.app'))
        if self.sysroot is not None: bundles += sorted((self.sysroot / 'Applications').glob('*.app'))
        for app in bundles:
            info = load_plist(app / 'Info.plist')
            if not isinstance(info, dict) or not info.get('CFBundleIdentifier'): continue
            bid = str(info['CFBundleIdentifier'])
            d = out.setdefault(bid, {'bundle_id': bid, 'seen_in': []})
            d['name'] = str(info.get('CFBundleDisplayName') or info.get('CFBundleName') or app.name[:-4])
            if info.get('CFBundleShortVersionString') or info.get('CFBundleVersion'): d['version'] = str(info.get('CFBundleShortVersionString') or info.get('CFBundleVersion'))
            d['bundle_path'] = self._dev(app); d['seen_in'] = ['app bundle']
            d['app_store_metadata'] = (app.parent / 'iTunesMetadata.plist').is_file()
            if (app / 'embedded.mobileprovision').is_file(): d['embedded_profile'] = str(app / 'embedded.mobileprovision')
        self._apps = out
        return out

    def apps(self): return set(self.app_details())

    def device(self):
        v = load_plist(self.sysroot / 'System/Library/CoreServices/SystemVersion.plist') if self.sysroot is not None else None
        v = v if isinstance(v, dict) else {}
        return {'model': 'unknown', 'ios': str(v.get('ProductVersion', 'unknown')), 'name': 'unknown', 'serial': 'unknown'}

    def source_info(self):
        return {'type': 'filesystem_dump', 'path': str(self.path), 'encrypted': False, 'decryption': 'not applicable',
                'last_backup': 'n/a (filesystem dump)', 'manifest_entries': len(self.files),
                'note': 'Only a targeted set of paths in this filesystem dump was read. Nothing in the dump was changed.'}

    def close(self): pass
    def __enter__(self): return self
    def __exit__(self, *a): pass

def finding(check, indicator, score, reasons, evidence=None, families=None):
    return {'check': check, 'indicator': indicator, 'score': score, 'severity': severity(score),
            'reasons': reasons, 'families': sorted(families or []), 'evidence': evidence or []}

# ---------- check 1: jailbreak artifacts ----------

def device_path(f):
    if f.get('device_path'): return f['device_path']
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
    for dev, name in backup.path_hits(patterns):
        hits.setdefault(name, {'kind': 'path', 'evidence': []})['evidence'].append(dev)
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

# ---------- check 4: installed apps and dual-use app matcher ----------

def check_apps(backup, data):
    apps = backup.app_details()
    cats, roles, curated = data['categories'], data['roles'], data['apps']
    out = []
    for bid in sorted(apps):
        meta = curated.get(bid)
        if not meta: continue
        score = 40
        reasons = [f"Dual-use app installed: {meta['name']} by {meta['developer']} ({meta['category'].replace('_', ' ')}). {cats[meta['category']]}",
                   f"Role: {roles[meta['role']]}"]
        if meta['role'] == 'monitoring_device':
            score = 30; reasons.append('This is usually the watching side, so on this phone it more often means this phone watches someone else. Check which account is signed in.')
        if meta['category'] == 'monitoring_marketed':
            score = 50; reasons.append('The developer markets it for monitoring another person.')
        if meta.get('echap_family'):
            score = 50; reasons.append(f"The same brand or its servers appear in the Echap stalkerware indicators (family: {meta['echap_family']}).")
        reasons.append('Not a verdict. Many people install this knowingly. Ask: did I install it, and do I know who can see what it collects?')
        a = apps[bid]
        ev = [{'bundle_id': bid, 'name_on_phone': a.get('name'), 'seen_in': ', '.join(a.get('seen_in', [])), 'app_store_record': meta['source']}]
        out.append(finding('dual_use_app', bid, score, reasons, ev, [meta['category']]))
    return out, {'status': 'ran' if apps else 'no app list in backup', 'apps_listed': len(apps),
                 'curated_apps_checked': len(curated), 'list_version': data.get('version')}

# ---------- check 5: enterprise / provisioning profile traces ----------

def parse_provision(raw):
    """Read the plist inside a CMS-signed .mobileprovision without verifying the signature."""
    i, j = raw.find(b'<?xml'), raw.rfind(b'</plist>')
    if i < 0 or j < 0: return None
    try: pl = plistlib.loads(raw[i:j + 8])
    except Exception: return None
    return pl if isinstance(pl, dict) else None

def provision_type(pl):
    ent = pl.get('Entitlements') or {}
    if pl.get('ProvisionsAllDevices'): return 'enterprise'
    if pl.get('ProvisionedDevices'): return 'development' if ent.get('get-task-allow') else 'ad_hoc'
    return 'app_store'

PROVISION_TEXT = {
    'enterprise': (45, 'In-house (enterprise) signing profile: lets apps install outside the App Store on any iPhone. Apple limits this to a company\'s own staff apps. Malware has been spread to iPhones this way (for example WireLurker and YiSpecter).'),
    'ad_hoc': (35, 'Ad hoc signing profile: lets an app outside the App Store run on a short list of specific iPhones, including this one.'),
    'development': (30, 'Developer signing profile: lets a test app run on specific iPhones. Normal if the owner builds apps; unusual otherwise.'),
}

def check_provisioning(backup):
    sources = [(device_path(f), backup.blob(f['file_id'])) for f in backup.files if f['path'].endswith('.mobileprovision')]
    apps = backup.app_details()
    for bid, a in sorted(apps.items()):
        if a.get('embedded_profile'): sources.append((a['bundle_path'] + '/embedded.mobileprovision', Path(a['embedded_profile'])))
    out, parsed = [], 0
    for where, blob in sources:
        if not blob: continue
        try: pl = parse_provision(Path(blob).read_bytes())
        except OSError: pl = None
        if not pl: continue
        parsed += 1
        kind = provision_type(pl)
        if kind == 'app_store': continue
        score, why = PROVISION_TEXT[kind]
        appid = str((pl.get('Entitlements') or {}).get('application-identifier', ''))
        team = pl.get('TeamName') or 'unknown team'
        reasons = [f'{why} Team: {team}.']
        target = appid.split('.', 1)[1] if '.' in appid else ''
        linked = sorted(b for b in apps if target and (b == target or (target.endswith('*') and b.startswith(target[:-1]))))
        if linked: reasons.append('Signs installed app(s): ' + ', '.join(linked))
        ev = [{'file': where, 'profile_name': pl.get('Name'), 'team': team, 'team_id': ','.join(pl.get('TeamIdentifier') or []),
               'app_id': appid, 'devices': 'all' if kind == 'enterprise' else len(pl.get('ProvisionedDevices') or []),
               'created': pl.get('CreationDate'), 'expires': pl.get('ExpirationDate')}]
        f = finding('provisioning_profile', str(pl.get('UUID') or pl.get('Name') or where), score, reasons, ev)
        f['profile_type'] = kind
        out.append(f)
    status = 'ran' if sources else ('no provisioning profiles in backup (standard backups usually leave them out; --fs-dump sees more)' if backup.kind == 'backup' else 'no provisioning profiles found')
    return out, {'status': status, 'profiles_found': len(sources), 'profiles_parsed': parsed}

def corroborate_provisioning(findings):
    """Enterprise/sideload traces become HIGH when other checks also found something."""
    others = sorted({f['check'] for f in findings if f['check'] != 'provisioning_profile' and f['score'] >= 30})
    if not others: return
    for f in findings:
        if f['check'] == 'provisioning_profile':
            f['score'] = max(f['score'], 65 if f.get('profile_type') == 'enterprise' else 60); f['severity'] = severity(f['score'])
            f['reasons'].append('Seen together with other findings in this scan (' + ', '.join(others) + '), which makes it more serious.')

# ---------- MVT escalation ----------

def mvt_handoff(backup, findings):
    top = max((f['score'] for f in findings), default=0)
    q = lambda x: '"' + str(x) + '"'
    steps = ['Install MVT (free, from Amnesty International): https://docs.mvt.re/', 'mvt-ios download-iocs']
    if backup.kind == 'filesystem_dump':
        steps.append(f'mvt-ios check-fs {q(backup.path)} --output /path/to/mvt-output/')
    elif backup.encrypted and 'already decrypted' not in backup.decryption:
        steps += [f'mvt-ios decrypt-backup -d /path/to/decrypted {q(backup.path)}   (MVT asks for the backup password if you leave out -p)',
                  'mvt-ios check-backup --output /path/to/mvt-output/ /path/to/decrypted']
    else:
        steps.append(f'mvt-ios check-backup --output /path/to/mvt-output/ {q(backup.path)}')
    steps.append('Review files ending in "_detected" in the output folder. Keep this report with the MVT output.')
    why = ('Recommended now: this scan found a HIGH or CRITICAL signal.' if top >= 60 else
           'Optional: nothing HIGH or CRITICAL was found, but MVT checks far more records and newer indicators if worry remains.')
    return {'recommended': top >= 60, 'why': why,
            'what_mvt_adds': 'MVT (Mobile Verification Toolkit) is Amnesty Tech\'s forensic tool. It extracts dozens of record types and matches them against public spyware and stalkerware indicators. It is best run by, or with, a trained examiner.',
            'steps': steps, 'docs': MVT_DOCS}

# ---------- report ----------

def load_iocs():
    jb = json.loads((ROOT / 'iocs/ios_jailbreak.json').read_text(encoding='utf-8'))
    net = json.loads((ROOT / 'iocs/network.json').read_text(encoding='utf-8'))
    return jb, net

def load_app_list():
    return json.loads((ROOT / 'iocs/ios_dual_use_apps.json').read_text(encoding='utf-8'))

def scan(backup, jb, net, dual=None):
    dual = dual if dual is not None else load_app_list()
    findings, checks = [], {}
    for name, fn in (('jailbreak', lambda: check_jailbreak(backup, jb)), ('configuration_profiles', lambda: check_profiles(backup)),
                     ('network_iocs', lambda: check_network(backup, net)), ('dual_use_apps', lambda: check_apps(backup, dual)),
                     ('provisioning_profiles', lambda: check_provisioning(backup))):
        f, meta = fn(); findings += f; checks[name] = meta
    corroborate_provisioning(findings)
    apps = backup.app_details()
    inventory = [dict(v, dual_use=bid in dual['apps']) for bid, v in sorted(apps.items())]
    for a in inventory: a.pop('embedded_profile', None)
    return {'generated_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'platform': 'ios', 'device': backup.device(),
            'package_count': len(apps), 'source_type': backup.kind, 'backup': backup.source_info(),
            'ioc_snapshots': {'jailbreak_paths_version': jb.get('version'), 'network_source': net.get('source'),
                              'network_source_ref': net.get('source_ref'), 'network_retrieved': net.get('retrieved'),
                              'dual_use_apps_version': dual.get('version')},
            'checks': checks, 'safety_warning': SAFETY, 'clean_scan_caveat': CAVEAT,
            'account_hygiene': ACCOUNT_HYGIENE, 'limitations': LIMITATIONS,
            'findings': sorted(findings, key=lambda x: (-x['score'], x['check'], x['indicator'])),
            'mvt_handoff': mvt_handoff(backup, findings), 'app_inventory': inventory}

def _ev(e):
    if isinstance(e, dict): return ', '.join(f'{k}={v}' for k, v in e.items() if v not in (None, ''))
    return str(e)

def plain(report):
    serious = [x for x in report['findings'] if x['score'] >= 30]
    d = report['device']
    lines = ['IOS STALKERWARE TRIAGE REPORT', '=' * 31, f"Generated: {report['generated_at']}",
             f"Device: {d['model']} (iOS {d['ios']})",
             (f"Backup: {report['backup']['path']} (last backup {report['backup']['last_backup']}; encryption: {report['backup']['decryption']})"
              if report['backup']['type'] == 'backup' else f"Filesystem dump: {report['backup']['path']}"),
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
    lines += ['', 'Next steps: preserve this report and a copy of the backup folder somewhere the suspected monitor cannot access; photograph Settings > General > VPN & Device Management with a safer device; record date/time and who handled the phone; seek specialist help before removing anything.']
    m = report['mvt_handoff']
    lines += ['', 'ESCALATE TO MVT FOR DEEP ANALYSIS', '  ' + m['why'], '  ' + m['what_mvt_adds']] + [f'  {i}. {s}' for i, s in enumerate(m['steps'], 1)]
    lines += ['  Docs: ' + ', '.join(m['docs'])]
    inv = report['app_inventory']
    lines += ['', f'APP INVENTORY ({len(inv)} apps; * = on the dual-use list, see findings above)']
    lines += [f"  {'*' if a['dual_use'] else ' '} {a['bundle_id']}" + (f" - {a['name']}" if a.get('name') else '') for a in inv] or ['  (no app list in this source)']
    return '\n'.join(lines) + '\n'

def ask_password(env):
    if os.environ.get(env): return os.environ[env]
    return getpass.getpass('This backup is encrypted. Backup password (typing is hidden): ')

def main():
    ap = argparse.ArgumentParser(description='Read-only iPhone stalkerware triage over an iTunes/Finder backup or a full filesystem dump')
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--backup', help='Path to one backup folder (the one containing Manifest.db), or its parent if it holds a single backup')
    src.add_argument('--fs-dump', help='Path to the root of an extracted full filesystem dump (the folder containing private/var)')
    ap.add_argument('--password-env', default='IOS_BACKUP_PASSWORD', help='Environment variable holding the backup password (default: IOS_BACKUP_PASSWORD). If unset, you are asked for it.')
    ap.add_argument('--output', default='report_ios.txt'); ap.add_argument('--json-output', default='report_ios.json')
    a = ap.parse_args()
    try: source = FilesystemDump(a.fs_dump) if a.fs_dump else Backup(a.backup, password_prompt=lambda: ask_password(a.password_env))
    except BackupError as e: raise SystemExit(str(e))
    with source:
        jb, net = load_iocs()
        report = scan(source, jb, net)
    Path(a.output).write_text(plain(report), encoding='utf-8'); Path(a.json_output).write_text(json.dumps(report, indent=2, default=str) + '\n', encoding='utf-8')
    print(f'Wrote {a.output} and {a.json_output}')
if __name__ == '__main__': main()
