import datetime as dt,hashlib,json,plistlib,sqlite3,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
import ios_scanner as ios

def make_backup(base,files=None,apps=(),encrypted=False):
    """Write a minimal unencrypted iTunes/Finder backup. files: {(domain,relativePath): bytes or None}."""
    base=Path(base); base.mkdir(parents=True,exist_ok=True)
    (base/'Info.plist').write_bytes(plistlib.dumps({'Product Type':'iPhone14,5','Product Version':'17.5','Device Name':'Test iPhone','Serial Number':'TESTSERIAL','Last Backup Date':dt.datetime(2026,9,1)}))
    (base/'Manifest.plist').write_bytes(plistlib.dumps({'IsEncrypted':encrypted,'Applications':{a:{} for a in apps},'Lockdown':{'ProductVersion':'17.5'}}))
    con=sqlite3.connect(base/'Manifest.db'); con.execute('CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)')
    for (domain,rel),content in (files or {}).items():
        fid=hashlib.sha1(f'{domain}-{rel}'.encode()).hexdigest()
        con.execute('INSERT INTO Files VALUES (?,?,?,?,?)',(fid,domain,rel,1 if content is not None else 2,b''))
        if content is not None: (base/fid[:2]).mkdir(exist_ok=True); (base/fid[:2]/fid).write_bytes(content)
    con.commit(); con.close(); return base

def sqlite_bytes(schema,rows):
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'db.sqlite'; con=sqlite3.connect(p); con.executescript(schema)
        for sql,args in rows: con.execute(sql,args)
        con.commit(); con.close(); return p.read_bytes()

def safari_db(urls):
    rows=[]
    for i,u in enumerate(urls,1):
        rows += [('INSERT INTO history_items (id,url) VALUES (?,?)',(i,u)),('INSERT INTO history_visits (history_item,visit_time) VALUES (?,?)',(i,780000000.0+i))]
    return sqlite_bytes('CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT); CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL);',rows)

def sms_db(texts):
    return sqlite_bytes('CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT, date INTEGER, is_from_me INTEGER, service TEXT);',
                        [('INSERT INTO message (text,date,is_from_me,service) VALUES (?,?,?,?)',(t,780000000*10**9,0,'iMessage')) for t in texts])

def stub(display,types):
    return plistlib.dumps({'PayloadDisplayName':display,'PayloadIdentifier':'com.example.'+display.replace(' ','').lower(),'PayloadOrganization':'Example Org','PayloadContent':[{'PayloadType':t} for t in types]})

PROFILES=ios.PROFILES_DOMAIN

class IOSScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.jb,cls.net=ios.load_iocs()
    def setUp(self): self.tmp=tempfile.TemporaryDirectory(); self.dir=Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()
    def run_scan(self,**kw): return ios.scan(ios.Backup(make_backup(self.dir/'b',**kw)),self.jb,self.net)
    def by_check(self,report,check): return [f for f in report['findings'] if f['check']==check]

    def test_ioc_snapshots_are_pinned_and_attributed(self):
        self.assertGreater(len(self.net['domains']),500); self.assertIn('CC-BY',self.net['license'])
        self.assertTrue(self.net['source_ref']); self.assertTrue(self.jb['version']); self.assertTrue(self.jb['sources'])
        for p in self.jb['paths']: self.assertTrue(p['path'].startswith('/') and p['tool'])

    def test_every_network_domain_and_ip_matches(self):
        iocs=ios.NetworkIOCs(self.net)
        for d,fam in self.net['domains'].items():
            self.assertEqual(iocs.match_url(f'https://{d}/login?x=1'),(d,fam),d)
            self.assertEqual(iocs.match_host('cdn.'+d)[0],d)
        for ip in self.net['ipv4']: self.assertEqual(iocs.match_url(f'http://{ip}:8080/a')[0],ip)
        for u in self.net['urls']: self.assertEqual(iocs.match_url('https://'+u+'/releases')[0],u)

    def test_no_false_positive_on_shared_hosts(self):
        iocs=ios.NetworkIOCs(self.net)
        for u in ('https://github.com/','https://www.apple.com/','https://firebaseio.com/','https://appspot.com/x','https://example.com/copy9.com'):
            self.assertIsNone(iocs.match_url(u),u)

    def test_clean_backup_has_caveat_hygiene_and_no_findings(self):
        r=self.run_scan(files={('HomeDomain','Library/Safari/History.db'):safari_db(['https://www.wikipedia.org/']),('HomeDomain','Library/SMS/sms.db'):sms_db(['see you at 5'])},apps=['com.apple.Pages'])
        self.assertEqual(r['findings'],[]); self.assertEqual(r['checks']['network_iocs']['status'],'ran')
        text=ios.plain(r)
        self.assertIn('DOES NOT prove the phone is clean',text); self.assertIn('CLEAN SCAN DOES NOT MEAN CLEAN',text)
        self.assertIn('Settings > Privacy & Security > Safety Check',text)
        self.assertLess(text.index('SAFETY FIRST'),text.index('Priority findings'))

    def test_jailbreak_app_and_package_manager(self):
        r=self.run_scan(files={('AppDomain-com.opa334.Dopamine','Library/Preferences/com.opa334.Dopamine.plist'):b'x',('HomeDomain','Library/Preferences/org.coolstar.SileoStore.plist'):b'x'},apps=['com.opa334.Dopamine'])
        f={x['indicator']:x for x in self.by_check(r,'jailbreak')}
        self.assertEqual(set(f),{'Dopamine','Sileo'})
        self.assertTrue(all(x['severity']=='CRITICAL' for x in f.values()))

    def test_single_jailbreak_tool_is_high_and_leftovers_merge(self):
        r=self.run_scan(files={('HomeDomain','Library/Cydia/metadata.cb0'):b'x',('HomeDomain','Library/Preferences/com.saurik.Cydia.plist'):b'x'})
        f=self.by_check(r,'jailbreak')
        self.assertEqual([x['indicator'] for x in f],['Cydia']); self.assertEqual(f[0]['severity'],'HIGH')
        self.assertIn('/private/var/mobile/Library/Cydia/metadata.cb0',f[0]['evidence'])

    def test_mdm_and_risky_profile(self):
        r=self.run_scan(files={(PROFILES,'Library/ConfigurationProfiles/profile-abc.stub'):stub('Phone Helper',['com.apple.security.root','com.apple.vpn.managed']),
                               (PROFILES,'Library/ConfigurationProfiles/profile-def.stub'):stub('Wallpaper',['com.apple.wallpaper']),
                               (PROFILES,'Library/ConfigurationProfiles/MDM.plist'):plistlib.dumps({'ServerURL':'https://mdm.example.net/server'})})
        sev={x['indicator']:x['severity'] for x in r['findings']}
        self.assertEqual(sev['MDM enrollment'],'HIGH'); self.assertEqual(sev['com.example.phonehelper'],'HIGH'); self.assertEqual(sev['com.example.wallpaper'],'MEDIUM')
        self.assertIn('mdm.example.net',' '.join(self.by_check(r,'mdm')[0]['reasons']))

    def test_network_iocs_in_safari_and_messages(self):
        dom=sorted(self.net['domains'])[0]; dom2=sorted(self.net['domains'])[-1]
        r=self.run_scan(files={('HomeDomain','Library/Safari/History.db'):safari_db([f'https://login.{dom}/panel']),
                               ('HomeDomain','Library/SMS/sms.db'):sms_db([f'install this: {dom2}/get now'])})
        f={x['indicator']:x for x in self.by_check(r,'network_ioc')}
        self.assertEqual(set(f),{dom,dom2}); self.assertTrue(all(x['severity']=='CRITICAL' for x in f.values()))
        self.assertEqual(f[dom]['evidence'][0]['source'],'Safari history'); self.assertTrue(f[dom]['evidence'][0]['first_visit'].startswith('2025'))
        self.assertEqual(f[dom2]['evidence'][0]['direction'],'received')

    def test_encrypted_backup_is_refused(self):
        with self.assertRaises(ios.BackupError): ios.Backup(make_backup(self.dir/'enc',encrypted=True))

    def test_parent_folder_with_single_backup(self):
        make_backup(self.dir/'MobileSync'/'00008110-TEST')
        self.assertEqual(ios.Backup(self.dir/'MobileSync').path.name,'00008110-TEST')

    def test_report_structure_matches_android(self):
        r=self.run_scan()
        for k in ('generated_at','device','package_count','findings'): self.assertIn(k,r)
        for k in ('safety_warning','clean_scan_caveat','account_hygiene'): self.assertTrue(r[k])
        self.assertEqual(ios.severity(90),'CRITICAL'); self.assertEqual(ios.severity(60),'HIGH'); self.assertEqual(ios.severity(30),'MEDIUM'); self.assertEqual(ios.severity(1),'LOW')

    def test_cli_writes_reports_and_leaves_backup_unchanged(self):
        b=make_backup(self.dir/'cli',files={('HomeDomain','Library/SMS/sms.db'):sms_db(['hi'])})
        before={p:p.read_bytes() for p in b.rglob('*') if p.is_file()}
        out=self.dir/'r.txt'; js=self.dir/'r.json'
        subprocess.run([sys.executable,str(ROOT/'ios_scanner.py'),'--backup',str(b),'--output',str(out),'--json-output',str(js)],check=True,capture_output=True)
        self.assertTrue(out.read_text().startswith('IOS STALKERWARE TRIAGE REPORT')); self.assertEqual(json.loads(js.read_text())['platform'],'ios')
        self.assertEqual(before,{p:p.read_bytes() for p in b.rglob('*') if p.is_file()})
if __name__=='__main__': unittest.main()
