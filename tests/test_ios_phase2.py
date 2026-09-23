import datetime as dt,hashlib,importlib.util,json,os,plistlib,sqlite3,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(Path(__file__).resolve().parent))
import ios_scanner as ios, ios_crypto as crypto
from test_ios_scanner import make_backup,sms_db,stub,PROFILES

BACKENDS=[n for n,mod in (('cryptography','cryptography'),('pycryptodome','Crypto')) if importlib.util.find_spec(mod)]
needs_aes=unittest.skipUnless(BACKENDS,'optional AES package (cryptography or pycryptodome) not installed')
PW='correct horse'

def tlv(tag,val): val=struct.pack('>L',val) if isinstance(val,int) else val; return tag+struct.pack('>L',len(val))+val

def make_encrypted_backup(base,files=None,apps=(),password=PW,backend=None,iters=(10,10)):
    """Encrypted backup in the iOS 10.2+ layout: TLV keybag, wrapped class keys, encrypted Manifest.db and files."""
    aes=crypto.AES(backend); base=Path(base); base.mkdir(parents=True,exist_ok=True)
    dpsl,salt=os.urandom(20),os.urandom(20)
    pk=hashlib.pbkdf2_hmac('sha1',hashlib.pbkdf2_hmac('sha256',password.encode(),dpsl,iters[0],32),salt,iters[1],32)
    classkeys={c:os.urandom(32) for c in (1,2,3,4)}
    kb=tlv(b'VERS',4)+tlv(b'TYPE',1)+tlv(b'UUID',os.urandom(16))+tlv(b'HMCK',os.urandom(40))+tlv(b'WRAP',0)+tlv(b'SALT',salt)+tlv(b'ITER',iters[1])+tlv(b'DPWT',1)+tlv(b'DPIC',iters[0])+tlv(b'DPSL',dpsl)
    for c,k in classkeys.items(): kb+=tlv(b'UUID',os.urandom(16))+tlv(b'CLAS',c)+tlv(b'WRAP',3)+tlv(b'KTYP',0)+tlv(b'WPKY',crypto.aes_wrap(aes,pk,k))
    def enc(key,data): pad=16-len(data)%16; return aes.cbc_encryptor(key)(data+bytes([pad])*pad)
    with tempfile.TemporaryDirectory() as d:
        dbp=Path(d)/'m.db'; con=sqlite3.connect(dbp); con.execute('CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)')
        for (domain,rel),content in (files or {}).items():
            fid=hashlib.sha1(f'{domain}-{rel}'.encode()).hexdigest(); fk=os.urandom(32)
            rec=plistlib.dumps({'$version':100000,'$archiver':'NSKeyedArchiver','$top':{'root':plistlib.UID(1)},
                '$objects':['$null',{'$class':plistlib.UID(3),'EncryptionKey':plistlib.UID(2),'ProtectionClass':3,'Size':len(content),'RelativePath':rel},
                            {'NS.data':struct.pack('<L',3)+crypto.aes_wrap(aes,classkeys[3],fk),'$class':plistlib.UID(4)},
                            {'$classname':'MBFile','$classes':['MBFile','NSObject']},{'$classname':'NSMutableData','$classes':['NSMutableData','NSData','NSObject']}]},fmt=plistlib.FMT_BINARY)
            con.execute('INSERT INTO Files VALUES (?,?,?,?,?)',(fid,domain,rel,1,rec))
            (base/fid[:2]).mkdir(exist_ok=True); (base/fid[:2]/fid).write_bytes(enc(fk,content))
        con.commit(); con.close(); mkey=os.urandom(32)
        (base/'Manifest.db').write_bytes(enc(mkey,dbp.read_bytes()))
    (base/'Info.plist').write_bytes(plistlib.dumps({'Product Type':'iPhone15,2','Product Version':'18.1','Last Backup Date':dt.datetime(2026,9,1)}))
    (base/'Manifest.plist').write_bytes(plistlib.dumps({'IsEncrypted':True,'Applications':{a:{} for a in apps},'BackupKeyBag':kb,
                                                        'ManifestKey':struct.pack('<l',4)+crypto.aes_wrap(aes,classkeys[4],mkey)}))
    return base

def mobileprovision(kind,app_id='ABCDE12345.com.example.helper',team='Example Corp'):
    pl={'Name':f'{kind} profile','TeamName':team,'TeamIdentifier':['ABCDE12345'],'UUID':f'uuid-{kind}','Entitlements':{'application-identifier':app_id,'get-task-allow':kind=='development'},
        'CreationDate':dt.datetime(2026,8,1),'ExpirationDate':dt.datetime(2027,8,1)}
    if kind=='enterprise': pl['ProvisionsAllDevices']=True
    elif kind in ('ad_hoc','development'): pl['ProvisionedDevices']=['00008110-TEST']
    return b'0\x82\x10\x00\x06\x09*\x86H\x86\xf7\r\x01\x07\x02'+plistlib.dumps(pl)+b'\xa0\x82\x0b\x00fake-signature'

def info_plist_app(path,bid,name):
    path.mkdir(parents=True,exist_ok=True); (path/'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':bid,'CFBundleDisplayName':name,'CFBundleShortVersionString':'1.0'}))

class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.jb,cls.net=ios.load_iocs(); cls.dual=ios.load_app_list()
    def setUp(self): self.tmp=tempfile.TemporaryDirectory(); self.dir=Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()
    def scan(self,src): return ios.scan(src,self.jb,self.net,self.dual)
    def by_check(self,r,check): return [f for f in r['findings'] if f['check']==check]

class CryptoTests(Base):
    @needs_aes
    def test_rfc3394_vectors_every_backend(self):
        for name in BACKENDS:
            a=crypto.AES(name)
            for kek,key,wrapped in ((bytes(range(16)),'00112233445566778899AABBCCDDEEFF','1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'),
                                    (bytes(range(32)),'00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F','28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21')):
                self.assertEqual(crypto.aes_unwrap(a,kek,bytes.fromhex(wrapped)),bytes.fromhex(key),name)
                self.assertEqual(crypto.aes_wrap(a,kek,bytes.fromhex(key)),bytes.fromhex(wrapped),name)
            with self.assertRaises(crypto.WrongPassword): crypto.aes_unwrap(a,bytes(16),bytes.fromhex('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'))

    @needs_aes
    def test_encrypted_backup_scans_like_unencrypted_every_backend(self):
        dom=sorted(self.net['domains'])[0]
        for name in BACKENDS:
            b=make_encrypted_backup(self.dir/name,backend=name,apps=['com.wheremychildren.ios'],
                files={('HomeDomain','Library/SMS/sms.db'):sms_db([f'open {dom}/x']),('HomeDomain','Library/Cydia/metadata.cb0'):b'x',
                       (PROFILES,'Library/ConfigurationProfiles/MDM.plist'):plistlib.dumps({'ServerURL':'https://mdm.example.net/s'})})
            before={p:p.read_bytes() for p in b.rglob('*') if p.is_file()}
            with mock.patch.object(crypto,'backend',return_value=name):
                with ios.Backup(b,password=PW) as src:
                    tmp=src._tmp; r=self.scan(src)
            self.assertFalse(tmp.exists(),'decrypted temp copies must be deleted')
            checks={f['check'] for f in r['findings']}
            self.assertTrue({'network_ioc','jailbreak','mdm','dual_use_app'}<=checks,(name,checks))
            self.assertTrue(r['backup']['encrypted']); self.assertIn(name,r['backup']['decryption'])
            self.assertIn('decrypt-backup',' '.join(r['mvt_handoff']['steps']))
            self.assertEqual(before,{p:p.read_bytes() for p in b.rglob('*') if p.is_file()})

    @needs_aes
    def test_wrong_or_missing_password(self):
        b=make_encrypted_backup(self.dir/'e')
        with self.assertRaisesRegex(ios.BackupError,'Wrong backup password'): ios.Backup(b,password='nope')
        with self.assertRaisesRegex(ios.BackupError,'password'): ios.Backup(b)
        self.assertEqual(ios.Backup(b,password_prompt=lambda:PW).decryption.split(' (')[0],'decrypted by this tool')

    @needs_aes
    def test_without_optional_package_encrypted_fails_clearly_and_plain_still_works(self):
        b=make_encrypted_backup(self.dir/'e')
        with mock.patch.object(crypto,'backend',return_value=None):
            with self.assertRaisesRegex(ios.BackupError,'pip install cryptography'): ios.Backup(b,password=PW)
            self.assertEqual(self.scan(ios.Backup(make_backup(self.dir/'plain')))['findings'],[])

    def test_unencrypted_path_never_imports_aes(self):
        code=('import sys,builtins; real=builtins.__import__\n'
              'def guard(n,*a,**k):\n    assert not n.startswith(("cryptography","Crypto")),n\n    return real(n,*a,**k)\n'
              'builtins.__import__=guard; sys.path.insert(0,sys.argv[1]); sys.path.insert(0,sys.argv[2])\n'
              'import ios_scanner as ios; from test_ios_scanner import make_backup\n'
              'jb,net=ios.load_iocs(); print(len(ios.scan(ios.Backup(make_backup(sys.argv[3])),jb,net)["findings"]))')
        out=subprocess.run([sys.executable,'-c',code,str(ROOT),str(ROOT/'tests'),str(self.dir/'p')],capture_output=True,text=True)
        self.assertEqual(out.returncode,0,out.stderr); self.assertEqual(out.stdout.strip(),'0')

    @needs_aes
    def test_cli_reads_password_from_env(self):
        b=make_encrypted_backup(self.dir/'cli',files={('HomeDomain','Library/SMS/sms.db'):sms_db(['hi'])})
        js=self.dir/'r.json'
        subprocess.run([sys.executable,str(ROOT/'ios_scanner.py'),'--backup',str(b),'--output',str(self.dir/'r.txt'),'--json-output',str(js)],
                       check=True,capture_output=True,env=dict(os.environ,IOS_BACKUP_PASSWORD=PW))
        r=json.loads(js.read_text()); self.assertTrue(r['backup']['encrypted']); self.assertNotIn(PW,js.read_text())

class DualUseAppTests(Base):
    def test_list_is_versioned_sourced_and_consistent(self):
        d=self.dual; self.assertTrue(d['version']); self.assertTrue(d['sources']); self.assertGreaterEqual(len(d['apps']),40)
        for bid,a in d['apps'].items():
            self.assertIn(a['category'],d['categories'],bid); self.assertIn(a['role'],d['roles'],bid)
            self.assertEqual(a['source'],f"https://itunes.apple.com/lookup?id={a['app_store_id']}"); self.assertFalse(bid.startswith('com.apple.'))
            if a.get('echap_family'): self.assertIn(a['echap_family'],{f for fams in self.net['domains'].values() for f in fams},bid)

    def test_matches_are_medium_labeled_and_never_a_verdict(self):
        r=self.scan(ios.Backup(make_backup(self.dir/'b',apps=list(self.dual['apps'])+['com.apple.Pages','org.example.unknown'])))
        f=self.by_check(r,'dual_use_app'); self.assertEqual(len(f),len(self.dual['apps']))
        for x in f:
            self.assertEqual(x['severity'],'MEDIUM',x['indicator']); self.assertEqual(x['families'],[self.dual['apps'][x['indicator']]['category']])
            self.assertIn('Not a verdict',' '.join(x['reasons'])); self.assertTrue(x['evidence'][0]['app_store_record'].startswith('https://itunes.apple.com/lookup?id='))
        sc={x['indicator']:x['score'] for x in f}
        self.assertEqual(sc['us.bark.Bark-iOS-Child2'],40); self.assertEqual(sc['us.bark.barkconnectiosapp'],30); self.assertEqual(sc['com.veraniz.lite'],50)
        self.assertNotIn('com.apple.Pages',sc)

    def test_inventory_lists_every_app_with_names(self):
        b=make_backup(self.dir/'b',apps=['com.life360.safetymap','org.example.notes'])
        m=plistlib.loads((b/'Manifest.plist').read_bytes()); m['Applications']['org.example.notes']={'CFBundleVersion':'7','Path':'/var/containers/Bundle/Application/X/Notes Pro.app'}
        (b/'Manifest.plist').write_bytes(plistlib.dumps(m))
        i=plistlib.loads((b/'Info.plist').read_bytes()); i['Applications']={'com.life360.safetymap':{'iTunesMetadata':plistlib.dumps({'itemName':'Life360','artistName':'Life360'},fmt=plistlib.FMT_BINARY)}}
        (b/'Info.plist').write_bytes(plistlib.dumps(i))
        r=self.scan(ios.Backup(b)); inv={a['bundle_id']:a for a in r['app_inventory']}
        self.assertEqual(inv['org.example.notes']['name'],'Notes Pro'); self.assertEqual(inv['com.life360.safetymap']['developer'],'Life360')
        self.assertTrue(inv['com.life360.safetymap']['dual_use']); self.assertFalse(inv['org.example.notes']['dual_use'])
        text=ios.plain(r); self.assertIn('APP INVENTORY (2 apps',text); self.assertIn('* com.life360.safetymap - Life360',text)

class ProvisioningTests(Base):
    def prov_backup(self,kinds,apps=()):
        return ios.Backup(make_backup(self.dir/'b',apps=apps,files={('HomeDomain',f'Library/MobileDevice/ProvisioningProfiles/{k}.mobileprovision'):mobileprovision(k) for k in kinds}))

    def test_types_and_scores_alone(self):
        r=self.scan(self.prov_backup(['enterprise','ad_hoc','development','app_store'],apps=['com.example.helper']))
        f={x['profile_type']:x for x in self.by_check(r,'provisioning_profile')}
        self.assertEqual(set(f),{'enterprise','ad_hoc','development'})
        self.assertEqual((f['enterprise']['score'],f['enterprise']['severity']),(45,'MEDIUM'))
        self.assertEqual(f['ad_hoc']['score'],35); self.assertEqual(f['development']['score'],30)
        self.assertIn('com.example.helper',' '.join(f['enterprise']['reasons'])); self.assertEqual(f['enterprise']['evidence'][0]['team'],'Example Corp')

    def test_high_when_alongside_other_signals(self):
        r=self.scan(self.prov_backup(['enterprise','ad_hoc'],apps=['us.bark.Bark-iOS-Child2']))
        f={x['profile_type']:x for x in self.by_check(r,'provisioning_profile')}
        self.assertEqual((f['enterprise']['score'],f['enterprise']['severity']),(65,'HIGH')); self.assertEqual(f['ad_hoc']['severity'],'HIGH')
        self.assertIn('dual_use_app',f['enterprise']['reasons'][-1]); self.assertTrue(r['mvt_handoff']['recommended'])

    def test_backup_without_profiles_says_so(self):
        r=self.scan(ios.Backup(make_backup(self.dir/'b')))
        self.assertIn('--fs-dump',r['checks']['provisioning_profiles']['status']); self.assertFalse(r['mvt_handoff']['recommended'])

class FilesystemDumpTests(Base):
    def make_dump(self,private_only=False):
        root=self.dir/'dump'; var=(root/'var') if private_only else (root/'private'/'var')
        (var/'mobile/Library/SMS').mkdir(parents=True)
        (var/'mobile/Library/SMS/sms.db').write_bytes(sms_db([f"get it at {sorted(self.net['domains'])[1]}/a"]))
        (var/'jb').mkdir()
        app=var/'containers/Bundle/Application/1111/Helper.app'; info_plist_app(app,'com.example.helper','Helper')
        (app/'embedded.mobileprovision').write_bytes(mobileprovision('enterprise'))
        info_plist_app(var/'containers/Bundle/Application/2222/Pingo.app','com.chatwithparents.ios','Pingo')
        cp=var/'containers/Shared/SystemGroup/ABCD/Library/ConfigurationProfiles'; cp.mkdir(parents=True)
        (cp/'profile-x.stub').write_bytes(stub('Phone Helper',['com.apple.security.root']))
        if not private_only:
            info_plist_app(root/'Applications/Cydia.app','com.saurik.Cydia','Cydia')
            (root/'System/Library/CoreServices').mkdir(parents=True); (root/'System/Library/CoreServices/SystemVersion.plist').write_bytes(plistlib.dumps({'ProductVersion':'16.7'}))
        return root

    def test_full_dump_all_checks(self):
        root=self.make_dump(); before={p:p.read_bytes() for p in root.rglob('*') if p.is_file()}
        r=self.scan(ios.FilesystemDump(root)); f={}
        for x in r['findings']: f.setdefault(x['check'],[]).append(x)
        self.assertEqual({x['indicator'] for x in f['jailbreak']},{'Cydia','Rootless jailbreak'}); self.assertTrue(all(x['severity']=='CRITICAL' for x in f['jailbreak']))
        self.assertTrue(any('/private/var/jb' in e for x in f['jailbreak'] for e in x['evidence']))
        self.assertEqual(f['provisioning_profile'][0]['severity'],'HIGH'); self.assertIn('embedded.mobileprovision',f['provisioning_profile'][0]['evidence'][0]['file'])
        self.assertEqual(f['dual_use_app'][0]['indicator'],'com.chatwithparents.ios'); self.assertEqual(len(f['network_ioc']),1)
        self.assertEqual(f['configuration_profile'][0]['severity'],'HIGH')
        self.assertEqual(r['source_type'],'filesystem_dump'); self.assertEqual(r['device']['ios'],'16.7')
        self.assertIn('check-fs',' '.join(r['mvt_handoff']['steps'])); self.assertIn('Filesystem dump:',ios.plain(r))
        self.assertEqual(before,{p:p.read_bytes() for p in root.rglob('*') if p.is_file()})

    def test_private_only_dump(self):
        r=self.scan(ios.FilesystemDump(self.make_dump(private_only=True)))
        self.assertIn('jailbreak',{x['check'] for x in r['findings']}); self.assertEqual(r['device']['ios'],'unknown')

    def test_bad_dump_path(self):
        with self.assertRaises(ios.BackupError): ios.FilesystemDump(self.dir)

    def test_cli_fs_dump(self):
        root=self.make_dump(); js=self.dir/'r.json'
        subprocess.run([sys.executable,str(ROOT/'ios_scanner.py'),'--fs-dump',str(root),'--output',str(self.dir/'r.txt'),'--json-output',str(js)],check=True,capture_output=True)
        self.assertEqual(json.loads(js.read_text())['source_type'],'filesystem_dump')

class MVTHandoffTests(Base):
    def test_section_in_every_report(self):
        r=self.scan(ios.Backup(make_backup(self.dir/'b'))); t=ios.plain(r)
        self.assertIn('ESCALATE TO MVT FOR DEEP ANALYSIS',t); self.assertIn('mvt-ios check-backup --output',t); self.assertIn('Optional:',t)
        self.assertLess(t.index('SAFETY FIRST'),t.index('ESCALATE TO MVT'))
if __name__=='__main__': unittest.main()
