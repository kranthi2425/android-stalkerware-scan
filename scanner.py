#!/usr/bin/env python3
"""Defensive, read-only Android stalkerware triage over ADB."""
from __future__ import annotations
import argparse, datetime as dt, json, re, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DANGEROUS = {
    'android.permission.READ_SMS','android.permission.RECEIVE_SMS','android.permission.SEND_SMS',
    'android.permission.READ_CALL_LOG','android.permission.WRITE_CALL_LOG','android.permission.PROCESS_OUTGOING_CALLS',
    'android.permission.RECORD_AUDIO','android.permission.CAMERA','android.permission.ACCESS_FINE_LOCATION',
    'android.permission.ACCESS_COARSE_LOCATION','android.permission.READ_CONTACTS','android.permission.READ_PHONE_STATE',
    'android.permission.CALL_PHONE','android.permission.READ_EXTERNAL_STORAGE','android.permission.MANAGE_EXTERNAL_STORAGE'
}
SYSTEMLIKE = re.compile(r'(^|\.)(system|service|update|security|sync|backup|device|manager|settings|wifi|bluetooth)(\.|$)',re.I)
SIDELoad_INSTALLERS = {'','null','com.android.packageinstaller','com.google.android.packageinstaller','com.samsung.android.packageinstaller'}

class ADB:
    def __init__(self, serial=None): self.serial=serial
    def run(self,*args,check=False):
        cmd=['adb'] + (['-s',self.serial] if self.serial else []) + list(args)
        p=subprocess.run(cmd,text=True,capture_output=True)
        if check and p.returncode: raise RuntimeError((p.stderr or p.stdout).strip())
        return p.stdout.strip()
    def shell(self,command): return self.run('shell','sh','-c',command)

def components(value):
    return {x.split('/',1)[0] for x in re.split(r'[:,\s]+',value or '') if '/' in x}

def parse_packages(text):
    out=[]
    for line in text.splitlines():
        if not line.startswith('package:'): continue
        body=line[8:]
        path,sep,rest=body.partition('=')
        if not sep: continue
        toks=rest.split()
        pkg=toks[0]
        installer=''
        uid=''
        for t in toks[1:]:
            if t.startswith('installer='): installer=t.split('=',1)[1]
            elif t.startswith('uid:'): uid=t.split(':',1)[1]
        out.append({'package':pkg,'apk_path':path,'installer':installer,'uid':uid})
    return out

def requested_permissions(dump):
    found=set(); active=False
    for line in dump.splitlines():
        s=line.strip()
        if s == 'requested permissions:': active=True; continue
        if active:
            m=re.match(r'(android\.permission\.[A-Z0-9_]+)',s)
            if m: found.add(m.group(1))
            elif s and not line.startswith((' ','\t')): active=False
    return found

def has_usage(adb,pkg):
    text=adb.shell(f'cmd appops get --user 0 {pkg} GET_USAGE_STATS 2>/dev/null')
    return bool(re.search(r'GET_USAGE_STATS:.*(?:allow|foreground)',text,re.I))

def severity(score):
    return 'CRITICAL' if score>=90 else 'HIGH' if score>=60 else 'MEDIUM' if score>=30 else 'LOW'

def assess(pkg, known, access, admins, notify, usage, perms):
    score=0; reasons=[]
    name=pkg['package']; installer=pkg.get('installer','')
    if name in known:
        score+=100; reasons.append('Exact package-name match in the public stalkerware IOC list: '+', '.join(known[name]))
    if name in access: score+=30; reasons.append('Accessibility service is enabled')
    if name in admins: score+=25; reasons.append('Device Administrator is active')
    if name in notify: score+=20; reasons.append('Notification access is enabled')
    if usage: score+=15; reasons.append('Usage access is allowed')
    sensitive=sorted(perms & DANGEROUS)
    if len(sensitive)>=6: score+=25; reasons.append(f'Requests {len(sensitive)} sensitive surveillance-relevant permissions')
    elif len(sensitive)>=3: score+=12; reasons.append(f'Requests {len(sensitive)} sensitive surveillance-relevant permissions')
    privilege_count=sum((name in access,name in admins,name in notify,usage))
    if privilege_count>=2: score+=25; reasons.append(f'High-risk privilege combination ({privilege_count} special accesses)')
    if installer in SIDELoad_INSTALLERS: score+=10; reasons.append('Install source is unknown or a package installer (possible sideload)')
    if SYSTEMLIKE.search(name) and name not in known: score+=8; reasons.append('Generic system-like package name (weak heuristic)')
    return {'package':name,'score':score,'severity':severity(score),'installer':installer or 'unknown','reasons':reasons,'sensitive_permissions':sensitive,'special_access':{'accessibility':name in access,'device_admin':name in admins,'notification_listener':name in notify,'usage_access':usage}}

def scan(adb,known):
    model=adb.shell('getprop ro.product.manufacturer')+' '+adb.shell('getprop ro.product.model')
    android=adb.shell('getprop ro.build.version.release')
    packages=parse_packages(adb.shell('pm list packages -f -i -U'))
    access=components(adb.shell('settings get secure enabled_accessibility_services'))
    notify=components(adb.shell('settings get secure enabled_notification_listeners'))
    policy=adb.shell('dumpsys device_policy')
    admins=set(re.findall(r'(?:ComponentInfo\{|admin=)([A-Za-z0-9_.$]+)/(?:[A-Za-z0-9_.$]+)',policy))
    reports=[]
    for i,p in enumerate(packages,1):
        dump=adb.shell(f'dumpsys package {p["package"]} 2>/dev/null')
        perms=requested_permissions(dump)
        candidate=(p['package'] in known or p['package'] in access or p['package'] in admins or p['package'] in notify or SYSTEMLIKE.search(p['package']) or p.get('installer','') in SIDELoad_INSTALLERS or len(perms & DANGEROUS)>=3)
        usage=has_usage(adb,p['package']) if candidate else False
        r=assess(p,known,access,admins,notify,usage,perms)
        if r['score']>0: reports.append(r)
        print(f'\rChecked {i}/{len(packages)} packages',end='',file=sys.stderr)
    print(file=sys.stderr)
    pp=adb.shell('settings get global package_verifier_enable')
    adb_verify=adb.shell('settings get global verifier_verify_adb_installs')
    return {'generated_at':dt.datetime.now(dt.timezone.utc).isoformat(),'device':{'model':model.strip(),'android':android,'serial':adb.serial or 'default'},'package_count':len(packages),'play_protect':{'package_verifier_enable':pp,'verify_adb_installs':adb_verify,'note':'These settings are only partial signals. Confirm Play Protect manually in Play Store > profile > Play Protect > Settings.'},'findings':sorted(reports,key=lambda x:(-x['score'],x['package']))}

def plain(report):
    serious=[x for x in report['findings'] if x['score']>=30]
    lines=['ANDROID STALKERWARE TRIAGE REPORT','='*35,f"Generated: {report['generated_at']}",f"Device: {report['device']['model']} (Android {report['device']['android']})",f"Packages inventoried: {report['package_count']}",'', 'SAFETY FIRST: Do not uninstall or change suspicious apps until you have a safety plan. Removal can alert an abuser and can destroy evidence. Use a safer device to contact a trusted advocate or local support service.','',f'Priority findings: {len(serious)}','']
    if not serious: lines += ['No medium/high-confidence findings were produced. This DOES NOT prove the phone is clean. New, renamed, or well-hidden tools can be missed.','']
    for f in serious:
        lines += [f"[{f['severity']}] {f['package']} - score {f['score']}",f"  Install source: {f['installer']}"]+[f'  - {r}' for r in f['reasons']]+['']
    lines += ['OTHER LOW-CONFIDENCE SIGNALS','']
    for f in report['findings']:
        if f['score']<30: lines.append(f"[LOW] {f['package']} - score {f['score']}: "+'; '.join(f['reasons']))
    lines += ['', 'Play Protect check:',f"  package_verifier_enable={report['play_protect']['package_verifier_enable']}",f"  verifier_verify_adb_installs={report['play_protect']['verify_adb_installs']}",f"  {report['play_protect']['note']}",'','Next steps: preserve this report and a full Android bugreport; photograph relevant settings with a safer device; record date/time and who handled the phone; seek specialist help before removing anything.']
    return '\n'.join(lines)+'\n'

def main():
    ap=argparse.ArgumentParser(description='Read-only ADB stalkerware triage')
    ap.add_argument('--serial'); ap.add_argument('--output',default='report.txt'); ap.add_argument('--json-output',default='report.json'); ap.add_argument('--input-fixture',help='Test/offline JSON fixture instead of ADB')
    a=ap.parse_args()
    data=json.loads((ROOT/'iocs/packages.json').read_text()); known=data['packages']
    if a.input_fixture:
        fixture=json.loads(Path(a.input_fixture).read_text()); findings=[]
        for p in fixture['packages']:
            findings.append(assess(p,known,set(fixture.get('accessibility',[])),set(fixture.get('device_admin',[])),set(fixture.get('notification',[])),p['package'] in fixture.get('usage',[]),set(p.get('permissions',[]))))
        report={'generated_at':dt.datetime.now(dt.timezone.utc).isoformat(),'device':fixture.get('device',{'model':'fixture','android':'test'}),'package_count':len(fixture['packages']),'play_protect':{'package_verifier_enable':'unknown','verify_adb_installs':'unknown','note':'fixture'},'findings':sorted([x for x in findings if x['score']],key=lambda x:-x['score'])}
    else:
        if not shutil.which('adb'): raise SystemExit('adb not found. Install Android Platform Tools and put adb on PATH.')
        adb=ADB(a.serial); state=adb.run('get-state')
        if state!='device': raise SystemExit('No authorized Android device found. Enable USB debugging, connect by USB, unlock, and accept the RSA prompt.')
        report=scan(adb,known)
    Path(a.output).write_text(plain(report)); Path(a.json_output).write_text(json.dumps(report,indent=2)+'\n')
    print(f'Wrote {a.output} and {a.json_output}')
if __name__=='__main__': main()
