#!/usr/bin/env python3
"""Rebuild iocs/network.json from Echap's public stalkerware network indicators.

Run manually after reviewing upstream changes. The scanner never downloads
indicators at scan time; it only reads the pinned snapshot in iocs/.
"""
from __future__ import annotations
import argparse, csv, datetime as dt, io, json, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = 'https://github.com/AssoEchap/stalkerware-indicators'
RAW = 'https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/{ref}/generated/network.csv'

def build(csv_text, ref, retrieved):
    domains, ipv4, urls = {}, {}, {}
    for row in csv.DictReader(io.StringIO(csv_text)):
        kind=(row.get('type') or '').strip().lower(); value=(row.get('indicator') or '').strip(); app=(row.get('app') or '').strip()
        if not value or not app: continue
        if '://' in value or '/' in value:
            key=value.split('://',1)[-1].rstrip('/').lower(); bucket=urls
        elif kind=='ipv4': key=value; bucket=ipv4
        elif kind=='domain': key=value.lower().rstrip('.'); bucket=domains
        else: continue
        bucket.setdefault(key,set()).add(app)
    tidy=lambda d:{k:sorted(v) for k,v in sorted(d.items())}
    apps={a for d in (domains,ipv4,urls) for v in d.values() for a in v}
    return {'source':REPO,'source_file':'generated/network.csv','source_ref':ref,'retrieved':retrieved,
            'license':'CC-BY-4.0','license_note':'Upstream IOC data by Echap, licensed CC-BY 4.0; see source repository for terms and updates.',
            'application_families':len(apps),'counts':{'domains':len(domains),'ipv4':len(ipv4),'urls':len(urls)},
            'domains':tidy(domains),'ipv4':tidy(ipv4),'urls':tidy(urls)}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--ref',required=True,help='Upstream commit SHA to pin (review it first)')
    ap.add_argument('--csv',help='Use a local network.csv instead of downloading')
    ap.add_argument('--output',default=str(ROOT/'iocs/network.json'))
    a=ap.parse_args()
    text=Path(a.csv).read_text(encoding='utf-8') if a.csv else urllib.request.urlopen(RAW.format(ref=a.ref),timeout=30).read().decode('utf-8')
    data=build(text,a.ref,dt.date.today().isoformat())
    Path(a.output).write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')
    print(f"Wrote {a.output}: {data['counts']} across {data['application_families']} app families")
if __name__=='__main__': main()
