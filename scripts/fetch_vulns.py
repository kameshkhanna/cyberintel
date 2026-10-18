#!/usr/bin/env python3
"""Build a capped public CVE enrichment snapshot from CISA KEV, NVD and FIRST EPSS.
No Shodan host data is joined to CVEs: fingerprint != confirmed vulnerable asset.
Uses stdlib only; source failures are reported; existing snapshot is preserved on total failure.
"""
import datetime as dt
import json
import os
import pathlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = pathlib.Path(__file__).resolve().parents[1]
OUTPUT = BASE / 'src/data/vulnerabilities.json'
KEV = BASE / 'src/data/intel.json'
NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
EPSS_URL = 'https://api.first.org/data/v1/epss'
UA = 'CyberIntel-research/0.7 (public data attribution; https://github.com/kameshkhanna/cyberintel)'
LIMIT = min(max(int(os.getenv('CVE_ENRICH_LIMIT', '24')), 1), 60)

def get_json(url, key=None, attempts=3):
    headers = {'User-Agent': UA, 'Accept': 'application/json'}
    if key:
        headers['apiKey'] = key
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=25) as r:
                return json.load(r)
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            if attempt == attempts - 1:
                raise RuntimeError(f'{type(e).__name__} requesting endpoint {urllib.parse.urlsplit(url).hostname}') from None
            time.sleep(2 * (attempt + 1))

def cvss_data(record):
    metrics = record.get('metrics') or {}
    for name in ('cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2'):
        group = metrics.get(name) or []
        if group:
            best = next((x for x in group if x.get('type') == 'Primary'), group[0])
            cvss = best.get('cvssData') or {}
            return cvss.get('baseScore'), cvss.get('baseSeverity') or best.get('baseSeverity'), name
    return None, None, None

def english_description(record):
    return next((x.get('value','') for x in record.get('descriptions',[]) if x.get('lang')=='en'), '')[:1200]

def guidance(kev):
    return (kev.get('requiredAction') or 'Review the vendor advisory, determine affected versions, apply the vendor-supported fix or mitigation, and validate the change.')[:800]

def tier(kev, epss, cvss):
    # Display heuristic only: not asset-specific risk; no fake Tenable/Qualys score.
    if kev:
        return 'Actively exploited (KEV)'
    if epss is not None and epss >= 0.20:
        return 'Elevated probability'
    if cvss is not None and cvss >= 9:
        return 'Critical severity'
    return 'Review'

def main():
    if not KEV.exists():
        raise SystemExit('CISA KEV snapshot missing; run scripts/fetch_intel.py first')
    cached = json.loads(KEV.read_text())
    items = cached.get('items', [])
    selected = [v for v in items if re.fullmatch(r'CVE-\d{4}-\d{4,}', str(v.get('cveID','')))] [:LIMIT]
    if not selected:
        print('No CISA KEV items found; leaving existing CVE snapshot untouched')
        return
    ids = [v['cveID'] for v in selected]
    try:
        epss_payload = get_json(EPSS_URL+'?'+urllib.parse.urlencode({'cve':','.join(ids)}))
        epss_map = {x['cve']:x for x in epss_payload.get('data',[]) if x.get('cve') in ids}
        epss_ok = True
    except RuntimeError as e:
        print(f'EPSS unavailable: {e}')
        epss_map = {}
        epss_ok = False
    enriched=[]
    nvd_ok=0
    api_key=os.getenv('NVD_API_KEY') or None
    for i, kev in enumerate(selected):
        cid = kev['cveID']
        record = {}
        try:
            payload=get_json(NVD_URL+'?'+urllib.parse.urlencode({'cveId':cid}),key=api_key,attempts=2)
            records=payload.get('vulnerabilities') or []
            record=records[0].get('cve',{}) if records else {}
            if record: nvd_ok+=1
        except RuntimeError:
            pass
        cvss, severity, version = cvss_data(record)
        epss = epss_map.get(cid)
        prob = float(epss['epss']) if epss and epss.get('epss') is not None else None
        percentile = float(epss['percentile']) if epss and epss.get('percentile') is not None else None
        enriched.append({
          'id':cid, 'title':kev.get('vulnerabilityName') or cid,
          'vendor':kev.get('vendorProject',''), 'product':kev.get('product',''),
          'date_added':kev.get('dateAdded'), 'due_date':kev.get('dueDate'),
          'description':english_description(record) or kev.get('shortDescription',''),
          'cvss':cvss, 'cvss_severity':severity, 'cvss_version':version,
          'epss':prob, 'epss_percentile':percentile,
          'epss_date':epss.get('date') if epss else None,
          'kev':True, 'ransomware':kev.get('knownRansomwareCampaignUse','Unknown'),
          'priority':tier(True,prob,cvss), 'guidance':guidance(kev),
          'source_nvd':'https://nvd.nist.gov/vuln/detail/'+cid,
          'source_cisa':'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
          'source_epss':'https://www.first.org/epss/',
          'nvd_status':'available' if record else 'unavailable',
        })
        # NVD unauthenticated low-rate usage; avoid exhausting free public API quota.
        if i < len(selected)-1:
            time.sleep(0.7 if api_key else 6.2)
    if not enriched:
        return
    result={'updated_at':dt.datetime.now(dt.timezone.utc).isoformat(),
      'scope':'Latest CISA KEV entries, not the entire NVD catalog',
      'sources':{'cisa_kev':cached.get('updated_at'),'nvd_success':nvd_ok,'nvd_requested':len(selected),'epss_available':epss_ok},
      'count':len(enriched),'items':enriched,
      'disclaimer':'KEV entry confirms observed exploitation somewhere, not vulnerability of your assets. CVSS is severity, EPSS is statistical probability, Shodan banners are indicative only.'}
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    temp=OUTPUT.with_suffix('.tmp')
    temp.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    temp.replace(OUTPUT)
    print(f'Wrote {len(enriched)} CVEs: NVD matched {nvd_ok}, EPSS available={epss_ok}')

if __name__=='__main__': main()
