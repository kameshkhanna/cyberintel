#!/usr/bin/env python3
"""Fetch and validate a recent snapshot of CISA KEV; preserve the previous file on errors."""
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
DEST = Path(__file__).resolve().parents[1] / 'src/data/intel.json'


def main():
    request = Request(URL, headers={'User-Agent': 'CyberIntelResearch/0.1 (public KEV catalog consumer)'})
    with urlopen(request, timeout=35) as response:
        data = json.load(response)
    vulnerabilities = data.get('vulnerabilities')
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise ValueError('Invalid or empty KEV catalog; keeping previous snapshot')
    required = ('cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded')
    for item in vulnerabilities:
        if not isinstance(item, dict) or any(not isinstance(item.get(k), str) for k in required):
            raise ValueError('Unexpected KEV schema; keeping previous snapshot')
    vulnerabilities.sort(key=lambda v: (v['dateAdded'], v['cveID']), reverse=True)
    trimmed = [{k: v.get(k, '') for k in (*required, 'knownRansomwareCampaignUse')} for v in vulnerabilities[:150]]
    payload = {'source': 'CISA KEV', 'updated_at': datetime.now(timezone.utc).isoformat(), 'total': len(vulnerabilities), 'items': trimmed}
    temp = DEST.with_suffix('.json.tmp')
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    temp.replace(DEST)
    print(f'Loaded {len(vulnerabilities)} KEV entries; saved {len(trimmed)}')


if __name__ == '__main__':
    main()
