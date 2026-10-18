#!/usr/bin/env python3
"""Fetch aggregated Shodan totals only. Optional: requires SHODAN_API_KEY and SHODAN_QUERY."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

DEST = Path(__file__).resolve().parents[1] / 'src/data/shodan.json'


def main():
    key = os.environ.get('SHODAN_API_KEY', '').strip()
    query = os.environ.get('SHODAN_QUERY', '').strip()
    if not key or not query:
        print('Skipping Shodan: missing SHODAN_API_KEY or SHODAN_QUERY')
        return
    url = 'https://api.shodan.io/shodan/host/count?' + urlencode({'key': key, 'query': query})
    with urlopen(Request(url, headers={'User-Agent':'CyberIntelResearch/0.1'}), timeout=25) as resp:
        payload = json.load(resp)
    if not isinstance(payload.get('total'), int) or payload['total'] < 0:
        raise ValueError('Unexpected Shodan response, preserving previous snapshot')
    result = {'source':'Shodan host/count', 'updated_at':datetime.now(timezone.utc).isoformat(), 'query':query, 'total':payload['total']}
    tmp = DEST.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    tmp.replace(DEST)
    print('Shodan aggregate updated')


if __name__ == '__main__':
    main()
