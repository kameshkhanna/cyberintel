#!/usr/bin/env python3
"""Collect PUBLIC aggregated Shodan counts only; never store host records or API keys."""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

DEST = Path(__file__).resolve().parents[1] / 'src/data/shodan.json'
ALLOWED_FACETS = ('country', 'port', 'org')


def clean_facets(raw):
    result = {}
    if not isinstance(raw, dict):
        return result
    for name in ALLOWED_FACETS:
        items = raw.get(name, [])
        if not isinstance(items, list):
            continue
        safe = []
        for item in items[:10]:
            if not isinstance(item, dict):
                continue
            label, count = item.get('value'), item.get('count')
            if not isinstance(label, (str, int)) or isinstance(label, bool):
                continue
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                continue
            safe.append({'label': str(label)[:100], 'count': count})
        result[name] = safe
    return result


def main():
    key = os.getenv('SHODAN_API_KEY', '').strip()
    query = os.getenv('SHODAN_QUERY', 'product:nginx').strip()
    if not key:
        print('Shodan skipped: SHODAN_API_KEY is not configured.')
        return 0
    # Only explicitly approved, public research queries should be used here.
    if not query or len(query) > 180:
        print('Invalid SHODAN_QUERY length.', file=sys.stderr)
        return 1
    url = 'https://api.shodan.io/shodan/host/count?' + urlencode({
        'key': key, 'query': query, 'facets': 'country:8,port:8,org:8'
    })
    try:
        with urlopen(Request(url, headers={'Accept': 'application/json', 'User-Agent': 'CyberIntel/1.0'}), timeout=30) as response:
            payload = json.load(response)
    except HTTPError as exc:
        # NEVER print HTTPError, request URL, or response body: URL contains secret key.
        print(f'Shodan request failed: HTTP {exc.code}. Check API permissions and query.', file=sys.stderr)
        return 1
    except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
        print('Shodan request failed: network error or invalid JSON.', file=sys.stderr)
        return 1
    total = payload.get('total') if isinstance(payload, dict) else None
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        print('Shodan returned an unexpected total; previous snapshot preserved.', file=sys.stderr)
        return 1
    result = {
        'source': 'Shodan /shodan/host/count',
        'updated_at': datetime.now(timezone.utc).isoformat(),
        'query': query,
        'total': total,
        'facets': clean_facets(payload.get('facets')),
    }
    DEST.parent.mkdir(parents=True, exist_ok=True)
    temporary = DEST.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    temporary.replace(DEST)
    print(f'Shodan aggregated snapshot updated successfully (total={total}).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
