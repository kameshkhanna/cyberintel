#!/usr/bin/env python3
"""Aggregate-only Shodan collector. Never publishes host records or credentials."""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'src/data/shodan.json'
HISTORY = ROOT / 'src/data/shodan-history.json'
# Fixed, reviewed research queries. Limit additions to avoid unexpected API costs.
QUERIES = {'Nginx': 'product:nginx', 'Apache HTTP': 'product:Apache httpd', 'Microsoft IIS': 'product:Microsoft IIS httpd'}
FACETS = ('country', 'port', 'org')


def clean_facets(raw):
    safe = {}
    for facet in FACETS:
        rows = raw.get(facet, []) if isinstance(raw, dict) else []
        safe[facet] = []
        if not isinstance(rows, list):
            continue
        for row in rows[:8]:
            if not isinstance(row, dict):
                continue
            label, count = row.get('value'), row.get('count')
            if isinstance(label, (str, int)) and not isinstance(label, bool) and isinstance(count, int) and not isinstance(count, bool) and count >= 0:
                safe[facet].append({'label': str(label)[:100], 'count': count})
    return safe


def fetch(key, query):
    url = 'https://api.shodan.io/shodan/host/count?' + urlencode({'key': key, 'query': query, 'facets': 'country:8,port:8,org:8'})
    # Never log the URL: it contains the secret.
    try:
        with urlopen(Request(url, headers={'Accept': 'application/json', 'User-Agent': 'CyberIntel-aggregates/0.3'}), timeout=30) as response:
            data = json.load(response)
    except HTTPError as exc:
        raise RuntimeError(f'Shodan API returned HTTP {exc.code}') from None
    except (URLError, TimeoutError, ValueError):
        raise RuntimeError('Shodan network error or invalid JSON') from None
    total = data.get('total') if isinstance(data, dict) else None
    if not isinstance(total, int) or isinstance(total, bool) or total < 0:
        raise RuntimeError('Shodan response missing valid total')
    return {'query': query, 'total': total, 'facets': clean_facets(data.get('facets'))}


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.json.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temp.replace(path)


def main():
    key = os.getenv('SHODAN_API_KEY', '').strip()
    if not key:
        print('SHODAN_API_KEY not configured: preserving existing snapshots.')
        return 0
    old = {}
    if DEST.exists():
        try:
            old = json.loads(DEST.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            pass
    previous = old.get('technologies', {}) if isinstance(old.get('technologies'), dict) else {}
    now = datetime.now(timezone.utc).isoformat()
    result = {}
    failures = []
    for name, query in QUERIES.items():
        try:
            item = fetch(key, query)
            item['updated_at'] = now
            result[name] = item
            print(f'Fetched aggregate for {name} (total={item["total"]}).')
        except RuntimeError as exc:
            failures.append(name)
            print(f'Could not refresh {name}: {exc}.', file=sys.stderr)
            if name in previous:
                result[name] = previous[name]  # Keep old timestamp; do not pretend data is fresh.
    if not result:
        print('No usable Shodan snapshots; existing files preserved.', file=sys.stderr)
        return 1
    snapshot = {'source': 'Shodan /shodan/host/count', 'generated_at': now, 'technologies': result}
    history = {'source': snapshot['source'], 'snapshots': []}
    if HISTORY.exists():
        try:
            loaded = json.loads(HISTORY.read_text(encoding='utf-8'))
            if isinstance(loaded.get('snapshots'), list):
                history['snapshots'] = loaded['snapshots']
        except (OSError, ValueError, AttributeError):
            pass
    # One point per day: bounded ~90 days, prevent every 6h snapshot from swelling repository.
    daily = {'date': now[:10], 'totals': {name: item['total'] for name, item in result.items() if item.get('updated_at') == now}}
    if daily['totals']:
        history['snapshots'] = [r for r in history['snapshots'] if isinstance(r, dict) and r.get('date') != daily['date']][-89:] + [daily]
    atomic_json(DEST, snapshot)
    atomic_json(HISTORY, history)
    if failures:
        print('WARNING: some feeds failed; retained existing snapshots and timestamps.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
