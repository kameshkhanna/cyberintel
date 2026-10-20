#!/usr/bin/env python3
"""Validate public intelligence snapshots and generate build-time source health.

Remote text is treated as untrusted data. A collector may fail while retaining
its last valid snapshot, but absent required datasets are not publishable.
"""
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'src/data'
NOW = dt.datetime.now(dt.timezone.utc)
SOURCES = [
    ('kev', 'CISA KEV', 'intel.json', 'items', 150),
    ('news', 'Global Cyber Watch', 'world.json', 'articles', 120),
    ('shodan', 'Shodan snapshots', 'shodan.json', None, None),
    ('cve', 'NVD / EPSS enrichment', 'vulnerabilities.json', 'items', 60),
]
ALLOWED_HOSTS = {
    'BleepingComputer': ('bleepingcomputer.com',),
    'SecurityWeek': ('securityweek.com',),
    'The Hacker News': ('thehackernews.com',),
    'CISA Advisories': ('cisa.gov',),
    'CIS Advisories': ('cisecurity.org',),
}
CVE = re.compile(r'^CVE-\d{4}-\d{4,}$')
CONTROL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')


def fail(message):
    raise ValueError(message)


def load(name):
    path = DATA / name
    if not path.exists():
        fail(f'{name}: required dataset missing; refusing to publish')
    if not path.is_file() or path.is_symlink():
        fail(f'{name}: expected a regular file')
    if path.stat().st_size > 3_000_000:
        fail(f'{name}: exceeds configured size limit')
    obj = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(obj, dict):
        fail(f'{name}: root must be an object')
    return obj


def timestamp(value, label):
    if value is None:
        return None
    if not isinstance(value, str):
        fail(f'{label}: invalid timestamp type')
    try:
        moment = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if moment.tzinfo is None:
            fail(f'{label}: missing timezone')
        moment = moment.astimezone(dt.timezone.utc)
        if moment > NOW + dt.timedelta(hours=24):
            fail(f'{label}: future timestamp')
        return moment
    except (TypeError, ValueError):
        fail(f'{label}: malformed timestamp')


def scalar_text(value, label, maximum=1600):
    if not isinstance(value, str) or len(value) > maximum or CONTROL.search(value):
        fail(f'{label}: malformed or oversized text')


def upstream_count(file, collection):
    try:
        raw = subprocess.run(['git', 'show', f'HEAD:src/data/{file}'], cwd=ROOT,
                             text=True, capture_output=True, timeout=5, check=True).stdout
        obj = json.loads(raw)
        seq = obj.get(collection, [])
        return len(seq) if isinstance(seq, list) else 0
    except (subprocess.CalledProcessError, ValueError, subprocess.TimeoutExpired):
        return 0


def validate(source, obj, file, collection, max_items):
    date_value = obj.get('updated_at') or (obj.get('generated_at') if source == 'shodan' else None)
    timestamp(date_value, file)
    if collection:
        items = obj.get(collection)
        if not isinstance(items, list) or len(items) > max_items:
            fail(f'{file}: invalid {collection} collection')
        old = upstream_count(file, collection)
        if old >= 20 and len(items) < old * .5:
            fail(f'{file}: more than 50% drop since last published snapshot; requires review')
        if source == 'kev':
            for item in items:
                if not isinstance(item, dict) or not CVE.fullmatch(str(item.get('cveID', ''))):
                    fail('intel.json: invalid CVE identifier')
                for key in ('vendorProject', 'product', 'vulnerabilityName'):
                    scalar_text(item.get(key, ''), 'KEV '+key, 800)
        elif source == 'cve':
            for item in items:
                if not isinstance(item, dict) or not CVE.fullmatch(str(item.get('id', ''))):
                    fail('vulnerabilities.json: invalid CVE identifier')
                for key in ('title', 'description', 'guidance'):
                    scalar_text(item.get(key, ''), 'CVE '+key)
                p = item.get('epss')
                if p is not None and (not isinstance(p, (float, int)) or isinstance(p, bool) or not 0 <= p <= 1):
                    fail('vulnerabilities.json: EPSS out of range')
        elif source == 'news':
            for item in items:
                if not isinstance(item, dict):
                    fail('world.json: invalid article')
                src = item.get('source')
                if src not in ALLOWED_HOSTS:
                    fail('world.json: untrusted publisher')
                link = item.get('url', '')
                if not isinstance(link, str):
                    fail('world.json: invalid URL')
                p = urlsplit(link)
                host = (p.hostname or '').lower()
                if (p.scheme != 'https' or p.username or p.password or p.port not in (None, 443)
                    or not any(host == allowed or host.endswith('.' + allowed) for allowed in ALLOWED_HOSTS[src])):
                    fail('world.json: external/unexpected publisher URL')
                scalar_text(item.get('title'), 'news headline', 250)
                timestamp(item.get('published_at'), 'news publication date')
    elif source == 'shodan':
        total = obj.get('total')
        if total is not None and (not isinstance(total, int) or isinstance(total, bool) or total < 0):
            fail('shodan.json: invalid aggregate total')
        technologies = obj.get('technologies', {})
        if not isinstance(technologies, dict) or len(technologies) > 12:
            fail('shodan.json: invalid technologies object')
        for name, tech in technologies.items():
            scalar_text(name, 'Shodan technology name', 100)
            if not isinstance(tech, dict):
                fail('shodan.json: invalid technology record')
            t = tech.get('total')
            if not isinstance(t, int) or isinstance(t, bool) or t < 0:
                fail('shodan.json: invalid technology count')
            timestamp(tech.get('updated_at'), 'Shodan technology timestamp')
    if source == 'shodan':
        history = load('shodan-history.json')
        snapshots = history.get('snapshots', [])
        if not isinstance(snapshots, list) or len(snapshots) > 100:
            fail('shodan-history.json: invalid history size')
    return len(obj.get(collection, [])) if collection else len(obj.get('technologies', {}))


def main():
    statuses = []
    collector_ok = 0
    for key, label, filename, collection, limit in SOURCES:
        outcome = os.getenv('COLLECTOR_' + key.upper(), 'unknown')
        if outcome not in ('unknown', 'success', 'failure', 'skipped'):
            fail(f'{key}: unexpected collector outcome')
        if outcome == 'success':
            collector_ok += 1
        data = load(filename)
        count = validate(key, data, filename, collection, limit)
        last = data.get('updated_at') or (data.get('generated_at') if key == 'shodan' else None)
        if key == 'shodan' and isinstance(data.get('technologies'), dict):
            timestamps = [x.get('updated_at') for x in data['technologies'].values() if isinstance(x, dict) and x.get('updated_at')]
            if timestamps:
                last = min(timestamps)
        parsed = timestamp(last, filename)
        age_hours = round((NOW - parsed).total_seconds() / 3600, 1) if parsed else None
        state = ('unavailable' if not parsed else
                 'degraded' if outcome in ('failure', 'skipped', 'unknown') else
                 'stale' if age_hours > 30 else 'current')
        statuses.append({'key': key, 'label': label, 'status': state, 'items': count,
                         'updated_at': last, 'age_hours': age_hours, 'collector': outcome})
    if any(os.getenv('COLLECTOR_' + k.upper(), 'unknown') != 'unknown' for k, *_ in SOURCES) and collector_ok == 0:
        fail('All collectors failed; refusing to publish a misleading refreshed dashboard')
    result = {'generated_at': NOW.isoformat(), 'meaning': 'Last validated build-time snapshot; not a live uptime monitor',
              'overall': 'degraded' if any(s['status'] != 'current' for s in statuses) else 'current',
              'sources': statuses}
    (DATA / 'source-health.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    for s in statuses:
        print(f"{s['label']}: {s['status']} | {s['items']} records | collector={s['collector']}")
    print('Snapshot validation complete')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        print(f'VALIDATION FAILED: {exc}', file=sys.stderr)
        sys.exit(1)
