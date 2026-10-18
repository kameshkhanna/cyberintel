#!/usr/bin/env python3
"""Curated cybersecurity RSS/Atom headline collector; standard library only.
No article-body scraping, no API keys, and no untrusted HTML in output.
"""
import json
import re
import sys
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'src/data/world.json'
FEEDS = {
    'BleepingComputer': 'https://www.bleepingcomputer.com/feed/',
    'SecurityWeek': 'https://www.securityweek.com/feed/',
    'The Hacker News': 'https://feeds.feedburner.com/TheHackersNews',
    'CISA Advisories': 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
}
LIMIT_PER_SOURCE = 18
MAX_AGE_DAYS = 14
ATOM = '{http://www.w3.org/2005/Atom}'

def clean(s, n=220):
    s = re.sub(r'<[^>]*>', ' ', s or '')
    return re.sub(r'\s+', ' ', s).strip()[:n]

def safe_url(link):
    try:
        p = urlsplit(link.strip())
        if p.scheme != 'https' or not p.netloc or p.username or p.password:
            return None
        return urlunsplit((p.scheme, p.netloc, p.path, p.query, ''))
    except ValueError:
        return None

def parse_date(value):
    if not value: return None
    try:
        d = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try: d = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError: return None
    if d.tzinfo is None: d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)

def parse_items(blob, source, now):
    root = ET.fromstring(blob)
    entries = root.findall('.//item')
    atom = False
    if not entries:
        entries = root.findall('.//' + ATOM + 'entry')
        atom = True
    output=[]
    for entry in entries[:LIMIT_PER_SOURCE * 3]:
        if atom:
            title = entry.findtext(ATOM+'title')
            links = entry.findall(ATOM+'link')
            link = next((x.attrib.get('href') for x in links if x.attrib.get('rel','alternate')=='alternate'), None)
            published = entry.findtext(ATOM+'published') or entry.findtext(ATOM+'updated')
        else:
            title = entry.findtext('title')
            link = entry.findtext('link')
            published = entry.findtext('pubDate')
        when = parse_date(published)
        link = safe_url(link or '')
        title = clean(title)
        if not link or not title or not when or when > now + timedelta(days=1) or when < now - timedelta(days=MAX_AGE_DAYS):
            continue
        output.append({'title':title,'url':link,'source':source,'published_at':when.isoformat()})
        if len(output)>=LIMIT_PER_SOURCE: break
    return output

def main():
    now=datetime.now(timezone.utc)
    previous={}
    if DEST.exists():
        try: previous=json.loads(DEST.read_text(encoding='utf-8'))
        except (ValueError,OSError): pass
    old_articles=previous.get('articles',[]) if isinstance(previous.get('articles'),list) else []
    articles=[]; statuses=[]; success=0
    for source,url in FEEDS.items():
        try:
            request=Request(url,headers={'User-Agent':'CyberIntel-RSS-Reader/0.4 (+https://github.com/kameshkhanna/cyberintel)','Accept':'application/rss+xml, application/atom+xml, application/xml, text/xml'})
            with urlopen(request,timeout=18) as resp:
                if int(resp.headers.get('Content-Length','0')) > 2_000_000:
                    raise ValueError('feed too large')
                body=resp.read(2_000_001)
            if len(body)>2_000_000: raise ValueError('feed too large')
            items=parse_items(body,source,now)
            articles.extend(items)
            statuses.append({'source':source,'status':'ok','items':len(items)})
            success+=1
            print(f'{source}: {len(items)} dated articles')
        except Exception as exc:
            print(f'{source}: refresh failed ({type(exc).__name__})',file=sys.stderr)
            statuses.append({'source':source,'status':'failed','items':0})
            articles.extend(x for x in old_articles if isinstance(x,dict) and x.get('source')==source)
    if not success:
        print('No feeds could be fetched; previous snapshot retained.',file=sys.stderr)
        return 1
    dedup={}
    for item in articles:
        link=item.get('url','')
        if safe_url(link) and item.get('published_at'):
            dedup[link]=item
    articles=sorted(dedup.values(),key=lambda x:x['published_at'],reverse=True)[:90]
    snapshot={'updated_at':now.isoformat(),'articles':articles,'sources':statuses}
    tmp=DEST.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(snapshot,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    tmp.replace(DEST)
    return 0

if __name__=='__main__':sys.exit(main())
