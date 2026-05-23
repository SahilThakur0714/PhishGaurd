import httpx
import json
import os
import csv
import io
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)

# Clear old suspects so we start fresh
SUSPECTS_FILE = os.path.join(DATA_DIR, 'suspects.jsonl')
if os.path.exists(SUSPECTS_FILE):
    os.remove(SUSPECTS_FILE)
    print("Cleared old suspects file.")

def save_url(url, source, target='unknown', score=0):
    if not url or not url.startswith('http'):
        return False
    try:
        domain = url.split('/')[2]
    except:
        return False
    # skip very short/weird domains
    if len(domain) < 4:
        return False
    record = {
        'domain': domain,
        'url': url,
        'source': source,
        'target': target,
        'phish_score': score,
        'found_at': datetime.now().isoformat()
    }
    with open(SUSPECTS_FILE, 'a') as f:
        f.write(json.dumps(record) + '\n')
    return True

def try_phishstats():
    """PhishStats gives a score per URL — we only take high-score ones"""
    print("\n--- Trying PhishStats (high-score phishing URLs) ---")
    try:
        r = httpx.get(
            "https://phishstats.info/phish_score.csv",
            timeout=40,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        reader = csv.reader(io.StringIO(r.text))
        saved = 0
        skipped = 0
        for row in reader:
            if len(row) < 4:
                continue
            try:
                score = float(row[1].strip())
                url   = row[2].strip().strip('"')
                # only take URLs with high phish score (8+ out of 10)
                if score >= 8.0 and url.startswith('http') and saved < 50:
                    if save_url(url, 'phishstats', score=score):
                        saved += 1
                        print(f"  [{saved}] score={score}  {url[:65]}")
                else:
                    skipped += 1
            except:
                continue
        print(f"Saved {saved} high-confidence URLs from PhishStats")
        return saved
    except Exception as e:
        print(f"PhishStats failed: {e}")
        return 0

def try_openphish():
    """OpenPhish — simple URL list, very fresh"""
    print("\n--- Trying OpenPhish ---")
    try:
        r = httpx.get(
            "https://openphish.com/feed.txt",
            timeout=30,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        urls = [l.strip() for l in r.text.splitlines()
                if l.strip().startswith('http')]
        print(f"Got {len(urls)} URLs")
        saved = 0
        for url in urls[:50]:
            if save_url(url, 'openphish'):
                saved += 1
                print(f"  [{saved}] {url[:70]}")
        print(f"Saved {saved} from OpenPhish")
        return saved
    except Exception as e:
        print(f"OpenPhish failed: {e}")
        return 0

def try_urlhaus_fresh():
    """URLhaus — filter to HTTPS only, no raw IPs, no bin.sh"""
    print("\n--- Trying URLhaus (filtered for phishing pages only) ---")
    try:
        r = httpx.get(
            "https://urlhaus.abuse.ch/downloads/text_recent/",
            timeout=30
        )
        all_urls = [l.strip() for l in r.text.splitlines()
                    if l.strip().startswith('http') and not l.startswith('#')]

        saved = 0
        for url in all_urls:
            if saved >= 30:
                break
            # skip raw IPs, shell scripts, and known malware payloads
            import re
            if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
                continue
            if url.endswith(('.sh', '.exe', '.bin', '.elf', '/i')):
                continue
            # only keep URLs that look like web pages
            if save_url(url, 'urlhaus'):
                saved += 1
                print(f"  [{saved}] {url[:70]}")

        print(f"Saved {saved} from URLhaus")
        return saved
    except Exception as e:
        print(f"URLhaus failed: {e}")
        return 0

print("="*60)
print("Collecting FRESH phishing URLs...")
print("="*60)

total = 0
total += try_phishstats()
if total < 10:
    total += try_openphish()
if total < 10:
    total += try_urlhaus_fresh()

print(f"\n{'='*60}")
if total > 0:
    print(f"SUCCESS! Saved {total} fresh suspects")
    print(f"File: {SUSPECTS_FILE}")
    print(f"\nNext: python services\\crawler\\screenshot.py")
else:
    print("All sources failed - check internet connection")
print("="*60)
