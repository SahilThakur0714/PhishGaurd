"""
services/classifier/scorer.py
──────────────────────────────
Scores crawl results from crawl_results.jsonl.

Key fixes vs v1:
  1. Detects Cloudflare-intercepted pages — suppresses visual score
     (screenshot is a CF challenge page, not the actual phishing page)
  2. Deduplicates by URL before scoring
  3. Overwrites scored_results.jsonl (no stacking on re-runs)
  4. page_title used as a scoring signal
  5. Brand keyword in path vs domain handled separately
  6. Malware download URLs categorised separately
"""

import os
import json
import imagehash
from PIL import Image

BASE_DIR      = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR      = os.path.join(BASE_DIR, 'data')
LIBRARY_DIR   = os.path.join(DATA_DIR, 'brand_library')
RESULTS_FILE  = os.path.join(DATA_DIR, 'crawl_results.jsonl')
SCORED_FILE   = os.path.join(DATA_DIR, 'scored_results.jsonl')
FINGERPRINTS  = os.path.join(LIBRARY_DIR, 'fingerprints.json')

VISUAL_MATCH_THRESHOLD = 70.0

# ── brand fingerprints ─────────────────────────────────────────────────────────
print("Loading brand fingerprint library...")
with open(FINGERPRINTS) as f:
    raw = json.load(f)
LIBRARY = {k: imagehash.hex_to_hash(v) for k, v in raw.items()}
print(f"Loaded {len(LIBRARY)} brand fingerprints: {', '.join(LIBRARY.keys())}\n")

BRAND_KEYWORDS = [
    'google', 'microsoft', 'facebook', 'paypal',
    'apple', 'netflix', 'amazon', 'instagram',
]

CLOUDFLARE_TITLES = {
    "suspected phishing site | cloudflare",
    "attention required! | cloudflare",
    "just a moment... | cloudflare",
    "access denied | cloudflare",
    "error | cloudflare",
}

CLOUDFLARE_REDIRECT_HOSTS = {
    "challenges.cloudflare.com",
    "cloudflare.com",
}


# ── detection helpers ──────────────────────────────────────────────────────────

def is_cloudflare_blocked(record: dict) -> bool:
    title = (record.get('page_title') or '').lower()
    if any(cf in title for cf in CLOUDFLARE_TITLES):
        return True
    for redirect in (record.get('redirects') or []):
        if any(cf in redirect for cf in CLOUDFLARE_REDIRECT_HOSTS):
            return True
    return False


def is_malware_download(record: dict) -> bool:
    url   = record.get('url', '').lower()
    error = (record.get('error') or '').lower()
    if 'download is starting' in error:
        return True
    return any(url.endswith(ext) for ext in
               ['.zip', '.exe', '.msi', '.dmg', '.apk', '.rar', '.7z'])


# ── scoring functions ──────────────────────────────────────────────────────────

def visual_score(screenshot_path: str) -> tuple:
    if not screenshot_path or not os.path.exists(screenshot_path):
        return None, 0
    try:
        img       = Image.open(screenshot_path).convert("RGB")
        page_hash = imagehash.phash(img, hash_size=16)
        best_brand, best_score = None, 0.0
        for brand, brand_hash in LIBRARY.items():
            distance   = page_hash - brand_hash
            similarity = max(0.0, 100.0 - (distance / 256.0 * 100.0))
            if similarity > best_score:
                best_score = similarity
                best_brand = brand
        if best_score < VISUAL_MATCH_THRESHOLD:
            return None, 0
        return best_brand, round(best_score, 1)
    except Exception as e:
        print(f"  [visual_score] {e}")
        return None, 0


def url_score(url: str) -> tuple:
    """Returns (score 0-100, list of triggered signal names)."""
    score   = 0
    signals = []
    u       = url.lower()

    try:
        after_scheme = url.split("//", 1)[1]
        domain_part  = after_scheme.split("/")[0].lower()
        path_part    = "/".join(after_scheme.split("/")[1:]).lower()
    except IndexError:
        domain_part, path_part = u, ""

    if len(url) > 75:
        score += 15; signals.append("long-url")
    if url.count('.') > 4:
        score += 20; signals.append("many-subdomains")
    if url.count('-') > 3:
        score += 15; signals.append("many-hyphens")
    if '@' in url:
        score += 25; signals.append("@-in-url")

    for kw in ['secure', 'login', 'verify', 'verification', 'update', 'account', 'confirm']:
        if kw in u:
            score += 10; signals.append(f"kw:{kw}"); break

    # Brand in domain = masquerade attempt
    for kw in BRAND_KEYWORDS:
        if kw in domain_part:
            score += 20; signals.append(f"brand-in-domain:{kw}"); break

    # Brand only in path = lure (e.g. /verification.google)
    for kw in BRAND_KEYWORDS:
        if kw in path_part and kw not in domain_part:
            score += 15; signals.append(f"brand-in-path:{kw}"); break

    risky_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq',
                  '.xyz', '.top', '.in.net', '.pw', '.cc', '.click']
    if any(domain_part.endswith(t) for t in risky_tlds):
        score += 20; signals.append("risky-tld")

    return min(score, 100), signals


def title_score(page_title: str) -> tuple:
    """Returns (score, force_flag: bool)."""
    if not page_title:
        return 0, False
    t = page_title.lower()
    if 'suspected phishing' in t:
        return 50, True    # CF itself called it phishing
    for kw in ['verify your account', 'confirm your identity',
               'sign in', 'log in', 'update your details']:
        if kw in t:
            return 20, False
    return 0, False


def score_result(record: dict) -> dict:
    url       = record.get('url', '')
    screenshot = record.get('screenshot_path')
    domain    = record.get('domain', '')

    cf_blocked = is_cloudflare_blocked(record)
    malware    = is_malware_download(record)

    # Visual score: suppress when CF blocked (screenshot = CF page, not phish)
    if cf_blocked or not screenshot:
        brand, v_score = None, 0
        v_note = "CF_BLOCKED" if cf_blocked else "NO_SCREENSHOT"
    else:
        brand, v_score = visual_score(screenshot)
        v_note = None

    u_score, signals   = url_score(url)
    t_score, cf_called = title_score(record.get('page_title') or '')

    login_score = (40 if record.get('has_password_field')
                   else 20 if record.get('has_login_form')
                   else 0)

    # Weighted total
    if cf_blocked:
        # CF has the screenshot; we rely on URL + CF title signal
        total = round((u_score * 0.55) + (t_score * 0.25) + (login_score * 0.20), 1)
        total = max(total, 36.0)   # CF flagged it → minimum NEEDS REVIEW
    elif malware:
        total = round(u_score * 0.70, 1)
    else:
        total = round((v_score * 0.45) + (u_score * 0.35) + (login_score * 0.20), 1)

    # Decision
    if cf_blocked and cf_called:
        decision = 'PHISHING'
    elif total > 65:
        decision = 'PHISHING'
    elif total > 35:
        decision = 'NEEDS REVIEW'
    else:
        decision = 'PROBABLY SAFE'

    return {
        'url':               url,
        'domain':            domain,
        'risk_score':        total,
        'decision':          decision,
        'looks_like':        brand,
        'visual_similarity': v_score,
        'url_suspicion':     u_score,
        'url_signals':       signals,
        'has_login':         record.get('has_login_form',     False),
        'has_password':      record.get('has_password_field', False),
        'page_title':        record.get('page_title',         ''),
        'cf_blocked':        cf_blocked,
        'malware_url':       malware,
        'visual_note':       v_note,
        'screenshot':        screenshot,
    }


# ── run ────────────────────────────────────────────────────────────────────────
print(f"Scoring: {RESULTS_FILE}")
print("=" * 65)

seen_urls    = set()
records      = []
skip_fail    = 0
skip_dupe    = 0

with open(RESULTS_FILE) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = rec.get('url', '')

        # Keep failed records only if they're malware downloads (still scoreable by URL)
        if not rec.get('success') and not is_malware_download(rec):
            skip_fail += 1
            continue

        if url in seen_urls:
            skip_dupe += 1
            continue
        seen_urls.add(url)
        records.append(rec)

print(f"  {len(records)} unique records | {skip_dupe} dupes removed | {skip_fail} failed crawls skipped\n")

results  = []
phishing = []
review   = []
safe     = []

with open(SCORED_FILE, 'w') as out:
    for record in records:
        scored = score_result(record)
        results.append(scored)
        out.write(json.dumps(scored) + '\n')

        if   scored['decision'] == 'PHISHING':      phishing.append(scored)
        elif scored['decision'] == 'NEEDS REVIEW':  review.append(scored)
        else:                                        safe.append(scored)

        bar    = '#' * int(scored['risk_score'] / 5)
        tags   = (" [CF]"  if scored['cf_blocked']  else "") + \
                 (" [MLW]" if scored['malware_url'] else "")

        print(f"\nURL   : {scored['url'][:65]}")
        print(f"Score : {scored['risk_score']:5.1f}/100  [{bar:<20}]  {scored['decision']}{tags}")
        if scored['page_title']:
            print(f"Title : {scored['page_title'][:60]}")
        if scored['looks_like']:
            print(f"Match : {scored['looks_like']} ({scored['visual_similarity']}%)")
        if scored['url_signals']:
            print(f"Flags : {', '.join(scored['url_signals'])}")
        if scored['has_password']:
            print("  *** HAS PASSWORD FIELD ***")

# ── summary ────────────────────────────────────────────────────────────────────
print("\n" + "=" * 65)
print(f"SUMMARY  —  {len(results)} unique sites scored")
print(f"  PHISHING     : {len(phishing)}")
print(f"  NEEDS REVIEW : {len(review)}")
print(f"  PROBABLY SAFE: {len(safe)}")
print(f"\nResults → {SCORED_FILE}")

if phishing:
    print(f"\nTop phishing sites:")
    for s in sorted(phishing, key=lambda x: x['risk_score'], reverse=True)[:10]:
        print(f"  [{s['risk_score']:5.1f}] {s['url'][:60]}"
              f"{'  [CF]' if s['cf_blocked'] else ''}")

print("=" * 65)
print("\nNext: python services\\takedown\\sender.py")