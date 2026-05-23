import asyncio
import os
import json
from datetime import datetime
from playwright.async_api import async_playwright
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(BASE_DIR, 'data')
SUSPECTS_FILE = os.path.join(DATA_DIR, 'suspects.jsonl')
RESULTS_FILE  = os.path.join(DATA_DIR, 'crawl_results.jsonl')
SCREENSHOTS_DIR = os.path.join(DATA_DIR, 'screenshots')
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

def is_crawlable(url):
    """Skip raw IPs with ports and non-http URLs"""
    if not url.startswith('http'):
        return False
    # skip raw IP:port URLs like http://1.2.3.4:5678/
    ip_port = re.match(r'https?://\d+\.\d+\.\d+\.\d+:\d+', url)
    if ip_port:
        return False
    return True

def load_suspects():
    suspects = []
    try:
        with open(SUSPECTS_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    suspects.append(json.loads(line))
    except FileNotFoundError:
        print("No suspects file found! Run ct_watcher.py first.")
    return suspects

async def crawl_one(page, suspect, index, total):
    url = suspect['url']
    domain = suspect['domain'].replace(':', '_')  # safe for filename
    result = {
        'url': url,
        'domain': suspect['domain'],
        'source': suspect.get('source', ''),
        'visited_at': datetime.now().isoformat(),
        'success': False,
        'screenshot_path': None,
        'page_title': None,
        'has_login_form': False,
        'has_password_field': False,
        'final_url': url,
        'redirects': [],
        'error': None
    }

    print(f"\n[{index}/{total}] Visiting: {url[:70]}")

    try:
        # track redirects
        redirects = []
        page.on('response', lambda r: redirects.append(r.url)
                if r.status in (301, 302, 303, 307, 308) else None)

        await page.goto(url, timeout=12000, wait_until='domcontentloaded')
        await page.wait_for_timeout(2000)  # let page fully render

        # screenshot
        safe_domain = re.sub(r'[^\w\-.]', '_', domain)[:80]
        screenshot_path = os.path.join(SCREENSHOTS_DIR, f'{safe_domain}.png')
        await page.screenshot(path=screenshot_path, full_page=False)

        # collect info
        title = await page.title()
        final_url = page.url
        has_password = await page.query_selector('input[type="password"]')
        has_login = await page.query_selector('input[name*="user"], input[name*="email"], input[id*="user"], input[id*="email"]')

        result.update({
            'success': True,
            'screenshot_path': screenshot_path,
            'page_title': title,
            'has_login_form': has_login is not None,
            'has_password_field': has_password is not None,
            'final_url': final_url,
            'redirects': redirects
        })

        flags = []
        if has_password:   flags.append('PASSWORD FIELD')
        if has_login:      flags.append('LOGIN FORM')
        flag_str = ' *** ' + ', '.join(flags) if flags else ''
        print(f"  OK  | Title: {title[:50]}{flag_str}")

    except Exception as e:
        result['error'] = str(e)
        print(f"  SKIP | {str(e)[:60]}")

    # save result immediately
    with open(RESULTS_FILE, 'a') as f:
        f.write(json.dumps(result) + '\n')

    return result

async def main():
    suspects = load_suspects()
    if not suspects:
        return

    # filter out raw IP:port and other uncrawlable URLs
    crawlable = [s for s in suspects if is_crawlable(s['url'])]
    skipped   = len(suspects) - len(crawlable)

    print(f"="*55)
    print(f"Total suspects : {len(suspects)}")
    print(f"Crawlable URLs : {len(crawlable)}  (skipped {skipped} raw IPs)")
    print(f"Screenshots → : {SCREENSHOTS_DIR}")
    print(f"Results file  : {RESULTS_FILE}")
    print(f"="*55)

    if not crawlable:
        print("Nothing to crawl!")
        return

    success = 0
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        for i, suspect in enumerate(crawlable, 1):
            # fresh context per site for isolation
            ctx  = await browser.new_context(
                viewport={'width': 1280, 'height': 800},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            page = await ctx.new_page()
            result = await crawl_one(page, suspect, i, len(crawlable))
            await ctx.close()

            if result['success']:
                success += 1

            await asyncio.sleep(1)  # be polite, 1 sec between sites

    print(f"\n{'='*55}")
    print(f"Done! {success}/{len(crawlable)} sites successfully crawled")
    print(f"Screenshots saved in: {SCREENSHOTS_DIR}")
    print(f"\nNext step: python services\\classifier\\scorer.py")
    print(f"{'='*55}")

asyncio.run(main())
