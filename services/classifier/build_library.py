import asyncio
import os
import json
import imagehash
from PIL import Image
from playwright.async_api import async_playwright

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(BASE_DIR, 'data')
LIBRARY_DIR = os.path.join(DATA_DIR, 'brand_library')
os.makedirs(LIBRARY_DIR, exist_ok=True)

REAL_SITES = {
    'google':    'https://accounts.google.com',
    'microsoft': 'https://login.microsoft.com',
    'facebook':  'https://www.facebook.com/login',
    'amazon':    'https://www.amazon.com/ap/signin',
    'paypal':    'https://www.paypal.com/signin',
    'apple':     'https://appleid.apple.com',
    'netflix':   'https://www.netflix.com/login',
    'instagram': 'https://www.instagram.com/accounts/login',
}

async def main():
    print("="*55)
    print("Building brand fingerprint library...")
    print("This visits the REAL login pages to get reference screenshots")
    print("="*55)

    library = {}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        for brand, url in REAL_SITES.items():
            print(f"\nFingerprinting {brand}...")
            print(f"  URL: {url}")

            ctx  = await browser.new_context(
                viewport={'width': 1280, 'height': 800},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            page = await ctx.new_page()

            try:
                await page.goto(url, timeout=15000, wait_until='domcontentloaded')
                await page.wait_for_timeout(2000)

                screenshot_path = os.path.join(LIBRARY_DIR, f'{brand}.png')
                await page.screenshot(path=screenshot_path)

                img         = Image.open(screenshot_path)
                fingerprint = str(imagehash.phash(img))
                library[brand] = fingerprint

                print(f"  Done! Fingerprint: {fingerprint[:16]}...")

            except Exception as e:
                print(f"  Skipped ({str(e)[:50]})")

            await ctx.close()
            await asyncio.sleep(1)

        await browser.close()

    # save fingerprints
    output_path = os.path.join(LIBRARY_DIR, 'fingerprints.json')
    with open(output_path, 'w') as f:
        json.dump(library, f, indent=2)

    print(f"\n{'='*55}")
    print(f"Library saved! {len(library)} brands fingerprinted")
    print(f"File: {output_path}")
    print(f"\nNext step: python services\\classifier\\scorer.py")
    print(f"{'='*55}")

asyncio.run(main())