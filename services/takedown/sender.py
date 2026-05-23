import json
import os
import smtplib
import httpx
import asyncio
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from datetime import datetime

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR    = os.path.join(BASE_DIR, 'data')
SCORED_FILE = os.path.join(DATA_DIR, 'scored_results.jsonl')
LOG_FILE    = os.path.join(DATA_DIR, 'takedown_log.jsonl')

# ── EMAIL SETTINGS ──────────────────────────────────────
# Fill these in with your real Gmail details
# For Gmail: go to myaccount.google.com → Security → App Passwords
# Create an App Password and paste it below
SENDER_EMAIL = "halfbloodprince0714@gmail.com"
SENDER_PASS  = "fytg notq bvcn vpis"   # 16-char app password, NOT your Gmail password
DRY_RUN      = False    # ← Change to False when you're ready to send real emails
MIN_SCORE    = 30.0    # ← Lower threshold so we catch more sites
# ────────────────────────────────────────────────────────

TAKEDOWN_TEMPLATE = """
    Hello Abuse Team,

    We are writing to report a malicious website hosted on your infrastructure.

    REPORTED URL   : {url}
    DOMAIN         : {domain}
    RISK SCORE     : {risk_score}/100
    DETECTED AT    : {found_at}
    SIMILAR TO     : {looks_like}

    This website has been flagged by our automated phishing detection system
    as potentially fraudulent. A screenshot is attached as evidence.

    We kindly request that you investigate and suspend this domain/hosting
    account as soon as possible to protect users from potential harm.

    This report is submitted in good faith. Further evidence is available
    upon request.

    Thank you for your prompt attention.

    -- 
    Automated Phishing Detection System
    Reported: {found_at}
    """

KNOWN_ABUSE_CONTACTS = {
        'namecheap'  : 'abuse@namecheap.com',
        'godaddy'    : 'abuse@godaddy.com',
        'cloudflare' : 'abuse@cloudflare.com',
        'google'     : 'registrar-abuse@google.com',
        'hostgator'  : 'abuse@hostgator.com',
        'bluehost'   : 'abuse@bluehost.com',
        'siteground' : 'abuse@siteground.com',
        'digitalocean':'abuse@digitalocean.com',
        'ovh'        : 'abuse@ovh.net',
        'hetzner'    : 'abuse@hetzner.com',
    }


async def lookup_abuse_contact(domain: str) -> str:
        """Find the correct abuse contact for a domain"""
        clean_domain = domain.split(':')[0].lower()

        # these specific campaign domains are all Cloudflare-proxied
        # Cloudflare is both the CDN and already blocking them
        CLOUDFLARE_CAMPAIGNS = [
            'silver-dock.in.net',
            'thornbay.in.net',
            'cr4ftlane.in.net',
            'kinematicflowunit.in.net',
            'wavefrontgateway.in.net',
        ]
        for campaign in CLOUDFLARE_CAMPAIGNS:
            if campaign in clean_domain:
                print(f"  Cloudflare-proxied campaign domain → abuse@cloudflare.com")
                return 'abuse@cloudflare.com'

        # try RDAP for unknown domains
        try:
            async with httpx.AsyncClient(timeout=8) as c:
                # get just the root domain for RDAP lookup
                parts = clean_domain.split('.')
                root = '.'.join(parts[-2:]) if len(parts) >= 2 else clean_domain
                r = await c.get(f'https://rdap.org/domain/{root}')
                if r.status_code == 200:
                    data = r.json()
                    for entity in data.get('entities', []):
                        if 'abuse' in entity.get('roles', []):
                            vcard = entity.get('vcardArray', [None, []])[1]
                            for field in vcard:
                                if field[0] == 'email':
                                    email = field[3]
                                    print(f"  Found via RDAP: {email}")
                                    return email
        except Exception:
            pass

        # known registrar fallbacks
        for registrar, email in KNOWN_ABUSE_CONTACTS.items():
            if registrar in clean_domain:
                print(f"  Known registrar: {email}")
                return email

        # last resort — report to URLhaus since that's where we got these URLs
        print(f"  No contact found → reporting to URLhaus")
        return 'abuse@urlhaus.abuse.ch'

        # check known registrars
        domain_lower = clean_domain.lower()
        for registrar, email in KNOWN_ABUSE_CONTACTS.items():
            if registrar in domain_lower:
                print(f"  Using known registrar contact: {email}")
                return email

        # generic fallback
        # get the root domain (last two parts)
        parts = clean_domain.split('.')
        if len(parts) >= 2:
            root = '.'.join(parts[-2:])
            fallback = f'abuse@{root}'
        else:
            fallback = f'abuse@{clean_domain}'

        print(f"  Using generic fallback: {fallback}")
        return fallback

def send_email(to_email: str, subject: str, body: str, screenshot_path: str) -> bool:
        """Send the actual takedown email with screenshot attached"""
        try:
            msg = MIMEMultipart()
            msg['From']    = SENDER_EMAIL
            msg['To']      = to_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            # attach screenshot if it exists
            if screenshot_path and os.path.exists(screenshot_path):
                with open(screenshot_path, 'rb') as f:
                    img = MIMEImage(f.read())
                    img.add_header('Content-Disposition', 'attachment',
                                filename='evidence_screenshot.png')
                    msg.attach(img)
                print(f"  Screenshot attached: {os.path.basename(screenshot_path)}")
            else:
                print(f"  No screenshot found at: {screenshot_path}")

            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(SENDER_EMAIL, SENDER_PASS)
                server.send_message(msg)
            return True

        except Exception as e:
            print(f"  Email error: {e}")
            return False

def log_action(record: dict, abuse_email: str, sent: bool, dry_run: bool):
        """Save a record of every takedown attempt"""
        entry = {
            'url'         : record['url'],
            'domain'      : record['domain'],
            'risk_score'  : record['risk_score'],
            'abuse_email' : abuse_email,
            'sent'        : sent,
            'dry_run'     : dry_run,
            'timestamp'   : datetime.now().isoformat()
        }
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(entry) + '\n')

async def process_all():
        # load scored results
        if not os.path.exists(SCORED_FILE):
            print(f"No scored results found at {SCORED_FILE}")
            print("Run scorer.py first!")
            return

        sites = []
        with open(SCORED_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    sites.append(json.loads(line))

        # filter by minimum score
        targets = [s for s in sites if s['risk_score'] >= MIN_SCORE]
        skipped = len(sites) - len(targets)

        print("="*65)
        print(f"  PHISHING TAKEDOWN SENDER")
        print(f"  Mode      : {'DRY RUN (no emails sent)' if DRY_RUN else '*** LIVE — SENDING REAL EMAILS ***'}")
        print(f"  Min score : {MIN_SCORE}")
        print(f"  Total scored sites : {len(sites)}")
        print(f"  Above threshold    : {len(targets)}")
        print(f"  Below threshold    : {skipped} (skipped)")
        print("="*65)

        if not targets:
            print(f"\nNo sites above score {MIN_SCORE}.")
            print(f"Your highest scores were:")
            top = sorted(sites, key=lambda x: x['risk_score'], reverse=True)[:5]
            for s in top:
                print(f"  {s['risk_score']:5.1f}  {s['url'][:60]}")
            print(f"\nTip: Lower MIN_SCORE in sender.py (currently {MIN_SCORE})")
            return

        sent_count  = 0
        fail_count  = 0
        dry_count   = 0

        for i, site in enumerate(targets, 1):
            print(f"\n[{i}/{len(targets)}] Processing:")
            print(f"  URL   : {site['url'][:65]}")
            print(f"  Score : {site['risk_score']}/100  ({site['decision']})")
            if site.get('looks_like'):
                print(f"  Looks like: {site['looks_like']} ({site['visual_similarity']}% match)")

            # find abuse contact
            abuse_email = await lookup_abuse_contact(site['domain'])

            # build email content
            subject = f"Phishing/Malicious Site Report: {site['domain']}"
            body    = TAKEDOWN_TEMPLATE.format(
                url        = site['url'],
                domain     = site['domain'],
                risk_score = site['risk_score'],
                looks_like = site.get('looks_like') or 'Unknown',
                found_at   = datetime.now().strftime('%Y-%m-%d %H:%M UTC')
            )

            if DRY_RUN:
                # show what WOULD be sent
                print(f"\n  [DRY RUN] Would send to: {abuse_email}")
                print(f"  [DRY RUN] Subject: {subject}")
                print(f"  [DRY RUN] Email preview:")
                print("  " + "\n  ".join(body.strip().splitlines()[:8]))
                print(f"  [DRY RUN] Screenshot: {site.get('screenshot', 'none')}")
                log_action(site, abuse_email, sent=False, dry_run=True)
                dry_count += 1
            else:
                # actually send
                print(f"  Sending to: {abuse_email} ...")
                ok = send_email(
                    to_email        = abuse_email,
                    subject         = subject,
                    body            = body,
                    screenshot_path = site.get('screenshot')
                )
                log_action(site, abuse_email, sent=ok, dry_run=False)
                if ok:
                    print(f"  SENT!")
                    sent_count += 1
                else:
                    print(f"  FAILED — check SENDER_EMAIL and SENDER_PASS in sender.py")
                    fail_count += 1

            await asyncio.sleep(2)  # pause between emails to avoid spam filters

        # final summary
        print(f"\n{'='*65}")
        print(f"DONE!")
        if DRY_RUN:
            print(f"  Dry run complete — {dry_count} emails previewed, none sent")
            print(f"\n  To send real emails:")
            print(f"  1. Open services/takedown/sender.py")
            print(f"  2. Set SENDER_EMAIL = 'your-real-gmail@gmail.com'")
            print(f"  3. Set SENDER_PASS  = 'your-16-char-app-password'")
            print(f"  4. Set DRY_RUN = False")
            print(f"  5. Run again!")
        else:
            print(f"  Sent : {sent_count}")
            print(f"  Failed: {fail_count}")
        print(f"  Log saved to: {LOG_FILE}")
        print("="*65)

asyncio.run(process_all())
print("\nNext: python dashboard_server.py")