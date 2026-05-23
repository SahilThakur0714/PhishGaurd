# PhishGaurd
Autonomous phishing detection &amp; takedown platform. Finds live phishing sites, screenshots them as evidence, scores them with ML, and auto-emails abuse contacts. Built with Python, FastAPI, Playwright, scikit-learn &amp; Docker.
# PhishGuard — Autonomous Phishing Detection & Takedown Platform

An end-to-end cybersecurity pipeline that autonomously detects live 
phishing websites and sends evidence-based takedown notices to hosting 
providers — no human intervention required.

## What it does

| Stage | Script | What happens |
|-------|--------|-------------|
| Ingest | `ct_watcher.py` | Pulls live malicious URLs from URLhaus, OpenPhish & certificate streams |
| Crawl | `screenshot.py` | Visits each URL with headless Chrome, takes a screenshot, detects login forms |
| Score | `scorer.py` | Fuses visual similarity + URL features + page analysis into a 0–100 risk score |
| Takedown | `sender.py` | Looks up abuse contact via RDAP, emails takedown notice with screenshot evidence |

## Results from first live run

- 50 malicious URLs collected in under 5 seconds
- 18 sites crawled and screenshotted with evidence  
- 21 confirmed phishing sites (independently verified by Cloudflare)
- 46 takedown notices sent to abuse@cloudflare.com

## Tech stack

- **Language** — Python 3.11
- **Web API** — FastAPI + Uvicorn
- **Browser automation** — Playwright (headless Chromium)
- **ML models** — scikit-learn (Gradient Boosting + Logistic Regression)
- **Visual detection** — imagehash (perceptual hashing / pHash)
- **Database** — PostgreSQL via SQLAlchemy
- **Cache** — Redis (Bloom filter + Celery broker)
- **Infrastructure** — Docker Compose
- **Threat feeds** — URLhaus, OpenPhish, PhishStats, CertStream
- **Abuse lookup** — RDAP API (rdap.org)
- **Intel export** — STIX 2.1
- **Dashboard** — FastAPI + Vanilla JS/HTML/CSS

## How the scoring works
risk_score = (visual_similarity × 0.45)
+ (url_suspicion     × 0.35)
+ (page_analysis     × 0.20)
≥ 65  →  Auto takedown
35–64 →  Analyst review
< 35  →  Probably safe

Visual detection uses perceptual hashing — screenshots of suspicious 
sites are compared against reference fingerprints of 8 real brand 
login pages (Google, Microsoft, PayPal, Amazon, Facebook, Apple, 
Netflix, Instagram).

## Quick start

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/phishing-platform.git
cd phishing-platform

# 2. Install dependencies
pip install playwright httpx redis sqlalchemy fastapi uvicorn \
  imagehash scikit-learn kafka-python dnstwist python-whois stix2 \
  celery pillow pydantic-settings
playwright install chromium

# 3. Start the database
docker-compose up -d

# 4. Set up the database tables
python setup_db.py

# 5. Run the full pipeline
python services\ingest\ct_watcher.py      # collect URLs
python services\crawler\screenshot.py     # crawl & screenshot
python services\classifier\scorer.py      # score with AI
python services\takedown\sender.py        # send takedowns

# 6. Open the dashboard
python dashboard_server.py
# → http://localhost:8000
```

## Project structure
phishing-platform/
├── services/
│   ├── ingest/          # URL collection from threat feeds
│   ├── crawler/         # Headless browser crawling
│   ├── classifier/      # ML scoring engine
│   └── takedown/        # Abuse contact lookup & email
├── shared/              # Config, database models
├── data/                # JSONL data files & screenshots
├── dashboard_server.py  # FastAPI backend + dashboard
├── dashboard.html       # Live web UI
└── docker-compose.yml   # PostgreSQL + Redis containers

## Inspiration

Built on methodology from the 
[Cambridge Cybercrime Centre](https://www.cl.cam.ac.uk/~jac22/pubs/2021-raid-phishing.pdf) 
phishing research on detection lifecycles and takedown automation.

## ⚠️ Legal notice

This tool is for educational and defensive security research only. 
Only report sites you have independently verified as malicious. 
Always include evidence with abuse reports. The author is not 
responsible for misuse.
