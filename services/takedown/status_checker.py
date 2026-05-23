"""
services/takedown/status_checker.py
────────────────────────────────────
Polls every site in takedown_notices table to see if it's still live.
Updates status: sent → taken_down | still_live

Usage:
    python services/takedown/status_checker.py
    python services/takedown/status_checker.py --all      # check all, not just 'sent'
"""

import os
import sys
import time
import argparse
import requests
from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://user:pass@localhost:5432/phishdb')

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; PhishMonitor/1.0; +https://yourorg.com/bot)'
}

def is_site_live(url: str, timeout: int = 10) -> tuple[bool, int]:
    """Returns (is_live, http_status_code)."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout,
                         allow_redirects=True, verify=False)
        # 200-399: still alive; 4xx/5xx: likely down
        return r.status_code < 400, r.status_code
    except requests.exceptions.ConnectionError:
        return False, 0
    except requests.exceptions.Timeout:
        return True, -1    # timeout = probably still up, just slow
    except Exception:
        return False, -2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--all', action='store_true',
                        help='Check all notices, not just sent ones')
    args = parser.parse_args()

    # import here so the module can run even without full package install
    try:
        from services.takedown.sender import TakedownNotice, Base
    except ImportError:
        # fallback: define inline
        from sqlalchemy import Column, Integer, String, Float, DateTime, Text
        from sqlalchemy.orm import declarative_base
        Base = declarative_base()
        class TakedownNotice(Base):
            __tablename__ = 'takedown_notices'
            id          = Column(Integer, primary_key=True)
            url         = Column(String)
            domain      = Column(String)
            risk_score  = Column(Float)
            looks_like  = Column(String)
            registrar   = Column(String)
            abuse_email = Column(String)
            notice_body = Column(Text)
            status      = Column(String, default='pending')
            sent_at     = Column(DateTime)
            created_at  = Column(DateTime)
            notes       = Column(Text)

    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        query = session.query(TakedownNotice)
        if not args.all:
            query = query.filter(TakedownNotice.status == 'sent')
        notices = query.all()

    if not notices:
        filter_desc = 'all statuses' if args.all else "status='sent'"
        print(f"No notices found ({filter_desc}). Nothing to check.")
        return

    print("=" * 65)
    print(f"  TAKEDOWN STATUS CHECKER  —  {len(notices)} sites")
    print("=" * 65 + "\n")

    still_live   = []
    taken_down   = []
    errors       = []

    with Session(engine) as session:
        for notice in notices:
            print(f"Checking: {notice.url[:60]}")
            live, code = is_site_live(notice.url)

            if live:
                status_str = f"STILL LIVE  (HTTP {code})"
                still_live.append(notice.url)
                notice.status = 'still_live'
            else:
                if code == 0:
                    status_str = "DOWN  (connection refused / DNS failed)"
                elif code == -1:
                    status_str = "TIMEOUT  (may still be live)"
                    still_live.append(notice.url)
                else:
                    status_str = f"DOWN  (HTTP {code})"
                if code not in (-1,):
                    taken_down.append(notice.url)
                    notice.status = 'taken_down'

            notice.notes = (notice.notes or '') + \
                f"\n[{datetime.now(timezone.utc).isoformat()}] check: {status_str}"
            print(f"  → {status_str}\n")

            try:
                session.merge(notice)
                session.commit()
            except Exception as e:
                session.rollback()
                errors.append(notice.url)
                print(f"  [DB] Write error: {e}")

            time.sleep(0.5)

    print("=" * 65)
    print("STATUS CHECK SUMMARY")
    print(f"  Still live   : {len(still_live)}")
    print(f"  Taken down   : {len(taken_down)}")
    print(f"  DB errors    : {len(errors)}")
    print("=" * 65)

    if still_live:
        print(f"\nSites still live — consider escalating to ICANN or upstream provider:")
        for u in still_live:
            print(f"  {u}")


if __name__ == '__main__':
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()