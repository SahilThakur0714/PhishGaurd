# # from sqlalchemy import Column, Integer, String, Float, DateTime
# # from sqlalchemy.orm import declarative_base
# # from datetime import datetime

# # Base = declarative_base()

# # class PhishSite(Base):
# #     """One row = one suspicious website we found"""
# #     __tablename__ = "phish_sites"
    
# #     id          = Column(Integer, primary_key=True)
# #     url         = Column(String)      # the fake website address
# #     domain      = Column(String)      # just the domain name
# #     risk_score  = Column(Float)       # 0.0 = safe, 1.0 = definitely phishing
# #     decision    = Column(String)      # 'phishing', 'safe', 'needs_review'
# #     brand       = Column(String)      # which brand it's pretending to be
# #     screenshot  = Column(String)      # path to the screenshot we took
# #     found_at    = Column(DateTime, default=datetime.utcnow)
# #     taken_down  = Column(String)      # 'yes', 'no', 'pending'


# from sqlalchemy import Column, Integer, String, Float, DateTime
# from sqlalchemy.orm import declarative_base
# from datetime import datetime

# Base = declarative_base()

# class PhishSite(Base):
#     __tablename__ = "phish_sites"

#     id          = Column(Integer, primary_key=True)
#     url         = Column(String)
#     domain      = Column(String)
#     risk_score  = Column(Float)
#     decision    = Column(String)
#     brand       = Column(String)
#     screenshot  = Column(String)
#     found_at    = Column(DateTime, default=datetime.utcnow)
#     taken_down  = Column(String, default="no")

from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone

Base = declarative_base()


class PhishSite(Base):
    __tablename__ = "phish_sites"

    id          = Column(Integer, primary_key=True)
    url         = Column(String,  nullable=False)
    domain      = Column(String)
    risk_score  = Column(Float)
    decision    = Column(String)   # PHISHING | NEEDS REVIEW | PROBABLY SAFE
    brand       = Column(String)
    screenshot  = Column(String)
    found_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    taken_down  = Column(String,   default="no")


class TakedownNotice(Base):
    __tablename__ = "takedown_notices"

    id          = Column(Integer, primary_key=True)
    url         = Column(String,  nullable=False)
    domain      = Column(String)
    risk_score  = Column(Float)
    looks_like  = Column(String)
    registrar   = Column(String)
    abuse_email = Column(String)
    notice_body = Column(Text)
    status      = Column(String,  default='pending')
    # pending | dry_run | sent | failed | no_contact | taken_down | still_live
    sent_at     = Column(DateTime)
    created_at  = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    notes       = Column(Text)