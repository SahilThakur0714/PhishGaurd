# from pydantic_settings import BaseSettings

# class Settings(BaseSettings):
#     database_url: str = "postgresql://user:pass@localhost/phishdb"
#     redis_url: str = "redis://localhost:6379"
#     smtp_host: str = "smtp.gmail.com"
#     smtp_user: str = "your-email@gmail.com"
#     smtp_pass: str = "your-password"
#     sendgrid_key: str = ""
#     phishtank_key: str = ""

# settings = Settings()


from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str = "postgresql://user:pass@localhost:5432/phishdb"
    redis_url: str = "redis://localhost:6379"

settings = Settings()
