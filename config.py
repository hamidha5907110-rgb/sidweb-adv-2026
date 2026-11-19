import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

# Owner Access Credentials (Change before deploying)
OWNER_USERNAME = "sid"
OWNER_SECRET_KEY = "sidd"

# Resource Limits per Userbot Process
MAX_BOTS_PER_USER = 5
MAX_RAM_MB_PER_BOT = 350
