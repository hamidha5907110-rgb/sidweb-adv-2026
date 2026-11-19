import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

# Set these in Render -> Environment Variables
SECRET_KEY = os.environ.get("SECRET_KEY", "siduser_persistent_master_key_2026_x99")
OWNER_USER_ID = os.environ.get("OWNER_USER_ID", "8684812026")
OWNER_SECRET_KEY = os.environ.get("OWNER_SECRET_KEY", "sidd")

MAX_BOTS_PER_USER = int(os.environ.get("MAX_BOTS_PER_USER", 5))
PORT = int(os.environ.get("PORT", 5000))
