import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

# Persistent Secret Key (Set SECRET_KEY in Render Environment Variables)
SECRET_KEY = os.environ.get("SECRET_KEY", "siduser_persistent_secret_key_2026_x99")

# Owner Access Credentials (Override in Render Environment Variables if desired)
OWNER_USER_ID = os.environ.get("OWNER_USER_ID", "8684812026")
OWNER_USERNAME = os.environ.get("OWNER_USERNAME", "sid")
OWNER_SECRET_KEY = os.environ.get("OWNER_SECRET_KEY", "sidd")

# Resource Limits
MAX_BOTS_PER_USER = int(os.environ.get("MAX_BOTS_PER_USER", 5))
PORT = int(os.environ.get("PORT", 5000))
