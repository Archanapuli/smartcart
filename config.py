# config.py
# ------------------------------------
# This file holds all configurations
# like Secret Key, Database connection
# details, Email settings, Razorpay keys etc.
# ------------------------------------

SECRET_KEY = "abc123"   # used for sessions

# MySQL Database Configuration
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = "root"  # keep empty if no password
DB_NAME = "smartcart_db"

# Email SMTP Settings
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'archanapuli57@gmail.com'
MAIL_PASSWORD = 'hcvr idav oupr bwjl'
MAIL_DEFAULT_SENDER = 'archanapuli57@gmail.com'

RAZORPAY_KEY_ID = "rzp_test_SFhtKUOMTDREaR"
RAZORPAY_KEY_SECRET = "EBOGrtMk2UO4aK0ZqnYDpBJQ"



