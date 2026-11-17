import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///safecipher.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'uploads'
    ENCRYPTED_FOLDER = 'encrypted_files'
    RECYCLE_BIN_FOLDER = 'recycle_bin'
    LOG_FOLDER = 'logs'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max file size
    LOCKOUT_THRESHOLD = 5  # Number of failed attempts before lockout
    LOCKOUT_TIME = 300  # Lockout time in seconds (5 minutes)