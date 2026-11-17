from extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='standard_user')  # 'admin' or 'standard_user'
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_time = db.Column(db.DateTime, nullable=True)
    otp_secret = db.Column(db.String(16), nullable=True)  # For OTP

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class EncryptedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    algorithm = db.Column(db.String(50), nullable=False)  # e.g., 'AES-256-CBC'
    hash_sha256 = db.Column(db.String(64), nullable=False)  # SHA-256 hash of original file
    is_stego = db.Column(db.Boolean, default=False)  # If hidden in an image
    unlock_time = db.Column(db.DateTime, nullable=True)  # For time-locked encryption
    otp_required = db.Column(db.Boolean, default=False)  # If OTP is required for decryption

    owner = db.relationship('User', backref=db.backref('encrypted_files', lazy=True))

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)  # e.g., 'login', 'encrypt', 'decrypt'
    event_time = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    details = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref=db.backref('logs', lazy=True))

class RecycleBin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    backup_filename = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    owner = db.relationship('User', backref=db.backref('recycle_bin_entries', lazy=True))