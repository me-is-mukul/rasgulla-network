from flask_login import current_user
from models import User, Log
from extensions import db
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from flask import current_app

def log_event(event_type, details=None, user_id=None, ip_address=None):
    if user_id is None and current_user.is_authenticated:
        user_id = current_user.id
    log = Log(
        user_id=user_id,
        event_type=event_type,
        details=details,
        ip_address=ip_address
    )
    db.session.add(log)
    db.session.commit()

def check_lockout(user):
    if user.lockout_time and user.lockout_time > datetime.utcnow():
        remaining_time = (user.lockout_time - datetime.utcnow()).seconds
        return False, f"Account locked. Try again in {remaining_time // 60} minutes."
    return True, ""

def increment_failed_attempts(user):
    user.failed_attempts += 1
    # Use the configured lockout threshold
    lockout_threshold = current_app.config.get('LOCKOUT_THRESHOLD', 5)
    if user.failed_attempts >= lockout_threshold:
        lockout_time = current_app.config.get('LOCKOUT_TIME', 300)
        user.lockout_time = datetime.utcnow() + timedelta(seconds=lockout_time)
        db.session.commit()
        log_event('lockout', f"User {user.username} locked out due to too many failed attempts")
        return False, f"Too many failed attempts. Account locked for {lockout_time // 60} minutes."
    db.session.commit()
    return True, ""

def reset_failed_attempts(user):
    user.failed_attempts = 0
    user.lockout_time = None
    db.session.commit()

def generate_otp_secret():
    return pyotp.random_base32()

def verify_otp(user, otp_token):
    if not user.otp_secret:
        return False
    totp = pyotp.TOTP(user.otp_secret)
    return totp.verify(otp_token)