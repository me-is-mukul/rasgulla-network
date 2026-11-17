from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from models import User
from auth import log_event, check_lockout, increment_failed_attempts, reset_failed_attempts
from extensions import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user:
            # Check lockout status
            can_login, message = check_lockout(user)
            if not can_login:
                flash(message, 'danger')
                return redirect(url_for('auth.login'))
            
            if user.check_password(password):
                reset_failed_attempts(user)
                login_user(user)
                log_event('login', f"User {username} logged in")
                return redirect(url_for('main.dashboard'))
            else:
                success, message = increment_failed_attempts(user)
                flash('Invalid password', 'danger')
                log_event('login_failed', f"Failed login attempt for {username}")
        else:
            flash('Invalid username', 'danger')
            log_event('login_failed', f"Failed login attempt for non-existent user {username}")
    
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('auth.register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('auth.register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        log_event('register', f"New user registered: {username}")
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    log_event('logout', f"User {current_user.username} logged out")
    logout_user()
    return redirect(url_for('main.index'))