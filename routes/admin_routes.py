from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_required, current_user
from models import User, Log, EncryptedFile
from auth import log_event
from extensions import db

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/panel')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('main.dashboard'))
    
    users = User.query.all()
    logs = Log.query.order_by(Log.event_time.desc()).limit(50).all()
    return render_template('admin_panel.html', users=users, logs=logs)

@admin_bp.route('/reset_password/<int:user_id>', methods=['POST'])
@login_required
def reset_password(user_id):
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('main.dashboard'))
    
    user = User.query.get_or_404(user_id)
    new_password = request.form.get('new_password')
    
    if not new_password:
        flash('New password is required', 'danger')
        return redirect(url_for('admin.admin_panel'))
    
    user.set_password(new_password)
    db.session.commit()
    
    log_event('password_reset', f"Admin {current_user.username} reset password for {user.username}")
    flash('Password reset successfully', 'success')
    return redirect(url_for('admin.admin_panel'))