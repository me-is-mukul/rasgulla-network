"""
TCP File Transfer routes — web UI on top of tcp_transfer.py

Lets a user:
  * start / stop a TCP receiver (socket server) on this machine
  * send an encrypted file from their vault to another SafeCipher instance
  * view / download received files, or import them into their own vault
    (after which the existing vault "Decrypt" flow works unchanged)
"""

import os
import json
import shutil
import threading
from collections import deque
from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, current_app, abort
from flask_login import login_required, current_user

from models import EncryptedFile
from auth import log_event
from extensions import db
from tcp_transfer import (TCPFileReceiver, send_file as tcp_send_file, list_received, get_local_ip,
                          get_local_ips, parse_host_port, DEFAULT_PORT)

transfer_bp = Blueprint('transfer', __name__)

# ----------------------------------------------------------------------
# Process-wide receiver state (one TCP server per running app)
# ----------------------------------------------------------------------
_receiver = None
_receiver_lock = threading.Lock()
_activity = deque(maxlen=50)


def _log_activity(msg):
    _activity.appendleft(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def _received_dir():
    return os.path.abspath(current_app.config.get('RECEIVED_FOLDER', 'received_files'))


def _received_path(stored_name):
    """Resolve a received file safely (no path traversal)."""
    if stored_name != os.path.basename(stored_name) or not stored_name.startswith("recv_"):
        abort(404)
    path = os.path.join(_received_dir(), stored_name)
    if not os.path.exists(path):
        abort(404)
    return path


# ======================================================================
# MAIN PAGE
# ======================================================================
@transfer_bp.route('/')
@login_required
def transfer_page():
    files = EncryptedFile.query.filter_by(owner_id=current_user.id).all()
    return render_template(
        "tcp_transfer.html",
        files=files,
        receiver=_receiver if (_receiver and _receiver.running) else None,
        local_ip=get_local_ip(),
        local_ips=get_local_ips(),
        default_port=DEFAULT_PORT,
        received=list_received(_received_dir()),
        activity=list(_activity),
    )


# ======================================================================
# RECEIVER (SERVER) CONTROL
# ======================================================================
@transfer_bp.route('/receiver/start', methods=['POST'])
@login_required
def start_receiver():
    global _receiver
    try:
        port = int(request.form.get('port') or DEFAULT_PORT)
        if not (1024 <= port <= 65535):
            raise ValueError
    except ValueError:
        flash("Port must be a number between 1024 and 65535.", "danger")
        return redirect(url_for('transfer.transfer_page'))

    with _receiver_lock:
        if _receiver and _receiver.running:
            flash(f"Receiver already running on port {_receiver.port}.", "warning")
            return redirect(url_for('transfer.transfer_page'))
        try:
            _receiver = TCPFileReceiver("0.0.0.0", port, _received_dir(), on_event=_log_activity)
            _receiver.start()
        except OSError as e:
            _receiver = None
            flash(f"Could not start receiver on port {port}: {e}", "danger")
            return redirect(url_for('transfer.transfer_page'))

    log_event('tcp_receiver_start', f"TCP receiver started on port {port}", ip_address=request.remote_addr)
    flash(f"TCP receiver listening on {get_local_ip()}:{port}", "success")
    return redirect(url_for('transfer.transfer_page'))


@transfer_bp.route('/receiver/stop', methods=['POST'])
@login_required
def stop_receiver():
    global _receiver
    with _receiver_lock:
        if _receiver:
            _receiver.stop()
            _receiver = None
    log_event('tcp_receiver_stop', "TCP receiver stopped", ip_address=request.remote_addr)
    flash("TCP receiver stopped.", "success")
    return redirect(url_for('transfer.transfer_page'))


# ======================================================================
# SEND (CLIENT)
# ======================================================================
@transfer_bp.route('/send', methods=['POST'])
@login_required
def send_vault_file():
    file_id = request.form.get('file_id', type=int)
    # Accepts "192.168.1.5", "192.168.1.5:5001", "http://192.168.1.5:5001", "localhost"
    host, port = parse_host_port(request.form.get('host'),
                                 request.form.get('port', type=int) or DEFAULT_PORT)

    f = EncryptedFile.query.get_or_404(file_id)
    if f.owner_id != current_user.id and current_user.role != 'admin':
        flash("Unauthorized.", "danger")
        return redirect(url_for('transfer.transfer_page'))

    if not host:
        flash("Receiver host / IP is required.", "danger")
        return redirect(url_for('transfer.transfer_page'))

    path = os.path.join(current_app.config['ENCRYPTED_FOLDER'], f.encrypted_filename)
    if not os.path.exists(path):
        flash("Encrypted file is missing on disk.", "danger")
        return redirect(url_for('transfer.transfer_page'))

    # Metadata lets the receiver import the file into its own vault
    meta = {
        "original_filename": f.original_filename,
        "file_type": f.file_type,
        "algorithm": f.algorithm,
        "hash_sha256": f.hash_sha256,
        "is_stego": bool(f.is_stego),
        "unlock_time": f.unlock_time.isoformat() if f.unlock_time else None,
        "sent_by": current_user.username,
    }

    _log_activity(f"Connecting to {host}:{port} to send '{f.original_filename}'")
    try:
        result = tcp_send_file(path, host, port, meta=meta)
    except Exception as e:
        if isinstance(e, TimeoutError):
            e = "Receiver stopped responding during the transfer (timed out). Try again."
        elif isinstance(e, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            e = "Receiver closed the connection during the transfer (was it stopped?). Try again."
        _log_activity(f"Send to {host}:{port} failed: {e}")
        log_event('tcp_send_failed', f"{f.original_filename} -> {host}:{port}: {e}", ip_address=request.remote_addr)
        flash(f"Transfer failed: {e}", "danger")
        return redirect(url_for('transfer.transfer_page'))

    ok = result.get("status") == "OK"
    _log_activity(f"Sent {result.get('bytes_sent')} bytes to {host}:{port} - receiver says {result.get('status')}")
    log_event('tcp_send', f"{f.original_filename} -> {host}:{port} [{result.get('status')}]", ip_address=request.remote_addr)
    flash(
        f"{'Transfer complete' if ok else 'Transfer problem'}: {result.get('message')} "
        f"(SHA-256 {str(result.get('sha256'))[:16]}...)",
        "success" if ok else "danger",
    )
    return redirect(url_for('transfer.transfer_page'))


# ======================================================================
# RECEIVED FILES
# ======================================================================
@transfer_bp.route('/received/<path:stored_name>/download')
@login_required
def download_received(stored_name):
    path = _received_path(stored_name)
    return send_file(path, as_attachment=True, download_name=stored_name)


@transfer_bp.route('/received/<path:stored_name>/import', methods=['POST'])
@login_required
def import_received(stored_name):
    """Copy a received encrypted file into the current user's vault."""
    path = _received_path(stored_name)
    with open(path + ".meta.json", encoding="utf-8") as mf:
        info = json.load(mf)
    meta = info.get("meta") or {}

    encrypted_folder = current_app.config['ENCRYPTED_FOLDER']
    os.makedirs(encrypted_folder, exist_ok=True)
    shutil.copy2(path, os.path.join(encrypted_folder, stored_name))

    unlock_time = None
    if meta.get("unlock_time"):
        try:
            unlock_time = datetime.fromisoformat(meta["unlock_time"])
        except ValueError:
            pass

    entry = EncryptedFile(
        original_filename=meta.get("original_filename") or info["filename"],
        encrypted_filename=stored_name,
        file_size=os.path.getsize(path),
        file_type=meta.get("file_type") or "application/octet-stream",
        owner_id=current_user.id,
        algorithm=meta.get("algorithm") or "AES-256-CBC",
        hash_sha256=meta.get("hash_sha256") or info["sha256"],
        is_stego=bool(meta.get("is_stego")),
        unlock_time=unlock_time,
    )
    db.session.add(entry)
    db.session.commit()

    info["imported_by"] = current_user.username
    with open(path + ".meta.json", "w", encoding="utf-8") as mf:
        json.dump(info, mf, indent=2)

    log_event('tcp_import', f"Imported received file {stored_name} into vault", ip_address=request.remote_addr)
    flash("File imported into your vault. Use 'Decrypt' there with the sender's password.", "success")
    return redirect(url_for('file.my_vault'))


@transfer_bp.route('/received/<path:stored_name>/delete', methods=['POST'])
@login_required
def delete_received(stored_name):
    path = _received_path(stored_name)
    os.remove(path)
    if os.path.exists(path + ".meta.json"):
        os.remove(path + ".meta.json")
    flash("Received file deleted.", "success")
    return redirect(url_for('transfer.transfer_page'))
