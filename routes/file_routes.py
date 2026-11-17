from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, current_app
from flask_login import login_required, current_user
from models import EncryptedFile, RecycleBin
from auth import log_event
from crypto_utils import encrypt_file, decrypt_file, derive_key, decrypt_text, compute_sha256
from stego_utils import hide_data_in_image, extract_data_from_image
from extensions import db
from datetime import datetime
import os
import shutil
import mimetypes
from PIL import Image
import base64

file_bp = Blueprint('file', __name__)


# ======================================================================
# ENCRYPT FILE
# ======================================================================
@file_bp.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt_file_route():
    if request.method == 'POST':

        file = request.files.get('file')
        password = request.form.get('password')
        stego_mode = request.form.get('stego_mode') == 'on'
        cover_image = request.files.get('cover_image') if stego_mode else None
        unlock_time_str = request.form.get('unlock_time')
        otp_required = request.form.get('otp_required') == 'on'

        if not file or not password:
            flash("File and password required.", "danger")
            return redirect(url_for('file.encrypt_file_route'))

        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)

        temp_path = os.path.join(upload_folder, file.filename)
        file.save(temp_path)

        recycle_folder = current_app.config['RECYCLE_BIN_FOLDER']
        os.makedirs(recycle_folder, exist_ok=True)

        backup_name = f"backup_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
        backup_path = os.path.join(recycle_folder, backup_name)
        shutil.copy2(temp_path, backup_path)

        recycle_entry = RecycleBin(
            original_filename=file.filename,
            backup_filename=backup_name,
            owner_id=current_user.id
        )
        db.session.add(recycle_entry)

        file_hash = compute_sha256(temp_path)
        salt = os.urandom(16)
        key = derive_key(password, salt)

        encrypted_folder = current_app.config['ENCRYPTED_FOLDER']
        os.makedirs(encrypted_folder, exist_ok=True)

        encrypted_name = f"encrypted_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
        encrypted_path = os.path.join(encrypted_folder, encrypted_name)

        unlock_time = None
        if unlock_time_str:
            unlock_time = datetime.strptime(unlock_time_str, "%Y-%m-%dT%H:%M")

        try:
            encrypt_file(temp_path, encrypted_path, key, salt, unlock_time)
        except Exception as e:
            flash(f"Encryption failed: {e}", "danger")
            return redirect(url_for('file.encrypt_file_route'))

        if stego_mode:
            if not cover_image:
                flash("Cover image required in stego mode.", "danger")
                return redirect(url_for('file.encrypt_file_route'))

            cover_temp = os.path.join(upload_folder, cover_image.filename)

            img = Image.open(cover_image)
            png_cover = cover_temp + ".png"
            img.save(png_cover, format="PNG")
            cover_temp = png_cover

            stego_name = f"stego_{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
            stego_path = os.path.join(encrypted_folder, stego_name)

            try:
                with open(encrypted_path, "rb") as f:
                    hidden_data = f.read()

                hide_data_in_image(cover_temp, hidden_data, stego_path)

                os.remove(encrypted_path)
                encrypted_path = stego_path
                encrypted_name = stego_name

            except Exception as e:
                flash(f"Stego embed failed: {e}", "danger")
                return redirect(url_for('file.encrypt_file_route'))

        file_type = mimetypes.guess_type(file.filename)[0] or "application/octet-stream"
        file_size = os.path.getsize(encrypted_path)

        entry = EncryptedFile(
            original_filename=file.filename,
            encrypted_filename=encrypted_name,
            file_size=file_size,
            file_type=file_type,
            owner_id=current_user.id,
            algorithm="AES-256-CBC",
            hash_sha256=file_hash,
            is_stego=stego_mode,
            unlock_time=unlock_time,
            otp_required=otp_required
        )

        db.session.add(entry)
        db.session.commit()

        os.remove(temp_path)
        flash("File encrypted successfully.", "success")
        return redirect(url_for('file.my_vault'))

    return render_template("encrypt_file.html")


# ======================================================================
# MY VAULT
# ======================================================================
@file_bp.route('/my_vault')
@login_required
def my_vault():
    files = EncryptedFile.query.filter_by(owner_id=current_user.id).all()
    return render_template("my_vault.html", files=files)


# ======================================================================
# DELETE FILE
# ======================================================================
@file_bp.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    f = EncryptedFile.query.get_or_404(file_id)

    if f.owner_id != current_user.id and current_user.role != 'admin':
        flash("Unauthorized.", "danger")
        return redirect(url_for('file.my_vault'))

    encrypted_path = os.path.join(current_app.config['ENCRYPTED_FOLDER'], f.encrypted_filename)

    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)

    db.session.delete(f)
    db.session.commit()

    flash("File deleted.", "success")
    return redirect(url_for("file.my_vault"))


# ======================================================================
# DECRYPT FROM VAULT
# ======================================================================
@file_bp.route('/decrypt/<int:file_id>', methods=['GET', 'POST'])
@login_required
def decrypt_file_route(file_id):
    f = EncryptedFile.query.get_or_404(file_id)

    if f.owner_id != current_user.id and current_user.role != 'admin':
        flash("Unauthorized.", "danger")
        return redirect(url_for('file.my_vault'))

    if request.method == 'POST':
        password = request.form.get('password')

        encrypted_path = os.path.join(current_app.config['ENCRYPTED_FOLDER'], f.encrypted_filename)

        if f.is_stego:
            try:
                extracted = extract_data_from_image(encrypted_path)
                temp = encrypted_path + "_temp.bin"
                with open(temp, "wb") as fp:
                    fp.write(extracted)
                encrypted_path = temp
            except Exception as e:
                flash(f"Stego extraction failed: {e}", "danger")
                return redirect(url_for("file.my_vault"))

        with open(encrypted_path, "rb") as fp:
            salt = fp.read(16)

        key = derive_key(password, salt)

        decrypted_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(decrypted_folder, exist_ok=True)

        output_path = os.path.join(decrypted_folder, f"decrypted_{f.original_filename}")

        try:
            decrypt_file(encrypted_path, output_path, key)
        except Exception as e:
            flash(f"Decryption failed: {e}", "danger")
            return redirect(url_for("file.my_vault"))

        return send_file(output_path, as_attachment=True)

    return render_template("decrypt_file.html", file=f)


# ======================================================================
# DOWNLOAD ENCRYPTED FILE
# ======================================================================
@file_bp.route('/download/<int:file_id>')
@login_required
def download_encrypted_file(file_id):
    f = EncryptedFile.query.get_or_404(file_id)

    if f.owner_id != current_user.id and current_user.role != 'admin':
        flash("Unauthorized.", "danger")
        return redirect(url_for('file.my_vault'))

    path = os.path.join(current_app.config['ENCRYPTED_FOLDER'], f.encrypted_filename)

    return send_file(path, as_attachment=True, download_name=f.encrypted_filename)


# ======================================================================
# RECYCLE BIN
# ======================================================================
@file_bp.route('/recycle_bin')
@login_required
def recycle_bin():
    entries = RecycleBin.query.filter_by(owner_id=current_user.id).all()
    return render_template("recycle_bin.html", entries=entries)


@file_bp.route('/recycle_bin/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_recycle_entry(entry_id):
    entry = RecycleBin.query.get_or_404(entry_id)

    if entry.owner_id != current_user.id and current_user.role != 'admin':
        flash("Unauthorized.", "danger")
        return redirect(url_for('file.recycle_bin'))

    path = os.path.join(current_app.config['RECYCLE_BIN_FOLDER'], entry.backup_filename)

    if os.path.exists(path):
        os.remove(path)

    db.session.delete(entry)
    db.session.commit()

    flash("Entry deleted.", "success")
    return redirect(url_for("file.recycle_bin"))


# ======================================================================
# DECRYPT UPLOADED FILE (TEXT / PNG / AES BINARY)
# ======================================================================
@file_bp.route('/decrypt_uploaded', methods=['GET', 'POST'])
@login_required
def decrypt_uploaded_file():
    if request.method == 'POST':

        file = request.files.get('file')
        password = request.form.get('password')
        file_type = request.form.get('file_type')

        if not file or not password:
            flash("File + password required.", "danger")
            return redirect(url_for('file.decrypt_uploaded_file'))

        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)

        temp_path = os.path.join(upload_folder, file.filename)
        file.save(temp_path)

        decrypted_path = os.path.join(upload_folder, f"decrypted_{file.filename}")

        # -----------------------------------------------------
        # 1) BINARY AES FILE (WITH TIME-LOCK)
        # -----------------------------------------------------
        if file_type == "binary":
            try:
                with open(temp_path, "rb") as fp:
                    salt = fp.read(16)

                key = derive_key(password, salt)
                decrypt_file(temp_path, decrypted_path, key)
                return send_file(decrypted_path, as_attachment=True)

            except Exception as e:
                flash(f"Binary decrypt failed: {e}", "danger")
                return redirect(url_for("file.decrypt_uploaded_file"))

        # -----------------------------------------------------
        # 2) TXT DECRYPT (FIXED FORMAT)
        # -----------------------------------------------------
        if file_type == "txt":
            try:
                with open(temp_path, 'r', encoding='utf-8') as fp:
                    text = fp.read().replace("\r", "")

                lines = [line.strip() for line in text.split("\n")]

                salt_b64 = iv_b64 = data_b64 = None

                for line in lines:
                    if line.startswith("SALT:"):
                        salt_b64 = line[5:].strip()
                    elif line.startswith("IV:"):
                        iv_b64 = line[3:].strip()
                    elif line.startswith("DATA:"):
                        data_b64 = line[5:].strip()

                if not salt_b64 or not iv_b64 or not data_b64:
                    raise ValueError("Invalid TXT format")

                salt = base64.b64decode(salt_b64)
                iv = base64.b64decode(iv_b64)
                data = base64.b64decode(data_b64)

                key = derive_key(password, salt)
                plaintext = decrypt_text(data, key, iv)

                with open(decrypted_path, "w", encoding="utf-8") as fp:
                    fp.write(plaintext)

                return send_file(decrypted_path, as_attachment=True)

            except Exception as e:
                flash(f"TXT decrypt failed: {e}", "danger")
                return redirect(url_for("file.decrypt_uploaded_file"))

        # -----------------------------------------------------
        # 3) PNG STEGO (NO TIME-LOCK FOR OPTION A)
        # -----------------------------------------------------
        if file_type == "png":
            try:
                Image.open(temp_path)

                extracted = extract_data_from_image(temp_path)
                extracted_temp = temp_path + "_data.bin"

                with open(extracted_temp, "wb") as fp:
                    fp.write(extracted)

                with open(extracted_temp, "rb") as fp:
                    salt = fp.read(16)

                key = derive_key(password, salt)
                decrypt_file(extracted_temp, decrypted_path, key)

                return send_file(decrypted_path, as_attachment=True)

            except Exception as e:
                flash(f"Stego decrypt failed: {e}", "danger")
                return redirect(url_for("file.decrypt_uploaded_file"))

    return render_template("decrypt_uploaded_file.html")
