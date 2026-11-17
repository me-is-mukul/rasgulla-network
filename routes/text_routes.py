from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, current_app
from flask_login import login_required
from crypto_utils import derive_key, encrypt_text, decrypt_text
import base64
import os

text_bp = Blueprint('text', __name__)


# ============================================================
# ENCRYPT TEXT
# ============================================================
@text_bp.route('/encrypt_text', methods=['GET', 'POST'])
@login_required
def encrypt_text_route():
    encrypted_text = None

    if request.method == 'POST':
        text = request.form.get('text')
        password = request.form.get('password')

        if not text or not password:
            flash("Text and password are required.", "danger")
            return redirect(url_for('text.encrypt_text_route'))

        # --- Generate salt ---
        salt = os.urandom(16)
        key = derive_key(password, salt)

        # --- Encrypt text ---
        ciphertext, iv = encrypt_text(text, key)

        # --- Prepare output ---
        encrypted_text = (
            f"SALT: {base64.b64encode(salt).decode()}\n"
            f"IV: {base64.b64encode(iv).decode()}\n"
            f"DATA: {base64.b64encode(ciphertext).decode()}"
        )

    return render_template("text_encrypt.html", encrypted_text=encrypted_text)


# ============================================================
# DOWNLOAD ENCRYPTED TEXT
# ============================================================
@text_bp.route('/download_encrypted_text', methods=['POST'])
@login_required
def download_encrypted_text():
    encrypted_text = request.form.get('encrypted_text')

    if not encrypted_text:
        flash("Nothing to download.", "danger")
        return redirect(url_for('text.encrypt_text_route'))

    path = os.path.join(current_app.config['UPLOAD_FOLDER'], "encrypted_text.txt")

    with open(path, 'w', encoding='utf-8') as f:
        f.write(encrypted_text)

    return send_file(path, as_attachment=True)


# ============================================================
# DECRYPT TEXT
# ============================================================
@text_bp.route('/decrypt_text', methods=['GET', 'POST'])
@login_required
def decrypt_text_route():
    decrypted_text = None

    if request.method == 'POST':
        encrypted_text = request.form.get('encrypted_text')
        password = request.form.get('password')

        if not encrypted_text or not password:
            flash("Encrypted text and password required.", "danger")
            return redirect(url_for('text.decrypt_text_route'))

        try:
            # Clean CRLF variations
            encrypted_text = encrypted_text.replace("\r", "")
            lines = [line.strip() for line in encrypted_text.split("\n")]

            salt_b64 = iv_b64 = data_b64 = None

            for line in lines:
                if line.startswith("SALT:"):
                    salt_b64 = line[5:].strip()
                elif line.startswith("IV:"):
                    iv_b64 = line[3:].strip()
                elif line.startswith("DATA:"):
                    data_b64 = line[5:].strip()

            if not salt_b64 or not iv_b64 or not data_b64:
                raise ValueError("Invalid encrypted text format.")

            salt = base64.b64decode(salt_b64)
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(data_b64)

            key = derive_key(password, salt)
            decrypted_text = decrypt_text(ciphertext, key, iv)

        except Exception as e:
            flash(f"Decryption failed: {str(e)}", "danger")
            return redirect(url_for('text.decrypt_text_route'))

    return render_template("text_decrypt.html", decrypted_text=decrypted_text)


# ============================================================
# DOWNLOAD DECRYPTED TEXT
# ============================================================
@text_bp.route('/download_decrypted_text', methods=['POST'])
@login_required
def download_decrypted_text():
    decrypted_text = request.form.get('decrypted_text')

    if not decrypted_text:
        flash("Nothing to download.", "danger")
        return redirect(url_for('text.decrypt_text_route'))

    path = os.path.join(current_app.config['UPLOAD_FOLDER'], "decrypted_text.txt")

    with open(path, 'w', encoding='utf-8') as f:
        f.write(decrypted_text)

    return send_file(path, as_attachment=True)
