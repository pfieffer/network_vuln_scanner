import pyotp
import qrcode
import io
import base64
from flask import session, redirect, url_for, flash, render_template, request
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, Role


def generate_totp_secret():
    """Generate a new TOTP secret for 2FA"""
    return pyotp.random_base32()


def generate_qr_code(totp_uri):
    """Generate a QR code image as base64 string"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"


# ─── Registration ────────────────────────────────────────────
def register_user(username, email, password):
    if User.query.filter_by(username=username).first():
        return False, "Username already exists"
    if User.query.filter_by(email=email).first():
        return False, "Email already exists"

    user = User(username=username, email=email)
    user.set_password(password)

    viewer_role = Role.query.filter_by(name='viewer').first()
    if viewer_role:
        user.roles.append(viewer_role)

    db.session.add(user)
    db.session.commit()
    return True, "Registration successful"


# ─── Login ───────────────────────────────────────────────────
def login_user_logic(username, password, two_fa_token=None):
    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return False, "Invalid username or password"

    if not user.is_active:
        return False, "Account is disabled"

    # 2FA check
    if user.two_fa_enabled:
        if not two_fa_token:
            return False, "2FA required"
        if not user.verify_totp(two_fa_token):
            return False, "Invalid 2FA token"

    login_user(user)
    return True, "Login successful"


# ─── 2FA Setup ───────────────────────────────────────────────
def setup_2fa(user_id):
    user = User.query.get(user_id)
    if not user:
        return False, "User not found"

    secret = generate_totp_secret()
    user.totp_secret = secret
    db.session.commit()

    totp_uri = user.get_totp_uri()
    qr_code = generate_qr_code(totp_uri)

    return True, {
        'secret': secret,
        'qr_code': qr_code,
        'totp_uri': totp_uri
    }


def enable_2fa(user_id, token):
    user = User.query.get(user_id)
    if not user:
        return False, "User not found"

    if not user.verify_totp(token):
        return False, "Invalid token"

    user.two_fa_enabled = True
    db.session.commit()
    return True, "2FA enabled successfully"


def disable_2fa(user_id, token):
    user = User.query.get(user_id)
    if not user:
        return False, "User not found"

    if not user.verify_totp(token):
        return False, "Invalid token"

    user.two_fa_enabled = False
    user.totp_secret = None
    db.session.commit()
    return True, "2FA disabled"
