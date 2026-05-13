from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_required, logout_user, current_user
from app.auth import register_user, login_user_logic, setup_2fa, enable_2fa, disable_2fa
from app.rbac import role_required

auth_bp = Blueprint('auth', __name__, template_folder='../templates')


# ─── Login Page ──────────────────────────────────────────────
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('scanner.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        two_fa = request.form.get('two_fa', '').strip()

        success, result = login_user_logic(username, password, two_fa if two_fa else None)

        if success:
            flash(result, 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('scanner.dashboard'))
        else:
            flash(result, 'danger')

    return render_template('login.html')


# ─── Register Page ───────────────────────────────────────────
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('scanner.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if password != confirm:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')

        success, result = register_user(username, email, password)
        if success:
            flash(result, 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(result, 'danger')

    return render_template('register.html')


# ─── Logout ──────────────────────────────────────────────────
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


# ─── 2FA Setup ───────────────────────────────────────────────
@auth_bp.route('/2fa-setup', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if current_user.two_fa_enabled:
        flash('2FA is already enabled', 'warning')
        return redirect(url_for('auth.dashboard'))

    if request.method == 'POST':
        success, result = setup_2fa(current_user.id)
        if success:
            session['two_fa_secret'] = result['secret']
            session['two_fa_qr'] = result['qr_code']
            flash('Scan the QR code with your authenticator app, then enter a code to confirm.', 'success')
            return render_template('2fa_setup.html', qr_code=result['qr_code'])
        else:
            flash(result, 'danger')

    return render_template('2fa_setup.html')


# ─── Enable 2FA ──────────────────────────────────────────────
@auth_bp.route('/2fa-enable', methods=['POST'])
@login_required
def enable_2fa():
    token = request.form.get('token', '').strip()
    success, result = enable_2fa(current_user.id, token)

    if success:
        flash(result, 'success')
    else:
        flash(result, 'danger')

    return redirect(url_for('auth.dashboard'))


# ─── Disable 2FA ─────────────────────────────────────────────
@auth_bp.route('/2fa-disable', methods=['POST'])
@login_required
def disable_2fa():
    token = request.form.get('token', '').strip()
    success, result = disable_2fa(current_user.id, token)

    if success:
        flash(result, 'success')
    else:
        flash(result, 'danger')

    return redirect(url_for('auth.dashboard'))


# ─── Dashboard (protected) ───────────────────────────────────
@auth_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)
