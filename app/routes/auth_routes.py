from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_required, logout_user, current_user
from app.auth import register_user, login_user_logic, setup_2fa as setup_2fa_auth, enable_2fa as enable_2fa_auth, disable_2fa as disable_2fa_auth, generate_qr_code
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

        # Check if user exists and password is correct first
        from app.models import User
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # If 2FA is enabled, require the token
            if user.two_fa_enabled:
                if not two_fa:
                    flash('2FA code required', 'warning')
                    return render_template('login.html', show_2fa=True, username=username)
                elif not user.verify_totp(two_fa):
                    flash('Invalid 2FA code', 'danger')
                    return render_template('login.html', show_2fa=True, username=username)
            
            # Login successful
            from flask_login import login_user
            login_user(user)
            flash('Login successful', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('scanner.dashboard'))
        else:
            flash('Invalid username or password', 'danger')

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

    # Generate QR code on GET request
    if request.method == 'GET':
        # Check if user already has a secret
        if current_user.totp_secret:
            # Use existing secret
            totp_uri = current_user.get_totp_uri()
            qr_code = generate_qr_code(totp_uri)
            secret = current_user.totp_secret
        else:
            # Generate new secret
            success, result = setup_2fa_auth(current_user.id)
            if success:
                qr_code = result['qr_code']
                secret = result['secret']
            else:
                flash(result, 'danger')
                return redirect(url_for('auth.dashboard'))
        
        session['two_fa_secret'] = secret
        session['two_fa_qr'] = qr_code
        return render_template('2fa_setup.html', qr_code=qr_code, secret=secret)

    # Handle POST request (enabling 2FA)
    if request.method == 'POST':
        success, result = enable_2fa_auth(current_user.id, request.form.get('token', '').strip())
        if success:
            flash(result, 'success')
            return redirect(url_for('auth.dashboard'))
        else:
            flash(result, 'danger')
            # Re-render with QR code from session
            return render_template('2fa_setup.html', 
                                 qr_code=session.get('two_fa_qr'), 
                                 secret=session.get('two_fa_secret'))


# ─── Enable 2FA ──────────────────────────────────────────────
@auth_bp.route('/2fa-enable', methods=['POST'])
@login_required
def enable_2fa():
    token = request.form.get('token', '').strip()
    success, result = enable_2fa_auth(current_user.id, token)

    if success:
        flash(result, 'success')
        # Clear session data
        session.pop('two_fa_secret', None)
        session.pop('two_fa_qr', None)
        return redirect(url_for('auth.dashboard'))
    else:
        flash(result, 'danger')
        return redirect(url_for('auth.setup_2fa'))


# ─── Disable 2FA ─────────────────────────────────────────────
@auth_bp.route('/2fa-disable', methods=['POST'])
@login_required
def disable_2fa():
    token = request.form.get('token', '').strip()
    success, result = disable_2fa_auth(current_user.id, token)

    if success:
        flash(result, 'success')
    else:
        flash(result, 'danger')

    return redirect(url_for('auth.dashboard'))


# ─── Dashboard (protected) ───────────────────────────────────
@auth_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('profile.html', user=current_user)
