from functools import wraps
from flask import abort, redirect, url_for, flash
from flask_login import current_user


def role_required(*roles):
    """Decorator: user must have at least one of the specified roles"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))

            if not any(current_user.has_role(r) for r in roles):
                abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def permission_required(perm):
    """Decorator: user must have a specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))

            if not current_user.has_permission(perm):
                abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ─── Permission Matrix ──────────────────────────────────────
# admin:    read, write, delete, scan, export
# analyst:  read, write, scan, export
# viewer:   read

PERMISSION_MATRIX = {
    'admin':    ['read', 'write', 'delete', 'scan', 'export'],
    'analyst':  ['read', 'write', 'scan', 'export'],
    'viewer':   ['read']
}
