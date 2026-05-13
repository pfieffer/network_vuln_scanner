from app import db, login_manager
from flask_login import UserMixin
from datetime import datetime
import bcrypt

# Association table: users <-> roles (many-to-many)
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)


class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.Column(db.PickleType, default=[])  # list of strings

    def __repr__(self):
        return f'<Role {self.name}>'

    def has_permission(self, perm):
        return perm in self.permissions


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    totp_secret = db.Column(db.String(32), nullable=True)  # 2FA secret
    two_fa_enabled = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    roles = db.relationship('Role', secondary=user_roles, backref=db.backref('users', lazy='dynamic'))
    scan_sessions = db.relationship('ScanSession', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def get_totp_uri(self):
        """Returns the otpauth:// URI for QR code generation"""
        import pyotp
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email,
            issuer_name='VulnScanner'
        )

    def verify_totp(self, token):
        import pyotp
        return pyotp.TOTP(self.totp_secret).verify(token)

    def has_role(self, role_name):
        return any(r.name == role_name for r in self.roles)

    def has_permission(self, perm):
        return any(r.has_permission(perm) for r in self.roles)

    def __repr__(self):
        return f'<User {self.username}>'


class ScanSession(db.Model):
    __tablename__ = 'scan_session'
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(256), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # 'port', 'service', 'tls', 'creds'
    results = db.Column(db.Text, nullable=True)  # JSON string
    severity = db.Column(db.String(20), nullable=True)  # 'critical', 'high', 'medium', 'low'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Scan {self.target} by {self.user.username}>'
