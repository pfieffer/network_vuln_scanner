import click

from flask import Flask, redirect, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager


db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)

    # Import models and blueprints after extensions are initialized
    from app.models import User, Role
    from app.routes.auth_routes import auth_bp
    from app.routes.scanner_routes import scanner_bp
    app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanner.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(scanner_bp, url_prefix='/scan')

    @app.route('/')
    def index():
        return redirect(url_for('auth.login'))

    @app.errorhandler(403)
    def forbidden(e):
        """Handle 403 Forbidden errors."""
        return render_template('error.html',
                             error_code=403,
                             error_message='Access Denied',
                             error_description='You do not have permission to access this resource. This action requires elevated privileges.'), 403

    @app.errorhandler(404)
    def not_found(e):
        """Handle 404 Not Found errors."""
        return render_template('error.html',
                             error_code=404,
                             error_message='Page Not Found',
                             error_description='The resource you are looking for does not exist or has been removed.'), 404

    with app.app_context():
        db.create_all()
        for role_name, permissions in [
            ('admin',    ['read', 'write', 'delete', 'scan', 'export']),
            ('analyst',  ['read', 'write', 'scan', 'export']),
            ('viewer',   ['read'])
        ]:
            role = Role.query.filter_by(name=role_name).first()
            if role:
                role.permissions = permissions
            else:
                role = Role(name=role_name, permissions=permissions)
                db.session.add(role)
        db.session.commit()

        @app.cli.command('create-user')
        @click.option('--username', prompt=True, help='Username')
        @click.option('--email', prompt=True, help='Email')
        @click.option('--password', prompt=True, hide_input=True, help='Password')
        @click.option('--role', default='viewer', type=click.Choice(['admin', 'analyst', 'viewer']), help='Role')
        def create_user(username, email, password, role):
            """Create a new user with a specific role."""
            if User.query.filter_by(username=username).first():
                click.echo(f"❌ User '{username}' already exists!")
                return

            user = User(username=username, email=email)
            user.set_password(password)

            role_obj = Role.query.filter_by(name=role).first()
            if role_obj:
                user.roles.append(role_obj)
            else:
                click.echo(f"❌ Role '{role}' not found!")
                return

            db.session.add(user)
            db.session.commit()
            click.echo(f"✅ User '{username}' created with role '{role}'!")

        @app.cli.command('list-users')
        def list_users():
            """List all users and their roles."""
            users = User.query.all()
            click.echo("\n📋 All Users:")
            click.echo("-" * 50)
            for user in users:
                roles = ', '.join([r.name for r in user.roles])
                click.echo(f"  👤 {user.username:<20} 📧 {user.email:<30} 🏷️ [{roles}]")
            click.echo("-" * 50)

    return app
