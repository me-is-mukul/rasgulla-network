from flask import Flask
from config import Config
from extensions import db, login_manager
from datetime import timezone


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # User loader callback for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        from models import User
        return User.query.get(int(user_id))

    # Import blueprints
    from routes.auth_routes import auth_bp
    from routes.main_routes import main_bp
    from routes.file_routes import file_bp
    from routes.text_routes import text_bp
    from routes.admin_routes import admin_bp
    from routes.transfer_routes import transfer_bp

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(main_bp)
    app.register_blueprint(file_bp, url_prefix='/files')
    app.register_blueprint(text_bp, url_prefix='/text')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(transfer_bp, url_prefix='/transfer')

    # Create tables and admin user
    with app.app_context():
        from models import User, EncryptedFile, Log, RecycleBin
        db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@example.com', role='admin')
            admin.set_password('admin123')  # Change this in production
            db.session.add(admin)
            db.session.commit()

                # Jinja filter to convert UTC → Local time
    @app.template_filter('localtime')
    def localtime(value):
        return value.replace(tzinfo=timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M')


    return app

app = create_app()




if __name__ == '__main__':
    app.run(debug=True)