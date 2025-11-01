from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask
from flask_qrcode import QRcode
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

from config import Config

db = SQLAlchemy()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",  # You can also pull this from Config
    default_limits=["200 per day", "50 per hour"] # Good idea to set defaults
)
def create_app():
    app = Flask(__name__)

    app.config.from_object(Config)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"
    db.init_app(app)
    csrf.init_app(app)
    QRcode(app)
    limiter.init_app(app)


    from .routes import main
    from app.models import User
    app.register_blueprint(main)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))



    return app

