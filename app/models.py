from pygments.lexer import default

from . import db  # <-- This is correct. It imports the 'db' object
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    locked_at = db.Column(db.DateTime, nullable=True, default=None)
    failed_attempts = db.Column(db.Integer,default = 0)
    secret =db.Column(db.String(128), default = None)

    def is_active(self):
        return not self.is_locked

    def commitDB(self):
        db.session.commit()