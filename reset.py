
import os
from app import create_app, db
from app.models import User
from flask_bcrypt import Bcrypt

db_path = 'instance/users.db'

if os.path.exists(db_path):
    os.remove(db_path)
    print("Existing database deleted.")

app = create_app()

with app.app_context():
    db.create_all()
    bcrypt = Bcrypt()
    if User.query.count() == 0:
        # Default users
        admin = User(username='admin', password=bcrypt.generate_password_hash('admin123').decode('utf-8'))
        user1 = User(username='user1', password=bcrypt.generate_password_hash('letmein').decode('utf-8'))
        user2 = User(username='user2', password=bcrypt.generate_password_hash('welcome123').decode('utf-8'))


        db.session.add_all([admin, user1, user2])
        db.session.commit()
        print("Seeded default users: admin, user1, user2")
