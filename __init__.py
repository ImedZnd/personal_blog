from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os
from flask_jwt_extended import JWTManager
from werkzeug.security import generate_password_hash
import logging

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    logging.basicConfig(level=logging.DEBUG)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
    CORS(app)
    db.init_app(app)
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
    jwt = JWTManager(app)

    from api.Blog.blog_routes import blogs
    app.register_blueprint(blogs)

    from api.User.user_model import User

    from api.Login.login_route import login
    app.register_blueprint(login)

    from api.Tag.tag_model import Tag
    with app.app_context():
        db.create_all()
        admin = User(email=ADMIN_USERNAME, password=ADMIN_PASSWORD)
        admin.password = generate_password_hash(admin.password, 'sha256', salt_length=12)
        db.session.add(admin)
        db.session.commit()

    return app
