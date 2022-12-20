from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class Adverts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.Text, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    type = db.Column(db.Text, nullable=False)
    contact = db.Column(db.Integer, nullable=False)



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(300))
    firstName = db.Column(db.String(150))