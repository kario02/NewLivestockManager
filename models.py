from app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class animal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    breed = db.Column(db.String(80), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    weight = db.Column(db.Float, nullable=False)

class Calf(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    calf_name = db.Column(db.String(255), nullable=False)
    calf_birth_date = db.Column(db.Date, nullable=False)
    calf_weight = db.Column(db.Float, nullable=False)
    dam_name = db.Column(db.String(255))  # Dam is the mother cow's name
    sire_name = db.Column(db.String(255))  # Sire is the father bull's name
