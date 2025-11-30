from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db=SQLAlchemy()

class Site(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(200),unique=True,nullable=False)
    active=db.Column(db.Boolean,default=True)

class User(UserMixin,db.Model):
    id=db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String(200),unique=True,nullable=False)
    name=db.Column(db.String(200))
    password_hash=db.Column(db.String(255),nullable=False)
    role=db.Column(db.String(50),default="oficial")
    site_id=db.Column(db.Integer,db.ForeignKey('site.id'))
    active=db.Column(db.Boolean,default=True)

class Visitor(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    nombre=db.Column(db.String(200),nullable=False)
    cedula=db.Column(db.String(100))
    empresa=db.Column(db.String(200))
    placa=db.Column(db.String(100))
    persona=db.Column(db.String(200))
    proposito=db.Column(db.String(300))
    hora_entrada=db.Column(db.DateTime,default=datetime.utcnow)
    hora_salida=db.Column(db.DateTime)
    sitio_id=db.Column(db.Integer,db.ForeignKey('site.id'))
    registrado_por=db.Column(db.Integer,db.ForeignKey('user.id'))
