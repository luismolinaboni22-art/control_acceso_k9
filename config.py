import os
class Config:
    SECRET_KEY=os.getenv("SECRET_KEY","devkey")
    SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL","sqlite:///visitas.db")
    SQLALCHEMY_TRACK_MODIFICATIONS=False
