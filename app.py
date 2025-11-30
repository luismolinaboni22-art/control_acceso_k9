from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Site, Visitor
from config import Config

app=Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

login=LoginManager(app)
login.login_view='login'

@login.user_loader
def load_user(uid):
    return User.query.get(int(uid))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        u=User.query.filter_by(email=request.form['email']).first()
        if u and check_password_hash(u.password_hash,request.form['password']):
            login_user(u)
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__=='__main__':
    with app.app_context():
        db.create_all()
    app.run()
