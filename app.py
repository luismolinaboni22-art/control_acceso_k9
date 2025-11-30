from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Site, Visitor
from config import Config

# ---------------------------------------------------------
# INICIALIZAR APP
# ---------------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

# ---------------------------------------------------------
# LOGIN MANAGER
# ---------------------------------------------------------
login_manager = LoginManager(app)
login_manager.login_view = 'login_view'  # coincide con el nombre de la función login

@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))

# ---------------------------------------------------------
# RUTAS
# ---------------------------------------------------------
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login_view():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # Validación para evitar errores SQL
        if not email or not password:
            flash("Debe ingresar correo y contraseña", "danger")
            return redirect(url_for('login_view'))

        u = User.query.filter_by(email=email).first()

        if u and check_password_hash(u.password_hash, password):
            login_user(u)
            return redirect(url_for('index'))

        flash("Credenciales inválidas", "danger")
        return redirect(url_for('login_view'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login_view'))

# ---------------------------------------------------------
# CREAR BASE DE DATOS Y SUPERADMIN (SE EJECUTA UNA SOLA VEZ EN RENDER)
# ---------------------------------------------------------
with app.app_context():
    db.create_all()

    # Crear superadmin si no existe
    if not User.query.filter_by(email='jorgemolinabonilla@gmail.com').first():
        u = User(
            email='jorgemolinabonilla@gmail.com',
            name='Super Admin',
            role='superadmin'
        )
        u.password_hash = generate_password_hash('Cambio123!')
        db.session.add(u)
        db.session.commit()
        print("Superadmin creado")


