from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Site, Visitor
from config import Config

# ------------------------------
# Inicializar app
# ------------------------------
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

# ------------------------------
# Login Manager
# ------------------------------
login_manager = LoginManager(app)
login_manager.login_view = 'login_view'

@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))

# ------------------------------
# Rutas principales
# ------------------------------
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login_view():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

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

# ------------------------------
# Rutas del panel / dashboard
# ------------------------------
@app.route('/registrar', methods=['GET', 'POST'])
@login_required
def registrar():
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        cedula = request.form.get('cedula', '').strip()
        empresa = request.form.get('empresa', '').strip()
        placa = request.form.get('placa', '').strip()
        persona_visitada = request.form.get('persona_visitada', '').strip()
        proposito = request.form.get('proposito', '').strip()

        if not nombre or not cedula:
            flash("Nombre y cédula son obligatorios", "danger")
            return redirect(url_for('registrar'))

        visitante = Visitor(
            nombre=nombre,
            cedula=cedula,
            empresa=empresa,
            placa=placa,
            persona_visitada=persona_visitada,
            proposito=proposito
        )
        db.session.add(visitante)
        db.session.commit()
        flash("Visitante registrado correctamente", "success")
        return redirect(url_for('listar'))

    return render_template('registrar.html')

@app.route('/listar')
@login_required
def listar():
    visitantes = Visitor.query.all()
    return render_template('listar.html', visitantes=visitantes)

@app.route('/admin/users')
@login_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/sites')
@login_required
def admin_sites():
    sites = Site.query.all()
    return render_template('admin_sites.html', sites=sites)

@app.route('/reports')
@login_required
def reports():
    visitantes = Visitor.query.all()
    return render_template('reports.html', visitantes=visitantes)

# ------------------------------
# Crear base de datos y superadmin
# ------------------------------
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





