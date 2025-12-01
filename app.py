from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import abort

# ---------------------------------------------------------------------
# CONFIGURACIÓN BASE
# ---------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_secreto_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///visitas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ---------------------------------------------------------------------
# DECORADOR PARA ROLES
# ---------------------------------------------------------------------
def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user or not hasattr(current_user, 'role'):
                flash("No tiene permisos para acceder.", "danger")
                return redirect(url_for('index'))
            if current_user.role == role or current_user.role == 'superadmin':
                return f(*args, **kwargs)
            flash("No tiene permisos para acceder.", "danger")
            return redirect(url_for('index'))
        return wrapped
    return decorator


# ---------------------------------------------------------------------
# MODELOS
# ---------------------------------------------------------------------
class Site(db.Model):
    __tablename__ = 'site'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    ubicacion = db.Column(db.String(300))
    activo = db.Column(db.Boolean, default=True)


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    name = db.Column(db.String(200))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="oficial") 
    active = db.Column(db.Boolean, default=True)

    site_id = db.Column(db.Integer, db.ForeignKey('site.id'), nullable=True)
    site = db.relationship('Site', backref='users')


class Visitor(db.Model):
    __tablename__ = 'visitor'
    id = db.Column(db.Integer, primary(primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    cedula = db.Column(db.String(100))
    empresa = db.Column(db.String(200))
    placa = db.Column(db.String(100))
    persona_visitada = db.Column(db.String(200))
    proposito = db.Column(db.String(300))
    hora_entrada = db.Column(db.DateTime, default=datetime.utcnow)
    hora_salida = db.Column(db.DateTime, nullable=True)

    site_id = db.Column(db.Integer, db.ForeignKey('site.id'), nullable=True)
    site = db.relationship('Site', backref='visitantes')


# ---------------------------------------------------------------------
# LOGIN MANAGER
# ---------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------------------------------------------------
# LOGIN
# ---------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()

        if user and user.active and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Credenciales inválidas o usuario inactivo', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ---------------------------------------------------------------------
# DASHBOARD
# ---------------------------------------------------------------------
@app.route('/')
@login_required
def index():

    if current_user.role == 'superadmin':
        base_query = Visitor.query
    else:
        base_query = Visitor.query.filter_by(site_id=current_user.site_id)

    active_visitors_count = base_query.filter(Visitor.hora_salida.is_(None)).count()
    pending_count = active_visitors_count

    today = date.today()
    today_start = datetime.combine(today, datetime.min.time())
    today_count = base_query.filter(Visitor.hora_entrada >= today_start).count()
    total_today = today_count

    visitantes = base_query.order_by(Visitor.hora_entrada.desc()).limit(10).all()

    alertas = []
    visitantes_sin_salida = base_query.filter(Visitor.hora_salida.is_(None)).all()
    for v in visitantes_sin_salida:
        if v.hora_entrada:
            horas = (datetime.utcnow() - v.hora_entrada).total_seconds() / 3600
            if horas >= 8:
                alertas.append(f"⚠ {v.nombre} lleva más de {int(horas)} horas dentro de planta.")

    alertas_totales = len(alertas)

    sites = Site.query.order_by(Site.nombre).all()

    return render_template(
        'index.html',
        current_user=current_user,
        active_visitors_count=active_visitors_count,
        pending_count=pending_count,
        today_count=today_count,
        total_today=total_today,
        visitantes=visitantes,
        alertas=alertas,
        alertas_totales=alertas_totales,
        sites=sites
    )


# ---------------------------------------------------------------------
# REGISTRO DE VISITAS
# ---------------------------------------------------------------------
@app.route('/registrar', methods=['GET', 'POST'])
@login_required
def registrar():
    sites = Site.query.filter_by(activo=True).order_by(Site.nombre).all()

    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        if not nombre:
            flash('El nombre es obligatorio.', 'danger')
            return redirect(url_for('registrar'))

        if current_user.role == 'superadmin':
            chosen_site = request.form.get('site_id') or None
            site_id = int(chosen_site) if chosen_site else None
        else:
            site_id = current_user.site_id

        v = Visitor(
            nombre=nombre,
            cedula=request.form.get('cedula'),
            empresa=request.form.get('empresa'),
            placa=request.form.get('placa'),
            persona_visitada=request.form.get('persona'),
            proposito=request.form.get('proposito'),
            site_id=site_id
        )
        db.session.add(v)
        db.session.commit()
        flash('Visitante registrado con éxito', 'success')
        return redirect(url_for('index'))

    return render_template('registrar.html', sites=sites)


# ---------------------------------------------------------------------
# LISTAR VISITAS
# ---------------------------------------------------------------------
@app.route('/listar')
@login_required
def listar():
    if current_user.role == 'superadmin':
        visitantes = Visitor.query.order_by(Visitor.hora_entrada.desc()).all()
    else:
        visitantes = Visitor.query.filter_by(site_id=current_user.site_id).order_by(Visitor.hora_entrada.desc()).all()

    return render_template('listar.html', visitantes=visitantes)


# ---------------------------------------------------------------------
# REGISTRAR SALIDA
# ---------------------------------------------------------------------
@app.route('/salida/<int:visitor_id>', methods=['POST'])
@login_required
def registrar_salida(visitor_id):
    visitor = Visitor.query.get_or_404(visitor_id)

    if current_user.role != 'superadmin' and visitor.site_id != current_user.site_id:
        flash('No tiene permiso para registrar salida de este visitante.', 'danger')
        return redirect(url_for('listar'))

    if visitor.hora_salida is None:
        visitor.hora_salida = datetime.utcnow()
        db.session.commit()
        flash(f'Salida registrada para {visitor.nombre}', 'success')
    else:
        flash(f'La salida de {visitor.nombre} ya estaba registrada', 'warning')

    return redirect(url_for('listar'))


# ---------------------------------------------------------------------
# COMANDOS ADMINISTRATIVOS
# ---------------------------------------------------------------------
@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("✔ Base de datos creada.")


@app.cli.command("create-admin")
def create_admin():
    from getpass import getpass

    print("Crear usuario superadmin:")
    email = input("Email: ").strip().lower()
    name = input("Nombre: ").strip()
    password = getpass("Contraseña: ")

    user = User(
        email=email,
        name=name,
        password_hash=generate_password_hash(password),
        role="superadmin",
        active=True
    )
    db.session.add(user)
    db.session.commit()
    print("✔ Superadmin creado.")


@app.cli.command("create-default-site")
def create_default_site():
    if not Site.query.first():
        s = Site(nombre="Central", ubicacion="Sede principal", activo=True)
        db.session.add(s)
        db.session.commit()
        print("✔ Sitio Central creado.")
    else:
        print("Ya existen sitios en la base de datos.")


# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
