from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

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
    id = db.Column(db.Integer, primary_key=True)
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
# LOGIN
# ---------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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

    visitantes = base_query.order_by(Visitor.hora_entrada.desc()).limit(10).all()

    alertas = []
    visitantes_sin_salida = base_query.filter(Visitor.hora_salida.is_(None)).all()
    for v in visitantes_sin_salida:
        if v.hora_entrada:
            horas = (datetime.utcnow() - v.hora_entrada).total_seconds() / 3600
            if horas >= 8:
                alertas.append(f"⚠ {v.nombre} lleva más de {int(horas)} horas dentro del sitio.")

    sites = Site.query.order_by(Site.nombre).all()

    return render_template(
        'index.html',
        current_user=current_user,
        active_visitors_count=active_visitors_count,
        pending_count=pending_count,
        today_count=today_count,
        visitantes=visitantes,
        alertas=alertas,
        alertas_totales=len(alertas),
        sites=sites
    )


# ---------------------------------------------------------------------
# REGISTRAR VISITANTE
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
# LISTAR VISITANTES
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
        flash(f"Salida registrada para {visitor.nombre}", "success")
    else:
        flash("Este visitante ya tenía salida registrada.", "warning")

    return redirect(url_for('listar'))


# ---------------------------------------------------------------------
# REPORTES
# ---------------------------------------------------------------------
@app.route('/reports')
@login_required
def reports():
    nombre = request.args.get('nombre', '')
    empresa = request.args.get('empresa', '')
    desde = request.args.get('desde', '')
    hasta = request.args.get('hasta', '')
    site_filter = request.args.get('site', '')

    query = Visitor.query

    if current_user.role != 'superadmin':
        query = query.filter(Visitor.site_id == current_user.site_id)
    else:
        if site_filter:
            try:
                query = query.filter(Visitor.site_id == int(site_filter))
            except:
                pass

    if nombre:
        query = query.filter(Visitor.nombre.ilike(f"%{nombre}%"))
    if empresa:
        query = query.filter(Visitor.empresa.ilike(f"%{empresa}%"))
    if desde:
        try:
            query = query.filter(Visitor.hora_entrada >= datetime.fromisoformat(desde))
        except:
            flash("Fecha 'desde' inválida", "warning")
    if hasta:
        try:
            query = query.filter(Visitor.hora_entrada <= datetime.fromisoformat(hasta))
        except:
            flash("Fecha 'hasta' inválida", "warning")

    visitantes = query.order_by(Visitor.hora_entrada.desc()).all()
    sites = Site.query.order_by(Site.nombre).all()

    return render_template(
        'reports.html',
        visitantes=visitantes,
        nombre=nombre,
        empresa=empresa,
        desde=desde,
        hasta=hasta,
        sites=sites,
        site_filter=site_filter
    )


# ---------------------------------------------------------------------
# ADMINISTRACIÓN DE USUARIOS
# ---------------------------------------------------------------------
@app.route('/admin/users')
@login_required
@role_required("superadmin")
def admin_users():
    users = User.query.order_by(User.name.asc()).all()
    sites = Site.query.order_by(Site.nombre).all()
    return render_template('admin_users.html', users=users, sites=sites)


@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@role_required("superadmin")
def admin_user_create():
    sites = Site.query.order_by(Site.nombre).all()

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        nombre = request.form.get('name', '').strip()
        role = request.form.get('role', 'oficial')
        password = request.form.get('password', '')
        site_id = request.form.get('site_id') or None

        if not email or not nombre or not password:
            flash("Nombre, email y contraseña son obligatorios.", "danger")
            return redirect(url_for('admin_user_create'))

        if User.query.filter_by(email=email).first():
            flash("El correo ya existe.", "danger")
            return redirect(url_for('admin_user_create'))

        nuevo = User(
            email=email,
            name=nombre,
            role=role,
            password_hash=generate_password_hash(password),
            active=True,
            site_id=int(site_id) if site_id else None
        )
        db.session.add(nuevo)
        db.session.commit()

        flash("Usuario creado correctamente.", "success")
        return redirect(url_for('admin_users'))

    return render_template('admin_user_form.html', action='create', sites=sites, user=None)


@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required("superadmin")
def admin_user_edit(user_id):
    user = User.query.get_or_404(user_id)
    sites = Site.query.order_by(Site.nombre).all()

    if request.method == 'POST':
        user.email = request.form.get('email', user.email).strip().lower()
        user.name = request.form.get('name', user.name).strip()
        user.role = request.form.get('role', user.role)
        site_id = request.form.get('site_id') or None
        user.site_id = int(site_id) if site_id else None

        new_password = request.form.get('password', '')
        if new_password:
            user.password_hash = generate_password_hash(new_password)

        db.session.commit()

        flash("Usuario actualizado.", "success")
        return redirect(url_for('admin_users'))

    return render_template('admin_user_form.html', action='edit', user=user, sites=sites)


@app.route('/admin/users/toggle/<int:user_id>', methods=['POST'])
@login_required
@role_required("superadmin")
def admin_user_toggle(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("No puede desactivar su propio usuario.", "danger")
        return redirect(url_for('admin_users'))

    user.active = not user.active
    db.session.commit()

    flash("Estado actualizado.", "info")
    return redirect(url_for('admin_users'))


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required("superadmin")
def admin_user_delete(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("No puede eliminar su propio usuario.", "danger")
        return redirect(url_for('admin_users'))

    db.session.delete(user)
    db.session.commit()

    flash("Usuario eliminado.", "success")
    return redirect(url_for('admin_users'))


# ---------------------------------------------------------------------
# ADMINISTRACIÓN DE SITIOS
# ---------------------------------------------------------------------
@app.route('/admin/sites')
@login_required
@role_required("admin")
def admin_sites():
    sites = Site.query.order_by(Site.nombre).all()
    users = User.query.order_by(User.name).all()
    return render_template('admin_sites.html', sites=sites, users=users)


@app.route('/admin/sites/new', methods=['GET', 'POST'])
@login_required
@role_required("admin")
def admin_sites_new():
    users = User.query.order_by(User.name).all()

    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        ubicacion = request.form.get('ubicacion', '').strip()

        if not nombre:
            flash("El nombre es obligatorio.", "danger")
            return redirect(url_for('admin_sites_new'))

        nuevo = Site(nombre=nombre, ubicacion=ubicacion)
        db.session.add(nuevo)
        db.session.commit()

        flash("Sitio creado exitosamente.", "success")
        return redirect(url_for('admin_sites'))

    return render_template('admin_sites_new.html', users=users)


@app.route('/admin/sites/edit/<int:site_id>', methods=['GET', 'POST'])
@login_required
@role_required("admin")
def admin_sites_edit(site_id):
    sitio = Site.query.get_or_404(site_id)
    users = User.query.order_by(User.name).all()

    if request.method == 'POST':
        sitio.nombre = request.form.get('nombre', sitio.nombre).strip()
        sitio.ubicacion = request.form.get('ubicacion', sitio.ubicacion).strip()
        db.session.commit()

        flash("Sitio actualizado correctamente.", "success")
        return redirect(url_for('admin_sites'))

    return render_template('admin_sites_edit.html', site=sitio, users=users)


@app.route('/admin/sites/toggle/<int:site_id>', methods=['POST'])
@login_required
@role_required("admin")
def admin_sites_toggle(site_id):
    sitio = Site.query.get_or_404(site_id)
    sitio.activo = not sitio.activo
    db.session.commit()

    flash("Estado actualizado.", "info")
    return redirect(url_for('admin_sites'))


@app.route('/admin/sites/delete/<int:site_id>', methods=['POST'])
@login_required
@role_required("superadmin")
def admin_sites_delete(site_id):
    sitio = Site.query.get_or_404(site_id)
    db.session.delete(sitio)
    db.session.commit()

    flash("Sitio eliminado.", "danger")
    return redirect(url_for('admin_sites'))


# ---------------------------------------------------------------------
# CREACIÓN AUTOMÁTICA DEL SUPERADMIN Y SITIO CENTRAL
# ---------------------------------------------------------------------
with app.app_context():
    db.create_all()

    # Crear sitio Central
    central = Site.query.filter_by(nombre="Central").first()
    if not central:
        central = Site(nombre="Central", ubicacion="Sede Principal", activo=True)
        db.session.add(central)
        db.session.commit()
        print("✔ Sitio 'Central' creado.")

    # Crear superadmin
    admin_email = "jorgemolinabonilla@gmail.com"
    admin_password = "Jo70156938"

    superadmin = User.query.filter_by(email=admin_email).first()
    if not superadmin:
        superadmin = User(
            email=admin_email,
            name="Super Admin",
            password_hash=generate_password_hash(admin_password),
            role="superadmin",
            active=True,
            site_id=central.id
        )
        db.session.add(superadmin)
        db.session.commit()
        print("✔ Superadmin creado automáticamente.")
        print(f"Usuario: {admin_email}")
        print(f"Contraseña: {admin_password}")


# ---------------------------------------------------------------------
# RUN
# ---------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
