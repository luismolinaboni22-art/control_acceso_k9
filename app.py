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
            # permiso si es el rol solicitado o superadmin
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

    # relaciones (backrefs definidos en User y Visitor)


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    name = db.Column(db.String(200))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="oficial")  # oficial / admin / superadmin
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
# DASHBOARD PRINCIPAL (filtrado por sitio si no es superadmin)
# ---------------------------------------------------------------------
@app.route('/')
@login_required
def index():
    # seleccionar base_query según rol / sitio
    if current_user.role == 'superadmin':
        base_query = Visitor.query
    else:
        base_query = Visitor.query.filter_by(site_id=current_user.site_id)

    # contadores
    active_visitors_count = base_query.filter(Visitor.hora_salida.is_(None)).count()
    pending_count = active_visitors_count

    today = date.today()
    today_start = datetime.combine(today, datetime.min.time())
    today_count = base_query.filter(Visitor.hora_entrada >= today_start).count()
    total_today = today_count

    # últimos visitantes (limit 10)
    visitantes = base_query.order_by(Visitor.hora_entrada.desc()).limit(10).all()

    # alertas (ejemplo: > 8 horas dentro)
    alertas = []
    visitantes_sin_salida = base_query.filter(Visitor.hora_salida.is_(None)).all()
    for v in visitantes_sin_salida:
        if v.hora_entrada:
            horas = (datetime.utcnow() - v.hora_entrada).total_seconds() / 3600
            if horas >= 8:
                alertas.append(f"⚠ {v.nombre} lleva más de {int(horas)} horas dentro de planta.")

    alertas_totales = len(alertas)

    # lista de sites (para superadmin en el dashboard si se quiere filtrar)
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
# REGISTRO DE VISITANTES (asocia site_id del usuario, o permite elegir si superadmin)
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

        # si el usuario es superadmin, permitimos elegir site_id en el form (campo opcional 'site_id')
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
# LISTADO DE VISITANTES (filtrado por sitio para roles no-superadmin)
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

    # permiso: si no es superadmin y el visitante no pertenece al sitio del user -> bloquear
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
# API DE VISITANTES ACTIVOS (filtrado por sitio)
# ---------------------------------------------------------------------
@app.route('/api/visitantes/activos')
@login_required
def api_visitantes_activos():
    if current_user.role == 'superadmin':
        visitantes = Visitor.query.order_by(Visitor.hora_entrada.desc()).all()
    else:
        visitantes = Visitor.query.filter_by(site_id=current_user.site_id).order_by(Visitor.hora_entrada.desc()).all()

    visitantes_data = [{
        'id': v.id,
        'nombre': v.nombre,
        'hora_entrada': v.hora_entrada.strftime('%Y-%m-%d %H:%M:%S'),
        'hora_salida': v.hora_salida.strftime('%Y-%m-%d %H:%M:%S') if v.hora_salida else None,
        'site': v.site.nombre if v.site else None
    } for v in visitantes]

    return jsonify({'visitantes': visitantes_data})


# ---------------------------------------------------------------------
# REPORTES (filtros y reporte por sitio)
# ---------------------------------------------------------------------
@app.route('/reports', methods=['GET'])
@login_required
def reports():
    nombre = request.args.get('nombre', '')
    empresa = request.args.get('empresa', '')
    desde = request.args.get('desde', '')
    hasta = request.args.get('hasta', '')
    site_filter = request.args.get('site', '')

    query = Visitor.query

    # si no es superadmin, forzamos filtro por su sitio
    if current_user.role != 'superadmin':
        query = query.filter(Visitor.site_id == current_user.site_id)
    else:
        # si superadmin y se pidió site, aplicarlo
        if site_filter:
            try:
                sid = int(site_filter)
                query = query.filter(Visitor.site_id == sid)
            except ValueError:
                pass

    if nombre:
        query = query.filter(Visitor.nombre.ilike(f'%{nombre}%'))
    if empresa:
        query = query.filter(Visitor.empresa.ilike(f'%{empresa}%'))

    if desde:
        try:
            query = query.filter(Visitor.hora_entrada >= datetime.fromisoformat(desde))
        except Exception:
            flash('Formato de fecha "desde" inválido', 'warning')

    if hasta:
        try:
            query = query.filter(Visitor.hora_entrada <= datetime.fromisoformat(hasta))
        except Exception:
            flash('Formato de fecha "hasta" inválido', 'warning')

    visitantes = query.order_by(Visitor.hora_entrada.desc()).all()
    sites = Site.query.order_by(Site.nombre).all()
    return render_template('reports.html',
                           visitantes=visitantes,
                           nombre=nombre,
                           empresa=empresa,
                           desde=desde,
                           hasta=hasta,
                           sites=sites,
                           site_filter=site_filter)


# ---------------------------------------------------------------------
# ADMINISTRACIÓN DE USUARIOS (CRUD) -> con asignación de sitio
# ---------------------------------------------------------------------
@app.route('/admin/users')
@login_required
@role_required('superadmin')
def admin_users():
    users = User.query.order_by(User.name.asc()).all()
    sites = Site.query.order_by(Site.nombre).all()
    return render_template('admin_users.html', users=users, sites=sites)


@app.route('/admin/users/create', methods=['GET', 'POST'])
@login_required
@role_required('superadmin')
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
            flash("El correo ya está registrado.", "danger")
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
@role_required('superadmin')
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
@role_required('superadmin')
def admin_user_toggle(user_id):
    user = User.query.get_or_404(user_id)
    # evitar desactivar al propio
    if user.id == current_user.id:
        flash("No puede desactivar su propio usuario.", "danger")
        return redirect(url_for('admin_users'))
    user.active = not user.active
    db.session.commit()
    estado = "activado" if user.active else "desactivado"
    flash(f"Usuario {estado}.", "info")
    return redirect(url_for('admin_users'))


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required('superadmin')
def admin_user_delete(user_id):
    user = User.query.get_or_404(user_id)
    # evitar eliminar al propio
    if user.id == current_user.id:
        flash("No puede eliminar su propio usuario.", "danger")
        return redirect(url_for('admin_users'))
    db.session.delete(user)
    db.session.commit()
    flash("Usuario eliminado correctamente.", "success")
    return redirect(url_for('admin_users'))


# ---------------------------------------------------------------------
# ADMIN – SITIOS (CRUD)
# ---------------------------------------------------------------------
@app.route('/admin/sites')
@login_required
@role_required('admin')
def admin_sites():
    sites = Site.query.order_by(Site.nombre).all()
    users = User.query.order_by(User.name).all()
    return render_template('admin_sites.html', sites=sites, users=users)


@app.route('/admin/sites/new', methods=['GET', 'POST'])
@login_required
@role_required('admin')
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
        flash("Sitio creado exitosamente", "success")
        return redirect(url_for('admin_sites'))
    return render_template('admin_sites_new.html', users=users)


@app.route('/admin/sites/edit/<int:site_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin_sites_edit(site_id):
    sitio = Site.query.get_or_404(site_id)
    users = User.query.order_by(User.name).all()
    if request.method == 'POST':
        sitio.nombre = request.form.get('nombre', sitio.nombre).strip()
        sitio.ubicacion = request.form.get('ubicacion', sitio.ubicacion).strip()
        db.session.commit()
        flash("Sitio actualizado correctamente", "success")
        return redirect(url_for('admin_sites'))
    return render_template('admin_sites_edit.html', site=sitio, users=users)


@app.route('/admin/sites/toggle/<int:site_id>', methods=['POST'])
@login_required
@role_required('admin')
def admin_sites_toggle(site_id):
    sitio = Site.query.get_or_404(site_id)
    sitio.activo = not sitio.activo
    db.session.commit()
    flash("Estado actualizado", "info")
    return redirect(url_for('admin_sites'))


@app.route('/admin/sites/delete/<int:site_id>', methods=['POST'])
@login_required
@role_required('superadmin')
def admin_sites_delete(site_id):
    sitio = Site.query.get_or_404(site_id)
    db.session.delete(sitio)
    db.session.commit()
    flash("Sitio eliminado", "danger")
    return redirect(url_for('admin_sites'))


# ---------------------------------------------------------------------
# INICIALIZAR DB Y CREAR SUPER ADMIN + SITIO POR DEFECTO SI NO EXISTEN
# ---------------------------------------------------------------------
with app.app_context():
    db.create_all()
    # crear un sitio por defecto si no hay ninguno
    default_site = Site.query.filter_by(nombre="Central").first()
    if not default_site:
        default_site = Site(nombre="Central", ubicacion="Sede principal", activo=True)
        db.session.add(default_site)
        db.session.commit()

    # crear superadmin si no existe y asignarle sitio 'Central' por defecto
    if not User.query.filter_by(email="jorgemolinabonilla@gmail.com").first():
        super_user = User(
            email="jorgemolinabonilla@gmail.com",
            name="Super Admin",
            password_hash=generate_password_hash("Cambio123!"),
            role="superadmin",
            active=True,
            site_id=default_site.id
        )
        db.session.add(super_user)
        db.session.commit()


if __name__ == '__main__':
    app.run(debug=True)
