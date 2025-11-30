from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
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

            if current_user.role == role or current_user.role == 'superadmin':
                return f(*args, **kwargs)

            flash("No tiene permisos para acceder.", "danger")
            return redirect(url_for('index'))
        return wrapped
    return decorator

# ---------------------------------------------------------------------
# MODELOS
# ---------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    name = db.Column(db.String(200))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="oficial")  # oficial / admin / superadmin
    active = db.Column(db.Boolean, default=True)

class Visitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    cedula = db.Column(db.String(100))
    empresa = db.Column(db.String(200))
    placa = db.Column(db.String(100))
    persona_visitada = db.Column(db.String(200))
    proposito = db.Column(db.String(300))
    hora_entrada = db.Column(db.DateTime, default=datetime.utcnow)
    hora_salida = db.Column(db.DateTime, nullable=True)

# ---------------------------------------------------------------------
# LOGIN
# ---------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))

        flash('Credenciales inválidas', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------------------------------------------------------------------
# DASHBOARD PRINCIPAL
# ---------------------------------------------------------------------
@app.route('/')
@login_required
def index():

    active_visitors_count = Visitor.query.filter_by(hora_salida=None).count()

    pending_count = Visitor.query.filter(
        Visitor.hora_salida.is_(None)
    ).count()

    today = date.today()
    today_start = datetime.combine(today, datetime.min.time())

    today_count = Visitor.query.filter(
        Visitor.hora_entrada >= today_start
    ).count()

    total_today = today_count

    visitantes = Visitor.query.order_by(Visitor.hora_entrada.desc()).limit(10).all()

    # ============================================================
    # SISTEMA DE ALERTAS
    # ============================================================
    alertas = []

    visitantes_sin_salida = Visitor.query.filter(
        Visitor.hora_salida.is_(None)
    ).all()

    for v in visitantes_sin_salida:
        horas = (datetime.utcnow() - v.hora_entrada).total_seconds() / 3600
        if horas >= 8:
            alertas.append(f"⚠ {v.nombre} lleva más de {int(horas)} horas dentro de planta.")

    alertas_totales = len(alertas)

    return render_template(
        'index.html',
        current_user=current_user,
        active_visitors_count=active_visitors_count,
        pending_count=pending_count,
        today_count=today_count,
        total_today=total_today,
        visitantes=visitantes,
        alertas=alertas,
        alertas_totales=alertas_totales
    )

# ---------------------------------------------------------------------
# REGISTRO DE VISITANTES
# ---------------------------------------------------------------------
@app.route('/registrar', methods=['GET','POST'])
@login_required
def registrar():
    if request.method == 'POST':
        v = Visitor(
            nombre=request.form['nombre'],
            cedula=request.form.get('cedula'),
            empresa=request.form.get('empresa'),
            placa=request.form.get('placa'),
            persona_visitada=request.form.get('persona'),
            proposito=request.form.get('proposito')
        )
        db.session.add(v)
        db.session.commit()
        flash('Visitante registrado con éxito', 'success')
        return redirect(url_for('index'))

    return render_template('registrar.html')

# ---------------------------------------------------------------------
# LISTADO DE VISITANTES
# ---------------------------------------------------------------------
@app.route('/listar')
@login_required
def listar():
    visitantes = Visitor.query.order_by(Visitor.hora_entrada.desc()).all()
    return render_template('listar.html', visitantes=visitantes)

# ---------------------------------------------------------------------
# REGISTRAR SALIDA
# ---------------------------------------------------------------------
@app.route('/salida/<int:visitor_id>', methods=['POST'])
@login_required
def registrar_salida(visitor_id):
    visitor = Visitor.query.get_or_404(visitor_id)

    if visitor.hora_salida is None:
        visitor.hora_salida = datetime.utcnow()
        db.session.commit()
        flash(f'Salida registrada para {visitor.nombre}', 'success')
    else:
        flash(f'La salida de {visitor.nombre} ya estaba registrada', 'warning')

    return redirect(url_for('listar'))

# ---------------------------------------------------------------------
# API DE VISITANTES ACTIVOS
# ---------------------------------------------------------------------
@app.route('/api/visitantes/activos')
@login_required
def api_visitantes_activos():
    count = Visitor.query.filter_by(hora_salida=None).count()
    visitantes = Visitor.query.order_by(Visitor.hora_entrada.desc()).all()

    visitantes_data = [{
        'id': v.id,
        'nombre': v.nombre,
        'hora_salida': v.hora_salida.strftime('%Y-%m-%d %H:%M:%S') if v.hora_salida else None
    } for v in visitantes]

    return jsonify({'active_count': count, 'visitantes': visitantes_data})

# ---------------------------------------------------------------------
# REPORTES
# ---------------------------------------------------------------------
@app.route('/reports', methods=['GET'])
@login_required
def reports():

    nombre = request.args.get('nombre', '')
    empresa = request.args.get('empresa', '')
    desde = request.args.get('desde', '')
    hasta = request.args.get('hasta', '')

    query = Visitor.query

    if nombre:
        query = query.filter(Visitor.nombre.ilike(f'%{nombre}%'))
    if empresa:
        query = query.filter(Visitor.empresa.ilike(f'%{empresa}%'))
    if desde:
        query = query.filter(Visitor.hora_entrada >= datetime.fromisoformat(desde))
    if hasta:
        query = query.filter(Visitor.hora_entrada <= datetime.fromisoformat(hasta))

    visitantes = query.order_by(Visitor.hora_entrada.desc()).all()

    return render_template('reports.html',
                           visitantes=visitantes,
                           nombre=nombre,
                           empresa=empresa,
                           desde=desde,
                           hasta=hasta)

# ---------------------------------------------------------------------
# ADMINISTRACIÓN
# ---------------------------------------------------------------------
@app.route('/admin/users')
@login_required
@role_required('superadmin')
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/sites')
@login_required
@role_required('admin')
def admin_sites():
    return "Sitios"

@app.route('/admin/configuracion')
@login_required
@role_required('admin')
def admin_configuracion():
    return "Configuración"

# ---------------------------------------------------------------------
# CREAR SUPER ADMIN SI NO EXISTE
# ---------------------------------------------------------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email="jorgemolinabonilla@gmail.com").first():
        super_user = User(
            email="jorgemolinabonilla@gmail.com",
            name="Super Admin",
            password_hash=generate_password_hash("Cambio123!"),
            role="superadmin"
        )
        db.session.add(super_user)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
