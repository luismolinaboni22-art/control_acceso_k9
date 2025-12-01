from flask import Flask, render_template, redirect, url_for, request, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
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

# -----------------------------
# DECORADORES
# -----------------------------
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

# -----------------------------
# MODELOS
# -----------------------------
class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    ubicacion = db.Column(db.String(300))
    activo = db.Column(db.Boolean, default=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    name = db.Column(db.String(200))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="oficial")
    active = db.Column(db.Boolean, default=True)
    site_id = db.Column(db.Integer, db.ForeignKey('site.id'), nullable=True)
    site = db.relationship('Site', backref='users')

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
    site_id = db.Column(db.Integer, db.ForeignKey('site.id'), nullable=True)
    site = db.relationship('Site', backref='visitantes')

# -----------------------------
# LOGIN
# -----------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        user = User.query.filter_by(email=email).first()
        if user and user.active and check_password_hash(user.password_hash,password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Credenciales inválidas o usuario inactivo','danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# -----------------------------
# DASHBOARD
# -----------------------------
@app.route('/')
@login_required
def index():
    base_query = Visitor.query if current_user.role=='superadmin' else Visitor.query.filter_by(site_id=current_user.site_id)
    active_visitors_count = base_query.filter(Visitor.hora_salida.is_(None)).count()
    today_start = datetime.combine(date.today(), datetime.min.time())
    total_today = base_query.filter(Visitor.hora_entrada>=today_start).count()
    visitantes = base_query.order_by(Visitor.hora_entrada.desc()).limit(10).all()
    return render_template('index.html',
                           visitantes=visitantes,
                           active_visitors_count=active_visitors_count,
                           today_count=total_today,
                           total_today=total_today)

# -----------------------------
# REGISTRAR VISITANTES
# -----------------------------
@app.route('/registrar', methods=['GET','POST'])
@login_required
def registrar():
    sites = Site.query.filter_by(activo=True).order_by(Site.nombre).all()
    if request.method=='POST':
        nombre = request.form.get('nombre','').strip()
        if not nombre:
            flash('El nombre es obligatorio','danger')
            return redirect(url_for('registrar'))
        site_id = int(request.form.get('site_id')) if current_user.role=='superadmin' and request.form.get('site_id') else current_user.site_id
        visitor = Visitor(
            nombre=nombre,
            cedula=request.form.get('cedula'),
            empresa=request.form.get('empresa'),
            placa=request.form.get('placa'),
            persona_visitada=request.form.get('persona'),
            proposito=request.form.get('proposito'),
            site_id=site_id
        )
        db.session.add(visitor)
        db.session.commit()
        flash('Visitante registrado con éxito','success')
        return redirect(url_for('index'))
    return render_template('registrar.html', sites=sites)

# -----------------------------
# LISTAR VISITANTES
# -----------------------------
@app.route('/listar')
@login_required
def listar():
    visitantes = Visitor.query.order_by(Visitor.hora_entrada.desc()) if current_user.role=='superadmin' else Visitor.query.filter_by(site_id=current_user.site_id).order_by(Visitor.hora_entrada.desc())
    return render_template('listar.html', visitantes=visitantes.all())

# -----------------------------
# REGISTRAR SALIDA
# -----------------------------
@app.route('/salida/<int:visitor_id>', methods=['POST'])
@login_required
def registrar_salida(visitor_id):
    visitor = Visitor.query.get_or_404(visitor_id)
    if current_user.role!='superadmin' and visitor.site_id!=current_user.site_id:
        flash('No tiene permiso para registrar salida de este visitante','danger')
        return redirect(url_for('listar'))
    if visitor.hora_salida is None:
        visitor.hora_salida = datetime.utcnow()
        db.session.commit()
        flash(f'Salida registrada para {visitor.nombre}','success')
    else:
        flash(f'La salida de {visitor.nombre} ya estaba registrada','warning')
    return redirect(url_for('listar'))

# -----------------------------
# REPORTES (nombre, empresa, fechas) + CSV
# -----------------------------
@app.route('/reports', methods=['GET'])
@login_required
def reports():
    nombre = request.args.get('nombre','')
    empresa = request.args.get('empresa','')
    desde = request.args.get('desde','')
    hasta = request.args.get('hasta','')
    export_csv = request.args.get('export','')

    query = Visitor.query
    if current_user.role!='superadmin':
        query = query.filter(Visitor.site_id==current_user.site_id)
    if nombre:
        query = query.filter(Visitor.nombre.ilike(f'%{nombre}%'))
    if empresa:
        query = query.filter(Visitor.empresa.ilike(f'%{empresa}%'))
    if desde:
        try:
            query = query.filter(Visitor.hora_entrada>=datetime.fromisoformat(desde))
        except:
            flash('Formato de fecha "desde" inválido','warning')
    if hasta:
        try:
            query = query.filter(Visitor.hora_entrada<=datetime.fromisoformat(hasta))
        except:
            flash('Formato de fecha "hasta" inválido','warning')

    visitantes = query.order_by(Visitor.hora_entrada.desc()).all()

    # Exportar CSV
    if export_csv.lower()=='true':
        def generate():
            header = ['Nombre','Empresa','Cédula','Placa','Persona Visitada','Propósito','Hora Entrada','Hora Salida']
            yield ','.join(header)+'\n'
            for v in visitantes:
                row = [
                    v.nombre,
                    v.empresa or '',
                    v.cedula or '',
                    v.placa or '',
                    v.persona_visitada or '',
                    v.proposito or '',
                    v.hora_entrada.strftime('%Y-%m-%d %H:%M:%S') if v.hora_entrada else '',
                    v.hora_salida.strftime('%Y-%m-%d %H:%M:%S') if v.hora_salida else ''
                ]
                yield ','.join(row)+'\n'
        return Response(generate(), mimetype='text/csv',
                        headers={"Content-Disposition":"attachment;filename=reportes_visitantes.csv"})

    return render_template('reports.html', visitantes=visitantes, nombre=nombre, empresa=empresa, desde=desde, hasta=hasta)

# -----------------------------
# INICIALIZAR DB + SUPERADMIN
# -----------------------------
with app.app_context():
    db.create_all()
    default_site = Site.query.filter_by(nombre="Central").first()
    if not default_site:
        default_site = Site(nombre="Central", ubicacion="Sede principal", activo=True)
        db.session.add(default_site)
        db.session.commit()
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
