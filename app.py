from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from io import BytesIO

import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from openpyxl.styles import Font, PatternFill, Alignment

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_secreto_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///visitas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------------------------------------------------------------------
# DECORADORES
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

def admin_or_superadmin(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if current_user.role in ['admin', 'superadmin']:
            return f(*args, **kwargs)
        flash("No tiene permisos para acceder.", "danger")
        return redirect(url_for('index'))
    return wrapped

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
    base_query = Visitor.query if current_user.role == 'superadmin' else Visitor.query.filter_by(site_id=current_user.site_id)
    active_visitors_count = base_query.filter(Visitor.hora_salida.is_(None)).count()
    today_start = datetime.combine(date.today(), datetime.min.time())
    total_today = base_query.filter(Visitor.hora_entrada >= today_start).count()
    visitantes = base_query.order_by(Visitor.hora_entrada.desc()).limit(10).all()
    alertas = [f"⚠ {v.nombre} lleva más de {int((datetime.utcnow()-v.hora_entrada).total_seconds()/3600)} horas dentro de planta."
               for v in base_query.filter(Visitor.hora_salida.is_(None)) if v.hora_entrada and (datetime.utcnow()-v.hora_entrada).total_seconds()/3600>=8]
    sites = Site.query.order_by(Site.nombre).all()
    return render_template('index.html', current_user=current_user, active_visitors_count=active_visitors_count,
                           pending_count=active_visitors_count, today_count=total_today, total_today=total_today,
                           visitantes=visitantes, alertas=alertas, alertas_totales=len(alertas), sites=sites)

# ---------------------------------------------------------------------
# REGISTRO VISITANTES
# ---------------------------------------------------------------------
@app.route('/registrar', methods=['GET','POST'])
@login_required
def registrar():
    sites = Site.query.filter_by(activo=True).order_by(Site.nombre).all()
    if request.method == 'POST':
        nombre = request.form.get('nombre','').strip()
        if not nombre:
            flash('El nombre es obligatorio', 'danger')
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

# ---------------------------------------------------------------------
# LISTADO VISITANTES
# ---------------------------------------------------------------------
@app.route('/listar')
@login_required
def listar():
    visitantes = Visitor.query.order_by(Visitor.hora_entrada.desc()) if current_user.role=='superadmin' else Visitor.query.filter_by(site_id=current_user.site_id).order_by(Visitor.hora_entrada.desc())
    return render_template('listar.html', visitantes=visitantes.all())

# ---------------------------------------------------------------------
# REGISTRAR SALIDA
# ---------------------------------------------------------------------
@app.route('/salida/<int:visitor_id>', methods=['POST'])
@login_required
def registrar_salida(visitor_id):
    visitor = Visitor.query.get_or_404(visitor_id)
    if current_user.role!='superadmin' and visitor.site_id!=current_user.site_id:
        flash('No tiene permiso para registrar salida de este visitante', 'danger')
        return redirect(url_for('listar'))
    if visitor.hora_salida is None:
        visitor.hora_salida = datetime.utcnow()
        db.session.commit()
        flash(f'Salida registrada para {visitor.nombre}','success')
    else:
        flash(f'La salida de {visitor.nombre} ya estaba registrada','warning')
    return redirect(url_for('listar'))

# ---------------------------------------------------------------------
# ADMIN USUARIOS
# ---------------------------------------------------------------------
@app.route('/admin/users')
@login_required
@role_required('superadmin')
def admin_users():
    users = User.query.order_by(User.name.asc()).all()
    sites = Site.query.order_by(Site.nombre).all()
    return render_template('admin_users.html', users=users, sites=sites)

@app.route('/admin/users/create', methods=['GET','POST'])
@login_required
@role_required('superadmin')
def admin_user_create():
    sites = Site.query.order_by(Site.nombre).all()
    if request.method=='POST':
        email = request.form.get('email','').strip().lower()
        nombre = request.form.get('name','').strip()
        role = request.form.get('role','oficial')
        password = request.form.get('password','')
        site_id = int(request.form.get('site_id')) if request.form.get('site_id') else None
        if not email or not nombre or not password:
            flash("Nombre, email y contraseña son obligatorios","danger")
            return redirect(url_for('admin_user_create'))
        if User.query.filter_by(email=email).first():
            flash("El correo ya está registrado","danger")
            return redirect(url_for('admin_user_create'))
        nuevo = User(email=email,name=nombre,role=role,password_hash=generate_password_hash(password),active=True,site_id=site_id)
        db.session.add(nuevo)
        db.session.commit()
        flash("Usuario creado correctamente","success")
        return redirect(url_for('admin_users'))
    return render_template('admin_user_form.html', action='create', sites=sites, user=None)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET','POST'])
@login_required
@role_required('superadmin')
def admin_user_edit(user_id):
    user = User.query.get_or_404(user_id)
    sites = Site.query.order_by(Site.nombre).all()
    if request.method=='POST':
        user.email = request.form.get('email', user.email).strip().lower()
        user.name = request.form.get('name', user.name).strip()
        user.role = request.form.get('role', user.role)
        site_id = int(request.form.get('site_id')) if request.form.get('site_id') else None
        user.site_id = site_id
        new_password = request.form.get('password','')
        if new_password:
            user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash("Usuario actualizado","success")
        return redirect(url_for('admin_users'))
    return render_template('admin_user_form.html', action='edit', user=user, sites=sites)

@app.route('/admin/users/toggle/<int:user_id>', methods=['POST'])
@login_required
@role_required('superadmin')
def admin_user_toggle(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("No puede desactivar su propio usuario","danger")
        return redirect(url_for('admin_users'))
    user.active = not user.active
    db.session.commit()
    estado = "activado" if user.active else "desactivado"
    flash(f"Usuario {estado}","info")
    return redirect(url_for('admin_users'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required('superadmin')
def admin_user_delete(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("No puede eliminar su propio usuario","danger")
        return redirect(url_for('admin_users'))
    db.session.delete(user)
    db.session.commit()
    flash("Usuario eliminado correctamente","success")
    return redirect(url_for('admin_users'))

# ---------------------------------------------------------------------
# ADMIN SITIOS
# ---------------------------------------------------------------------
@app.route('/admin/sites/new', methods=['GET','POST'])
@login_required
@admin_or_superadmin
def admin_sites_new():
    users = User.query.order_by(User.name).all()
    if request.method=='POST':
        nombre = request.form.get('nombre','').strip()
        ubicacion = request.form.get('ubicacion','').strip()
        if not nombre:
            flash("El nombre es obligatorio","danger")
            return redirect(url_for('admin_sites_new'))
        nuevo = Site(nombre=nombre, ubicacion=ubicacion)
        db.session.add(nuevo)
        db.session.commit()
        flash("Sitio creado exitosamente","success")
        return redirect(url_for('admin_sites'))
    return render_template('admin_sites_new.html', users=users)

@app.route('/admin/sites/edit/<int:site_id>', methods=['GET','POST'])
@login_required
@admin_or_superadmin
def admin_sites_edit(site_id):
    sitio = Site.query.get_or_404(site_id)
    users = User.query.order_by(User.name).all()
    if request.method=='POST':
        sitio.nombre = request.form.get('nombre', sitio.nombre).strip()
        sitio.ubicacion = request.form.get('ubicacion', sitio.ubicacion).strip()
        db.session.commit()
        flash("Sitio actualizado correctamente","success")
        return redirect(url_for('admin_sites'))
    return render_template('admin_sites_edit.html', site=sitio, users=users)

@app.route('/admin/sites/toggle/<int:site_id>', methods=['POST'])
@login_required
@admin_or_superadmin
def admin_sites_toggle(site_id):
    sitio = Site.query.get_or_404(site_id)
    sitio.activo = not sitio.activo
    db.session.commit()
    flash("Estado actualizado","info")
    return redirect(url_for('admin_sites'))

@app.route('/admin/sites/delete/<int:site_id>', methods=['POST'])
@login_required
@admin_or_superadmin
def admin_sites_delete(site_id):
    sitio = Site.query.get_or_404(site_id)
    db.session.delete(sitio)
    db.session.commit()
    flash("Sitio eliminado","danger")
    return redirect(url_for('admin_sites'))

# ---------------------------------------------------------------------
# REPORTES VISITANTES
# ---------------------------------------------------------------------
@app.route('/reports', methods=['GET'])
@login_required
def reports_view():
    nombre = request.args.get('nombre','')
    empresa = request.args.get('empresa','')
    desde = request.args.get('desde','')
    hasta = request.args.get('hasta','')
    site_filter = request.args.get('site','')

    query = Visitor.query

    if current_user.role != 'superadmin':
        query = query.filter(Visitor.site_id==current_user.site_id)
    elif site_filter:
        try:
            query = query.filter(Visitor.site_id==int(site_filter))
        except ValueError:
            pass

    if nombre:
        query = query.filter(Visitor.nombre.ilike(f"%{nombre}%"))
    if empresa:
        query = query.filter(Visitor.empresa.ilike(f"%{empresa}%"))
    if desde:
        try:
            query = query.filter(Visitor.hora_entrada>=datetime.fromisoformat(desde))
        except Exception:
            flash("Formato de fecha 'desde' inválido", "warning")
    if hasta:
        try:
            query = query.filter(Visitor.hora_entrada<=datetime.fromisoformat(hasta))
        except Exception:
            flash("Formato de fecha 'hasta' inválido", "warning")

    visitantes = query.order_by(Visitor.hora_entrada.desc()).all()
    sites = Site.query.order_by(Site.nombre).all()

    return render_template('reports.html', visitantes=visitantes, nombre=nombre,
                           empresa=empresa, desde=desde, hasta=hasta, sites=sites,
                           site_filter=site_filter)

# ---------------------------------------------------------------------
# EXPORT PDF
# ---------------------------------------------------------------------
@app.route('/reports/export/pdf')
@login_required
def export_pdf():
    args = request.args
    query = Visitor.query

    if current_user.role != 'superadmin':
        query = query.filter(Visitor.site_id==current_user.site_id)
    else:
        site_filter = args.get('site','')
        if site_filter:
            try:
                query = query.filter(Visitor.site_id==int(site_filter))
            except ValueError:
                pass

    if args.get('nombre'):
        query = query.filter(Visitor.nombre.ilike(f"%{args.get('nombre')}%"))
    if args.get('empresa'):
        query = query.filter(Visitor.empresa.ilike(f"%{args.get('empresa')}%"))
    if args.get('desde'):
        try:
            query = query.filter(Visitor.hora_entrada>=datetime.fromisoformat(args.get('desde')))
        except Exception:
            pass
    if args.get('hasta'):
        try:
            query = query.filter(Visitor.hora_entrada<=datetime.fromisoformat(args.get('hasta')))
        except Exception:
            pass

    visitantes = query.order_by(Visitor.hora_entrada.desc()).all()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=18)
    elements = []
    styles = getSampleStyleSheet()
    title = Paragraph("Reporte de Visitantes", styles['Title'])
    elements.append(title)

    data = [["Nombre","Empresa","Placa","Persona Visitada","Propósito","Entrada","Salida"]]
    if current_user.role=='superadmin':
        data[0].append("Sitio")

    for v in visitantes:
        row = [v.nombre, v.empresa, v.placa or "", v.persona_visitada or "", v.proposito or "",
               v.hora_entrada.strftime('%Y-%m-%d %H:%M:%S') if v.hora_entrada else "",
               v.hora_salida.strftime('%Y-%m-%d %H:%M:%S') if v.hora_salida else ""]
        if current_user.role=='superadmin':
            row.append(v.site.nombre if v.site else "")
        data.append(row)

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#00A3E0')),
        ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('FONTSIZE',(0,0),(-1,0),10),
        ('BOTTOMPADDING',(0,0),(-1,0),8),
        ('GRID',(0,0),(-1,-1),0.5,colors.grey),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white, colors.lightgrey])
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, download_name="visitantes.pdf", as_attachment=True)

# ---------------------------------------------------------------------
# EXPORT EXCEL
# ---------------------------------------------------------------------
@app.route('/reports/export/excel')
@login_required
def export_excel():
    args = request.args
    query = Visitor
