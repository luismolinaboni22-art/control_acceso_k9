from flask import Flask, render_template, redirect, url_for, request, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secreto'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///visitas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -----------------------------
# MODELOS
# -----------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    name = db.Column(db.String(200))
    password_hash = db.Column(db.String(255), nullable=False)

class Visitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(200), nullable=False)
    empresa = db.Column(db.String(200))
    hora_entrada = db.Column(db.DateTime, default=datetime.utcnow)
    hora_salida = db.Column(db.DateTime, nullable=True)

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
        if user and check_password_hash(user.password_hash,password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Usuario o contraseña inválida','danger')
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
    visitantes = Visitor.query.order_by(Visitor.hora_entrada.desc()).limit(10).all()
    return render_template('index.html', visitantes=visitantes)

# -----------------------------
# REGISTRAR VISITANTE
# -----------------------------
@app.route('/registrar', methods=['GET','POST'])
@login_required
def registrar():
    if request.method=='POST':
        nombre = request.form.get('nombre','').strip()
        empresa = request.form.get('empresa','')
        if not nombre:
            flash('El nombre es obligatorio','danger')
            return redirect(url_for('registrar'))
        visitor = Visitor(nombre=nombre, empresa=empresa)
        db.session.add(visitor)
        db.session.commit()
        flash('Visitante registrado','success')
        return redirect(url_for('index'))
    return render_template('registrar.html')

# -----------------------------
# LISTAR VISITANTES
# -----------------------------
@app.route('/listar')
@login_required
def listar():
    visitantes = Visitor.query.order_by(Visitor.hora_entrada.desc()).all()
    return render_template('listar.html', visitantes=visitantes)

# -----------------------------
# REPORTES
# -----------------------------
@app.route('/reports')
@login_required
def reports():
    nombre = request.args.get('nombre','')
    empresa = request.args.get('empresa','')
    desde = request.args.get('desde','')
    hasta = request.args.get('hasta','')
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

    export_csv = request.args.get('export','')
    if export_csv.lower()=='true':
        def generate():
            yield 'Nombre,Empresa,Hora Entrada,Hora Salida\n'
            for v in visitantes:
                row = [
                    v.nombre,
                    v.empresa or '',
                    v.hora_entrada.strftime('%Y-%m-%d %H:%M:%S'),
                    v.hora_salida.strftime('%Y-%m-%d %H:%M:%S') if v.hora_salida else ''
                ]
                yield ','.join(row)+'\n'
        return Response(generate(), mimetype='text/csv',
                        headers={"Content-Disposition":"attachment;filename=reportes.csv"})
    
    return render_template('reports.html', visitantes=visitantes, nombre=nombre, empresa=empresa, desde=desde, hasta=hasta)

# -----------------------------
# INICIALIZAR DB
# -----------------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='admin@k9.com').first():
        user = User(email='admin@k9.com', name='Admin', password_hash=generate_password_hash('1234'))
        db.session.add(user)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
