from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_secreto_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///visitas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# =====================
# MODELOS
# =====================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    name = db.Column(db.String(200))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="oficial")
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

# =====================
# LOGIN
# =====================
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

# =====================
# RUTAS PRINCIPALES
# =====================
@app.route('/')
@login_required
def index():
    active_visitors_count = Visitor.query.filter_by(hora_salida=None).count()
    visitantes = Visitor.query.order_by(Visitor.hora_entrada.desc()).limit(10).all()
    return render_template('index.html', current_user=current_user,
                           active_visitors_count=active_visitors_count,
                           visitantes=visitantes)

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

@app.route('/listar')
@login_required
def listar():
    visitantes = Visitor.query.order_by(Visitor.hora_entrada.desc()).all()
    return render_template('listar.html', visitantes=visitantes)

@app.route('/admin/users')
@login_required
def admin_users():
    return "Usuarios"

@app.route('/admin/sites')
@login_required
def admin_sites():
    return "Sitios"

@app.route('/reports')
@login_required
def reports():
    return "Reportes"

@app.route('/admin/configuracion')
@login_required
def admin_configuracion():
    return "Configuración"

# =====================
# INICIALIZAR DB
# =====================
with app.app_context():
    db.create_all()
    # Crear un superadmin si no existe
    if not User.query.filter_by(email="jorgemolinabonilla@gmail.com").first():
        user = User(
            email="jorgemolinabonilla@gmail.com",
            name="Super Admin",
            password_hash=generate_password_hash("Cambio123!"),
            role="superadmin"
        )
        db.session.add(user)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)






