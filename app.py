@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # Validación para evitar errores SQL
        if not email or not password:
            return render_template('login.html', error="Debe ingresar correo y contraseña")

        u = User.query.filter_by(email=email).first()

        if u and check_password_hash(u.password_hash, password):
            login_user(u)
            return redirect(url_for('index'))

        return render_template('login.html', error="Credenciales inválidas")

    return render_template('login.html')
