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




