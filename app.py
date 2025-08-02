from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate  

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  
app.config['SECRET_KEY'] = 'mysecretkey'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"  

migrate = Migrate(app, db)

class User(UserMixin, db.Model):  
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='admin')  # Asignado por defecto como 'admin'

    def __repr__(self):
        if self.role == 'admin':
            return f"AdminUser('{self.username}', '{self.email}', '{self.role}')"
        else:
            return f"ClientUser('{self.username}', '{self.email}', '{self.role}')"
        
class reservar_clase(db.Model):  
    id = db.Column(db.Integer, primary_key=True)
    nombre_estudiante = db.Column(db.String(100), nullable=False)
    correo_estudiante = db.Column(db.String(120), nullable=False)
    telefono_estudiante = db.Column(db.String(15), nullable=False)
    fecha_reserva = db.Column(db.String(10), nullable=False)  
    hora_reserva = db.Column(db.String(5), nullable=False)  
    tipo_clase = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Relacionado con el estudiante logueado
    profesor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Relacionado con el profesor
    estado = db.Column(db.String(20), default='pendiente')  # Estado de la reserva
    
    usuario = db.relationship('User', foreign_keys=[user_id], backref=db.backref('reservas', lazy=True))
    profesor = db.relationship('User', foreign_keys=[profesor_id], backref=db.backref('reservas_profesor', lazy=True))

    def __repr__(self):
        return f"Reserva('{self.nombre_estudiante}', '{self.fecha_reserva}', '{self.hora_reserva}')"

class reserva_nutricionista(db.Model):  
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    correo = db.Column(db.String(120), nullable=False)
    telefono = db.Column(db.String(15), nullable=False)
    fecha_reserva = db.Column(db.String(10), nullable=False)  
    hora_reserva = db.Column(db.String(5), nullable=False)  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    nutricionista_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  
    estado = db.Column(db.String(20), default='pendiente')  
    
    usuario = db.relationship('User', foreign_keys=[user_id], backref=db.backref('reservas_nutricionista_usuario', lazy=True))
    nutricionista = db.relationship('User', foreign_keys=[nutricionista_id], backref=db.backref('reservas_nutricionista_nutricionista', lazy=True))

@app.route('/gracias_reserva')
def gracias_reserva():
    return render_template('gracias_reserva.html')  # Página con el mensaje de gracias


@app.route('/historial_citas', methods=['GET', 'POST'])
@login_required  
def historial_citas():
    if request.method == 'POST':
        if 'nombre_estudiante' in request.form:
            # Reserva de clase/profesor
            nueva_reserva = reservar_clase(
                nombre_estudiante=request.form['nombre_estudiante'],
                correo_estudiante=request.form['correo_estudiante'],  
                telefono_estudiante=request.form['telefono_estudiante'],
                fecha_reserva=request.form['fecha_reserva'],
                hora_reserva=request.form['hora_reserva'],
                tipo_clase=request.form['tipo_clase'],
                user_id=current_user.id,  
                profesor_id=request.form['profesor_id'],
                estado='pendiente'  
            )
            db.session.add(nueva_reserva)
            db.session.commit()
        elif 'nombre' in request.form:
            # Reserva de nutricionista
            nueva_reserva = reserva_nutricionista(
                nombre=request.form['nombre'],
                correo=request.form['correo'],
                telefono=request.form['telefono'],
                fecha_reserva=request.form['fecha_reserva'],
                hora_reserva=request.form['hora_reserva'],
                user_id=current_user.id,
                nutricionista_id=request.form.get('nutricionista_id', None),
                estado='pendiente'
            )
            db.session.add(nueva_reserva)
            db.session.commit()
        flash('Reserva creada exitosamente', 'success')
        return redirect(url_for('historial_citas'))
    
    citas = reservar_clase.query.filter_by(user_id=current_user.id).order_by(reservar_clase.fecha_reserva.desc()).all()
    citas_nutricionista = reserva_nutricionista.query.filter_by(user_id=current_user.id).order_by(reserva_nutricionista.fecha_reserva.desc()).all()
    return render_template('historial_citas.html', citas=citas, citas_nutricionista=citas_nutricionista)

@app.route('/citas_profesor')
@login_required
def citas_profesor():
    
    #if current_user.rol != 'profesor': 
    # flash('Acceso no autorizado', 'danger')
    # return redirect(url_for('index'))

    citas = reservar_clase.query.filter_by(profesor_id=current_user.id).order_by(reservar_clase.fecha_reserva.desc()).all()
    return render_template('citas_profesor.html', citas=citas)


@app.route('/borrar_historial', methods=['POST'])
@login_required
def borrar_historial():
    # Borrar todas las reservas del usuario actual
    reservar_clase.query.filter_by(user_id=current_user.id).delete()
    reserva_nutricionista.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('Historial de citas borrado exitosamente.', 'info')
    return redirect(url_for('historial_citas'))

@app.route('/cancelar_cita/<int:id>')
@login_required
def cancelar_cita(id):
    tipo = request.args.get('tipo')
    if tipo == 'profesor' or tipo is None:
        cita = reservar_clase.query.get(id)
        if cita:
            if cita.user_id != current_user.id and cita.profesor_id != current_user.id:
                flash('No tienes permisos para cancelar esta cita.', 'danger')
                return redirect(url_for('historial_citas'))
            cita.estado = 'cancelada'
            db.session.commit()
            flash('Cita cancelada exitosamente.', 'info')
            return redirect(url_for('historial_citas'))
    elif tipo == 'nutricionista':
        cita_nutri = reserva_nutricionista.query.get(id)
        if cita_nutri:
            if cita_nutri.user_id != current_user.id and cita_nutri.nutricionista_id != current_user.id:
                flash('No tienes permisos para cancelar esta cita.', 'danger')
                return redirect(url_for('historial_citas'))
            cita_nutri.estado = 'cancelada'
            db.session.commit()
            flash('Cita cancelada exitosamente.', 'info')
            return redirect(url_for('historial_citas'))
    flash('Cita no encontrada.', 'danger')
    return redirect(url_for('historial_citas'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def inicio():
    return render_template('inicio.html')

@app.route('/index')
@login_required  
def index():
    users = User.query.all()  
    return render_template('index.html', users=users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first() 
        
        if user and bcrypt.check_password_hash(user.password, password):  
            login_user(user)  
            
            if user.role == 'admin': 
                flash('Inicio de sesión exitoso como Administrador', 'success')
                return redirect(url_for('index'))  
            elif user.role == 'cliente':  
                flash('Inicio de sesión exitoso como Cliente', 'success')
                return redirect(url_for('negocio'))  
            else:
                flash('Rol desconocido. Acceso denegado.', 'danger')
                return redirect(url_for('login'))  
        else:
            flash('Inicio de sesión fallido. Verifica tus credenciales.', 'danger')
            return redirect(url_for('login'))  
    
    return render_template('login.html')  

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            role = request.form['role']  
            if User.query.filter_by(email=email).first():
                flash('El correo ya está registrado. Por favor inicia sesión.', 'danger')
                return redirect(url_for('register'))
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, email=email, password=hashed_password, role=role)

            db.session.add(new_user)
            db.session.commit()

            flash('Cuenta creada exitosamente. Puedes iniciar sesión ahora.', 'success')
            return redirect(url_for('login'))

        except KeyError as e:
            flash(f'Error: No se pudo encontrar el campo: {str(e)}', 'danger')
            return render_template('register.html')
    return render_template('register.html')

@app.route('/negocio')
def negocio():
    nutricionistas = User.query.filter_by(role='nutricionista').all()
    return render_template('negocio.html', nutricionistas=nutricionistas)

@app.route('/logout')
def logout():
    logout_user()
    flash('Has cerrado sesión', 'info')
    return redirect(url_for('inicio'))  

@app.route('/add_user', methods=['GET', 'POST'])
@login_required  
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form.get('password', '') 
        
        if password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        else:
            hashed_password = bcrypt.generate_password_hash('defaultpassword').decode('utf-8')
        
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_user.html')

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@login_required  
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_user.html', user=user)

@app.route('/perfil_profesor')
@login_required
def perfil_profesor():
    return render_template('perfil_profesor.html', profesor=current_user)

@app.route('/delete_user/<int:id>')
@login_required 
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/perfil_nutricionista')
@login_required
def perfil_nutricionista():
    return render_template('perfil_nutricionista.html', nutricionista=current_user)

@app.route('/recuperar', methods=['GET', 'POST'], endpoint='recuperar')
def recuperar():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('El nombre de usuario no existe.', 'danger')
            return render_template('recuperar.html')
        if user.email != email:
            flash('El correo electrónico no corresponde al usuario.', 'danger')
            return render_template('recuperar.html')
        if password != confirm_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return render_template('recuperar.html')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Contraseña actualizada correctamente. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
    return render_template('recuperar.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

@app.route('/perfil_profesor/<int:id>', methods=['GET', 'POST'])
def perfil_profesor_id(id):
    profesor = User.query.get_or_404(id)

    if request.method == 'POST':
        nombre_estudiante = request.form['nombre_estudiante']
        correo_estudiante = request.form['correo_estudiante']
        telefono_estudiante = request.form['telefono_estudiante']
        fecha_reserva = request.form['fecha_reserva']
        hora_reserva = request.form['hora_reserva']
        tipo_clase = request.form['tipo_clase']

        nueva_reserva = reservar_clase(
            nombre_estudiante=nombre_estudiante,
            correo_estudiante=correo_estudiante,
            telefono_estudiante=telefono_estudiante,
            fecha_reserva=fecha_reserva,
            hora_reserva=hora_reserva,
            tipo_clase=tipo_clase,
            profesor_id=profesor.id,  
            user_id=current_user.id, 
            estado='pendiente'
        )
        db.session.add(nueva_reserva)
        db.session.commit()
        flash('Reserva creada exitosamente', 'success')
        return redirect(url_for('citas_estudiante'))

    return render_template('perfil_profesor.html', profesor=profesor)

