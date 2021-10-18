from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, Email
import os
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))


app.config['SECRET_KEY'] = 'hard to guess string'
app.config['SQLALCHEMY_DATABASE_URI'] =\
'sqlite:///' + os.path.join(basedir, 'grades.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('pruebamintic2021@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('mintic2021')

mail = Mail(app)
db = SQLAlchemy(app)
moment = Moment(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return '<Role %r>' % self.name

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def __repr__(self):
        return '<User %r>' % self.username
    
    @property
    def password(self):
        raise AttributeError('password no es un atributo legible')    

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role)

#trae un usuario con el query de la db dado su id (usuario loggeado)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Recordarme')
    submit = SubmitField('Log In')

class RegForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired()])
    apellido = StringField('Apellido', validators=[DataRequired()])
    id = StringField('Cédula', validators=[DataRequired()])
    tel = StringField('Teléfono', validators=[DataRequired()])
    email = StringField('Email UniQuindio', validators=[DataRequired()])
    submit = SubmitField('ENVIAR')

class AsignForm(FlaskForm):
    nombre = StringField('Nombre')
    codigo = StringField('Código')
    submit = SubmitField('Cambiar')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/perfil')
@login_required
def perfil():
     return render_template('perfil.html')


@app.route('/registro_completo')
def registro_completo():
     return render_template('registro_completo.html')


@app.route('/cursos', methods=['GET', 'POST'])
@login_required
def cursos():
    form = AsignForm()    
    cursos = {"9287222":"Programación y Desarrollo Web", "1277362":"Python Avanzado", "234322":"Machine Learning y AI"}
    if form.validate_on_submit():
        codigo = str(form.codigo.data)
        nombre = str(form.nombre.data)
        cursos[codigo] =  nombre
        return render_template('cursos.html', cursos=cursos)
    return render_template('cursos.html', cursos=cursos, form=form)


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    form = RegForm()
    if form.validate_on_submit():
        return render_template('registro_completo.html', nombre=form.nombre.data, apellido=form.apellido.data, id=form.id.data, tel=form.tel.data, email=form.email.data)
    return render_template('registro.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('home')
            return redirect(next)
        flash('Usuario o clave inválida')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Cerraste sesión')
    return redirect(url_for('index'))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/test')
def test():
    return render_template('test.html')


@app.route('/home')
@login_required
def home():
    return render_template('home.html', name=session.get('name'))
    

@app.route('/actividades')
@login_required
def actividades():
    return render_template('actividades.html')
