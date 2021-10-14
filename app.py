from flask import Flask, render_template, redirect, url_for, session, flash
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to guess string'

bootstrap = Bootstrap(app)
moment = Moment(app)


class LoginForm(FlaskForm):
    name = StringField('Nombre', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('ENVIAR')

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
def perfil():
     return render_template('perfil.html')


@app.route('/registro_completo')
def registro_completo():
     return render_template('registro_completo.html')


@app.route('/cursos', methods=['GET', 'POST'])
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
        if form.name.data == "nicolas":
            session['name'] = form.name.data
            return redirect(url_for('home'))
        flash("Nombre de usuario incorrecto")
    return render_template('login.html', form=form)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/test')
def test():
    return render_template('test.html')


@app.route('/home')
def home():
    return render_template('home.html', name=session.get('name'))
    

@app.route('/actividades')
def actividades():
    return render_template('actividades.html')

