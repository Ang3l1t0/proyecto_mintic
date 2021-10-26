from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
import os
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))


app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] =\
'sqlite:///' + os.path.join(basedir, 'grades.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

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

class Enrollment (db.Model):
    __tablename__ = "enrollment"
    id = db.Column(db.Integer, primary_key = True)
    student_id = db.Column(db.Integer,db.ForeignKey('students.id'))
    course_id = db.Column(db.Integer,db.ForeignKey('courses.id'))

    score = db.Column(db.DECIMAL(5,2))

    homework = db.relationship('Homework', backref='homework', lazy='subquery')
    student_list = db.relationship('User', backref='course_list',lazy='subquery')


class Homework(db.Model):
    __tablename__ = 'homework'
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(128))
    description = db.Column(db.String)
    limit_date = db.Column(db.DateTime)
    status = db.Column(db.String)
    student_comment = db.Column(db.String)
    grade = db.Column(db.DECIMAL(5,2))
    date_sent = db.Column(db.DateTime)
    file_url = db.Column(db.String)
    enrollment_id = db.Column(db.Integer, db.ForeignKey('enrollment.id'))


class User(UserMixin, db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    cc = db.Column(db.Integer, unique=True, index=True)
    age = db.Column(db.Integer)
    genre = db.Column(db.CHAR)
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


class Teacher(UserMixin, db.Model):
    __tablename__ = 'teachers'
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    cc = db.Column(db.Integer, unique=True, index=True)
    age = db.Column(db.Integer)
    genre = db.Column(db.CHAR)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    course_list = db.relationship("Course",uselist=True, backref="teacher",lazy="subquery")

    def __repr__(self):
        return '<Teacher %r>' % self.username
    
    @property
    def password(self):
        raise AttributeError('password no es un atributo legible')    

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, index=True)
    code = db.Column(db.String(64), unique=True, index=True)
    about = db.Column(db.String(128))
    teacher_id = db.Column(db.Integer,db.ForeignKey(Teacher.id))

    def __repr__(self):
        return '<Course %r>' % self.name


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role, Teacher=Teacher, Course=Course, Homework=Homework, Enrollment=Enrollment)

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
    name = StringField('Nombre', validators=[DataRequired()])
    last_name = StringField('Apellido', validators=[DataRequired()])
    cc = StringField('Cédula', validators=[DataRequired()])
    age = StringField('Edad', validators=[DataRequired()])
    email = StringField('Email UniQuindio', validators=[DataRequired()])
    username = StringField('Usuario', validators=[
    DataRequired(), Length(1, 64),
    Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
    'Solo usuarios con numeros o letras')])
    password = PasswordField('Password', validators=[ DataRequired(), EqualTo('password2', message='Passwords deben ser iguales')])
    password2 = PasswordField('Confirma password', validators=[DataRequired()])
    submit = SubmitField('Registrar')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email ya registrado')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Usuario ya registrado')

class EditProfileForm(FlaskForm):
    name = StringField('Nombre', validators=[Length(0, 64)])
    last_name = StringField('Apellido', validators=[Length(0, 64)])
    cc = StringField('Cédula', validators=[Length(0, 64)])
    age = StringField('Edad', validators=[Length(0, 64)])
    email = StringField('Email UniQuindio', validators=[Length(0, 64)])
    submit = SubmitField('Editar')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500



@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=user)

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.last_name = form.last_name.data
        current_user.cc = form.cc.data
        current_user.age = form.age.data
        current_user.email = form.email.data
        db.session.add(current_user._get_current_object())
        db.session.commit()
        flash('Perfil actualizado.')
        return redirect(url_for('user', username=current_user.username))
    form.name.data = current_user.name  
    form.last_name.data = current_user.last_name
    form.cc.data = current_user.cc
    form.age.data = current_user.age
    form.email.data = current_user.email
    return render_template('edit_profile.html', form=form)



@app.route('/courses/<username>')
@login_required
def courses(username):
    user = User.query.filter(User.username==username).first()
    result = db.session.execute('Select students.name, courses.name As course, teachers.name As teacher, homework.title As homework, enrollment.id As enrollment From courses Inner Join enrollment On courses.id = enrollment.course_id Inner Join students On students.id = enrollment.student_id Inner Join teachers On teachers.id = courses.teacher_id Inner Join homework On enrollment.id = homework.enrollment_id Where students.username = :val', {'val': current_user.username})
    #print([row[0] for row in result])

    return render_template('courses.html', result=result)

@app.route('/activities/<enrollment_id>')
@login_required
def activities(enrollment_id):
    result = db.session.execute('Select courses.name As course, teachers.name As teacher, homework.title As homework, enrollment.id As enrollment, homework.description, homework.status, homework.limit_date, homework.student_comment, homework.grade, homework.date_sent From courses Inner Join enrollment On courses.id = enrollment.course_id Inner Join students On students.id = enrollment.student_id Inner Join teachers On teachers.id = courses.teacher_id Inner Join homework On enrollment.id = homework.enrollment_id Where enrollment.id = :val', {'val': enrollment_id})
    return render_template('activities.html', result=result)



@app.route('/registro', methods=['GET', 'POST'])
def registro():
    form = RegForm()
    if form.validate_on_submit():
        user = User(name=form.name.data,
                    last_name=form.last_name.data,
                    cc=form.cc.data,
                    age=form.age.data,
                    email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        print('se registro')
        flash('Puedes hacer Login')
        return redirect(url_for('login'))
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
    



