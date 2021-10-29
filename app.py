from flask import Flask, render_template, redirect, url_for, session, flash, request, send_file
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, FileField, TextAreaField,  DecimalField, DateTimeField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo, NumberRange
import os
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_uploads import configure_uploads, UploadSet, DOCUMENTS
from datetime import datetime
from functools import wraps
from flask_breadcrumbs import Breadcrumbs, register_breadcrumb




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
app.config['UPLOADED_DOCUMENTS_DEST'] = 'uploads/documents'

documents = UploadSet('documents', DOCUMENTS)
configure_uploads(app, documents)

mail = Mail(app)
db = SQLAlchemy(app)
moment = Moment(app)
migrate = Migrate(app, db)
Breadcrumbs(app=app)
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
    description = db.Column(db.Text)
    limit_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String)
    student_comment = db.Column(db.Text)
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

def require_role(role):
    """make sure user has this role"""
    def decorator(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            if not session['account_type'] == role:
                return redirect("/404")
            else:
                return func(*args, **kwargs)
        return wrapped_function
    return decorator

#trae un usuario con el query de la db dado su id (usuario loggeado)
@login_manager.user_loader
def load_user(user_id):
    if session['account_type'] == 'Student':
        return User.query.get(int(user_id))
    elif session['account_type'] == 'Teacher':
        return Teacher.query.get(int(user_id))
    else:
      return None


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


class SubmitHomework(FlaskForm):
    homework = FileField('Documento')
    comment = TextAreaField('Comentarios')
    submit = SubmitField('Enviar')

class GradeForm(FlaskForm):
    grade =  DecimalField('Nota', validators=[NumberRange(max=5)])
    submit = SubmitField('Enviar')

class CreateActForm(FlaskForm):
    title = StringField('Titulo', validators=[DataRequired()])
    description = TextAreaField('Descripción', validators=[DataRequired()])
    limit_date = DateTimeField('Fecha Límite', validators=[DataRequired(message='Fecha en formato AAAA-MM-DD HH:MM:SS')])
    submit = SubmitField('Editar')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500



@app.route('/user/<username>')
@login_required
@require_role(role="Student")
def user(username):

    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=user)


@app.route('/teacher/user/<username>')
@login_required
@require_role(role="Teacher")
def user_teacher(username):

    user = Teacher.query.filter_by(username=username).first_or_404()
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
        if session['account_type'] == 'Student':
            return redirect(url_for('user', username=current_user.username))
        if session['account_type'] == 'Teacher':
            return redirect(url_for('user_teacher', username=current_user.username))
    form.name.data = current_user.name
    form.last_name.data = current_user.last_name
    form.cc.data = current_user.cc
    form.age.data = current_user.age
    form.email.data = current_user.email
    return render_template('edit_profile.html', form=form)



@app.route('/courses/<username>')
@login_required
@require_role(role="Student")
def courses(username):
    result = db.session.execute('Select courses.name As course, courses.code As course_code, courses.about As course_about, teachers.name As teacher_name, teachers.last_name As teacher_last_name, students.username, enrollment.id As enrollment From students Inner Join enrollment On students.id = enrollment.student_id Inner Join courses On courses.id = enrollment.course_id Inner Join teachers On teachers.id = courses.teacher_id Where students.username = :val', {'val': current_user.username})
    #print([row[0] for row in result])

    return render_template('courses.html', result=result)

@app.route('/activities/<int:enrollment_id>', methods=['GET', 'POST'])
@login_required
@require_role(role="Student")
def activities(enrollment_id):
    result = db.session.execute('Select courses.name As course, teachers.name As teacher_name, teachers.last_name As teacher_last_name, homework.title As homework, enrollment.id As enrollment, homework.description, homework.status, homework.limit_date, homework.student_comment, homework.grade, homework.date_sent, homework.file_url, homework.id From courses Inner Join enrollment On courses.id = enrollment.course_id Inner Join students On students.id = enrollment.student_id Inner Join teachers On teachers.id = courses.teacher_id Inner Join homework On enrollment.id = homework.enrollment_id Where enrollment.id = :val', {'val': enrollment_id})
    
    return render_template('activities.html', result=result, enrollment_id=enrollment_id)

@app.route('/upload/<int:enrollment_id>/<int:homework_id>', methods=['GET', 'POST'])
@login_required
@require_role(role="Student")
def upload(homework_id, enrollment_id):
    form = SubmitHomework()
    homework = Homework.query.filter(Homework.id==homework_id).first()
    homework_name = homework.title
    if request.method == 'POST':
        homework.file_url = documents.save(form.homework.data)
        homework.status = "Entregado"
        homework.student_comment = form.comment.data
        homework.date_sent = datetime.utcnow()
        db.session.add(homework)
        db.session.commit()
        flash('Actividad correctamente enviada')
        return redirect(url_for('activities', enrollment_id=enrollment_id))
       # db.session.commit()
        #db.session.execute('UPDATE homework Set file_url = :val, status = "Entregado" Where id = :val', {'val': filename, 'val': id})
    return render_template('upload.html', form=form, homework=homework, homework_name=homework_name)

@app.route('/download/<int:homework_id>')
@login_required
def download_file(homework_id):
    homework = Homework.query.filter(Homework.id==homework_id).first()
    return send_file(basedir+"\\uploads\\documents\\"+ homework.file_url, as_attachment=True)

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
    name = 'Estudiante'
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            session['account_type'] = 'Student'
            login_user(user, remember=True)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('home')
            return redirect(next)
        flash('Usuario o clave inválida')
    return render_template('login.html', form=form, name=name)


@app.route('/teacher/login', methods=['GET', 'POST'])
def login_teacher():
    form = LoginForm()
    name = 'Profesor'
    if form.validate_on_submit():
        user = Teacher.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            session['account_type'] = 'Teacher'
            login_user(user, remember=True)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('home')
            return redirect(next)
        flash('Usuario o clave inválida')
    return render_template('login.html', form=form, name=name)

@app.route('/teacher/courses/<username>', methods=['GET', 'POST'])
@login_required
@require_role(role="Teacher")
def courses_teacher(username):
    result = db.session.execute('Select teachers.id As teachers_id, teachers.username As teachers_username, courses.name As courses_name, courses.code As courses_code, courses.about As courses_about, courses.id As courses_id From courses Inner Join teachers On teachers.id = courses.teacher_id Where teachers.username = :val', {'val': username})
    #print([row[0] for row in result])

    return render_template('teacher_courses.html', result=result)

@app.route('/teacher/activities/<int:teacher_id>/<int:course_id>', methods=['GET', 'POST'])
@login_required
@require_role(role="Teacher")
def teacher_activities(teacher_id, course_id):
    result = db.session.execute('Select teachers.id, courses.name As course_name, courses.code As course_code, courses.id As courses_id, homework.title As homework_title, homework.description As homework_description, homework.student_comment As homework_student_comment, students.name As students_name, students.last_name As students_last_name, homework.limit_date As homework_limit_date, homework.status As homework_status, homework.grade As homework_grade, homework.date_sent As homework_date_sent, homework.id As homework_id, homework.file_url As homework_file_url From enrollment Inner Join courses On courses.id = enrollment.course_id Inner Join homework On enrollment.id = homework.enrollment_id Inner Join teachers On teachers.id = courses.teacher_id Inner Join students On students.id = enrollment.student_id Where teachers.id = :val And courses.id = :val2', {'val': teacher_id, 'val2': course_id})
    return render_template('teacher_activities.html', result=result, teacher_id=teacher_id, course_id=course_id)

@app.route('/grade/<int:teacher_id>/<int:course_id>/<int:homework_id>', methods=['GET', 'POST'])
@login_required
@require_role(role="Teacher")
def teacher_grade(teacher_id, course_id, homework_id):
    form = GradeForm()
    homework = Homework.query.filter(Homework.id==homework_id).first()
    homework_name = homework.title
    if request.method == 'POST':
        homework.status = "Entregado y Calificado"
        homework.grade = form.grade.data
        db.session.add(homework)
        db.session.commit()
        flash('Actividad calificada correctamente')
        return redirect(url_for('teacher_activities', teacher_id=teacher_id, course_id=course_id))
       # db.session.commit()
        #db.session.execute('UPDATE homework Set file_url = :val, status = "Entregado" Where id = :val', {'val': filename, 'val': id})
    return render_template('teacher_grade.html', form=form, homework=homework, homework_name=homework_name)

@app.route('/teacher/create_activity/<int:teacher_id>/<int:course_id>', methods=['GET', 'POST'])
@login_required
@require_role(role="Teacher")
def teacher_create_activity(teacher_id, course_id):
    result = db.session.execute('Select enrollment.id As id From enrollment where enrollment.course_id = :val', {'val': course_id})
    res = [r for r, in result]
    form = CreateActForm()
    if form.validate_on_submit():
        for i in res:
            homework = Homework(title=form.title.data,
                    description=form.description.data,
                    limit_date=form.limit_date.data,
                    status = "No Entregado",
                    enrollment_id=i)
            db.session.add(homework)
            db.session.commit()
        flash('Actividad creada con éxito!')
        return redirect(url_for('teacher_activities', teacher_id=teacher_id, course_id=course_id))
    return render_template('teacher_create_act.html', form=form)

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
    



