from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo
from mysql_db import MySQL
from datetime import datetime

login_manager = LoginManager()

app = Flask(__name__)
app.config.from_pyfile('config.py')

mysql = MySQL(app)

login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Доступ к данной странице есть только у авторизованных пользователей'
login_manager.login_message_category = 'warning'


class User(UserMixin):
    def __init__(self, user_id, login):
        self.id = user_id
        self.login = login


@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor(named_tuple=True)
    cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))
    user = cursor.fetchone()
    if user:
        return User(user_id=user.id, login=user.login)
    return None


class CreateUserForm(FlaskForm):
    login = StringField('Login', validators=[DataRequired(), Length(min=5)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128)])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name')
    middle_name = StringField('Middle Name')
    role = SelectField('Role', coerce=int)
    submit = SubmitField('Create')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8, max=128)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/users/')
@login_required
def users():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT id, login, first_name, last_name FROM users')
    users = cursor.fetchall()
    return render_template('users/index.html', users=users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        login = request.form.get('login')
        password = request.form.get('password')
        remember = request.form.get('remember')
        if login and password:
            cursor = mysql.connection.cursor(named_tuple=True)
            cursor.execute('SELECT * FROM users WHERE login=%s AND password_hash = SHA2(%s, 256)', (login, password))
            user = cursor.fetchone()
            if user:
                login_user(User(user_id=user.id, login=user.login), remember=remember)
                flash('Вы успешно прошли аутентификацию', 'success')
                next = request.args.get('next')
                return redirect(next or url_for('index'))
        flash('Неверные логин или пароль', 'danger')
    return render_template('login.html')


@app.route('/users/register', methods=['GET', 'POST'])
@login_required
def register():
    form = CreateUserForm()
    # Populate role choices
    form.role.choices = [(role.id, role.name) for role in Role.query.all()]
    if form.validate_on_submit():
        # Create new user
        new_user = User(
            login=form.login.data,
            password_hash=form.password.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            middle_name=form.middle_name.data,
            role_id=form.role.data
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully', 'success')
        return redirect(url_for('users'))
    return render_template('users/register.html', form=form)


@app.route('/users/<int:user_id>')
@login_required
def view_user(user_id):
    cursor = mysql.connection.cursor(named_tuple=True)
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    if user:
        return render_template('/users/view.html', user=user)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('index'))


@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if request.method == 'POST':
        login = request.form.get('login')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        try:
            with mysql.connection().cursor(named_tuple=True) as cursor:
                cursor.execute('UPDATE users SET login = %s, first_name = %s, last_name = %s WHERE id = %s', (
                login, first_name, last_name, user_id,))
                mysql.connection().commit()
                flash('Сведения о пользователи успешно сохранены', 'success')
                return redirect(url_for('view_user', user_id=user_id))
        except Exception as e:
            mysql.connection().rollback()
            flash('Ошбика', 'danger')
            return render_template('users/edit.html')
    else:
        cursor = mysql.connection().cursor(named_tuple=True)
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        if user:
            return render_template('users/edit.html', user=user)
        flash('Пользователь не найден', 'danger')
        return redirect(url_for('index'))


@app.route('/users/<int:user_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    cursor = mysql.connection.cursor(named_tuple=True)
    cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
    mysql.connection().commit()
    flash('Пользователь успешно удалён', 'success')
    return redirect(url_for('users'))


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Password changed successfully', 'success')
            return redirect(url_for('index'))
        else:
            flash('Old password is incorrect', 'danger')
    return render_template('change_password.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
