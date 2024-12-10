import os
from flask import render_template, Blueprint, url_for, redirect, flash, current_app
from itsdangerous import URLSafeTimedSerializer

from itsdangerous.exc import BadTimeSignature, BadSignature
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash
from flask_login import current_user, login_user, logout_user
from config import serializer, SERVER_URL
from online.log import loger
from online.extensions import db
from online.mail import send_mail
from online.validate import validate_password
from online.auth.forms import UserRegisterForm, LoginForm, RegisterFormAdmin, ResetPasswordForm, ForgotPasswordForm
from online.models import User


auth = Blueprint('auth', __name__)
load_dotenv()
# serializer = URLSafeTimedSerializer(current_app.config['SALT'])


@auth.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'voter':
            return redirect(url_for('online_voting.categories'))
        elif current_user.role == 'chairman':
            return redirect(url_for('auth.dashboard'))
        else:
            return redirect(url_for('online_voting.categories'))
    return render_template('index.html')


@auth.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    form = UserRegisterForm()
    if form.validate_on_submit():
        print("Form validated successfully!")
        username = form.username.data
        email = form.email.data

        existing_username = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_username or existing_email:
            flash('Username or Email already exists', 'danger')
            return redirect(url_for('auth.register'))
        else:
            try:
                salt = os.getenv('SALT')
                if not salt:
                    raise ValueError('Server Error: Missing SALT.')
                password = form.password.data + salt
                validate_password(password)

                user = User(
                    email=form.email.data,
                    role=form.role.data,
                    username=form.username.data,
                    password=password,
                )

                db.session.add(user)
                db.session.commit()

                if user.is_authenticated:
                    logout_user()

                flash('Thanks for registering!', 'success')
                return redirect(url_for('auth.login'))
            except ValueError as e:
                flash(str(e), 'danger')
            except IntegrityError as e:
                db.session.rollback()
                flash(
                    "An error occurred during registration. Please try again.", 'danger')
    else:
        print("Form validation failed!")
        print(form.errors)

    return render_template('register.html', form=form)


@auth.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    if current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    form = RegisterFormAdmin()
    if form.validate_on_submit():
        print("Form validated successfully!")
        username = form.username.data
        email = form.email.data

        existing_username = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_username or existing_email:
            flash('Username or Email already exists', 'danger')
            return redirect(url_for('auth.register'))
        else:
            try:
                salt = os.getenv('SALT')
                if not salt:
                    raise ValueError('Server Error: Missing SALT.')
                password = form.password.data + salt
                validate_password(password)

                user = User(
                    email=form.email.data,
                    role=form.role.data,
                    username=form.username.data,
                    password=password,
                )

                db.session.add(user)
                db.session.commit()

                if user.is_authenticated:
                    logout_user()

                flash('Thanks for registering!', 'success')
                return redirect(url_for('auth.login'))
            except ValueError as e:
                loger.log_error("Error")
                flash(str(e), 'danger')
            except IntegrityError as e:
                db.session.rollback()
                loger.log_error("An error occurred during registration..")
                flash(
                    "An error occurred during registration. Please try again.", 'danger')
    else:
        print("Form validation failed!")
        print(form.errors)

    return render_template('admin_register.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('auth.index'))

    form = LoginForm()
    if form.validate_on_submit():
        salt = os.getenv('SALT')
        if not salt:
            flash('Server Error', 'danger')
            return render_template('login.html', title='Login', form=form)

        user = User.query.filter_by(username=form.username.data).first()
        if user:
            entered_password = form.password.data + salt
            if user.check_password(entered_password):
                login_user(user, remember=form.remember.data)

                if user.role == 'voter':
                    # total_categories = Category.query.count()
                    # votes_in_categories = (
                    #     Vote.query.filter_by(user_id=user.id).with_entities(Vote.category_id).distinct().count()
                    # )

                    # if votes_in_categories == total_categories:
                    #     return redirect(url_for('online_voting.live_results'))
                    # else:
                    return redirect(url_for('auth.index'))

                elif user.role == 'chairman':
                    return redirect(url_for('auth.index'))

                return redirect(url_for('auth.index'))

            else:
                flash(
                    'Invalid credentials. Please check your username and password.', 'danger')
                return redirect(url_for('auth.login'))
        else:
            flash(
                'Login Unsuccessful. Please check your username and password.', 'danger')
            return redirect(url_for('auth.login'))

    return render_template('login.html', title='Login', form=form)


@auth.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    flash('Logout Successful')
    return redirect(url_for('auth.login'))


@auth.route('/forgot_password', methods=['POST', 'GET'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            try:
                username = user.username
                hashCode = serializer.dumps(email, salt='forgot_password')
                user.hasCode = hashCode
                db.session.commit()

                server = current_app.config.get(
                    'SERVER_URL', 'http://localhost:3000')
                link = f"{server}/{hashCode}"

                send_mail(
                    to=email,
                    template='email.html',
                    subject='Reset Password',
                    username=username,
                    link=link
                )

                flash("A password reset link has been sent to your email!", "success")
                return redirect(url_for('auth.login'))
            except Exception as e:
                loger.log_error(f"Error sending reset email: {str(e)}")
                flash(
                    "An error occurred while sending the reset email. Please try again.", "danger")
        else:
            flash("There is no account associated with that email.", "danger")
    else:
        loger.log_error(f"Form validation errors: {form.errors}")

    return render_template('forgot_password.html', title='Forgot Password', form=form)


@auth.route("/<string:hashCode>", methods=["GET", "POST"])
def hashcode(hashCode):
    try:
        email = serializer.loads(
            hashCode, salt="forgot_password", max_age=3600)  # Validate hash
    except BadTimeSignature:
        loger.log_error("Expired password reset link accessed.")
        flash("The password reset link has expired. Please request a new one.", "danger")
        return redirect(url_for("auth.forgot_password"))
    except BadSignature:
        loger.log_error("Invalid password reset link accessed.")
        flash("Invalid password reset link. Please request a new one.", "danger")
        return redirect(url_for("auth.forgot_password"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User does not exist!", "danger")
        return redirect(url_for("auth.login"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        if form.password.data == form.confirm_password.data:
            user.password = generate_password_hash(
                form.password.data
            )
            user.hasCode = None
            db.session.commit()

            flash("Your password has been reset successfully!", "success")
            return redirect(url_for("auth.login"))
        else:
            flash("Passwords do not match. Please try again.", "danger")

    return render_template("reset_password.html", form=form, hashCode=hashCode)
