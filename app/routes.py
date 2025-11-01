import logging
from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, login_manager

from app.forms import *
from app.models import User
from flask_bcrypt import Bcrypt
import pyotp
from flask_qrcode import  QRcode
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from . import limiter

main = Blueprint('main', __name__)






@main.route('/', methods=['GET', 'POST'])
@limiter.limit('7 per minute')
def login():
    bcrypt = Bcrypt()
    form = loginForm()
    showCap = False

    if form.validate_on_submit():

        name = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=name).first()

        if user and user.locked_at:
            time_elapsed = datetime.now() - user.locked_at
            if time_elapsed < timedelta(minutes=5):
                remaining = int((timedelta(minutes=5) - time_elapsed).total_seconds())
                flash(f"Account locked. Please try again in {remaining} seconds.")
                return redirect(url_for('main.login'))
            else:
                user.locked_at = None
                user.failed_attempts = 0
                user.commitDB()
            return "Account is locked. Try again later.", 403



        if user and bcrypt.check_password_hash(user.password,password):
            current_app.logger.info(
                f'Successful login for user: {name}, IP: {request.remote_addr}'
            )
            session.clear()
            user.failed_attempts = 0
            login_user(user)
            user.locked_at = None
            if user.secret != None:
                session['mfa_secret'] = user.secret

            user.commitDB()
            flash('Login successful!')
            session['name'] = name
            return redirect(url_for('main.mfa_setup'))
        else:
            if user:
                user.failed_attempts +=1
                current_app.logger.warning(
                    f'Failed login attempt for username: {name}, IP: {request.remote_addr}'
                )
                if user.failed_attempts >=5:
                    current_app.logger.warning(
                        f'Account locked for user: {name}, IP: {request.remote_addr}, Failed attempts: {user.failed_attempts}'
                    )
                    user.locked_at = datetime.now()
                elif user.failed_attempts >= 3:
                    current_app.logger.info(
                        f'CAPTCHA triggered for user: {name}, IP: {request.remote_addr}, Failed attempts: {user.failed_attempts}'
                    )
                    showCap = True
                user.commitDB()
            flash('Invalid username or password.')
    else:
        f'VALIDATION FAILURE from IP {request.remote_addr}.'

    if not showCap: #Remove Captcha  unless 3 failed attempts
        del form.recaptcha

    return render_template('login.html',form=form,)

@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@main.route('/logout')
def logout():


    current_app.logger.info(
        f'Logout event for user: {session["name"]}, IP: {request.remote_addr}'
    )

    session.clear()

    return redirect(url_for('main.login'))

@main.route('/mfa_setup', methods=['GET', 'POST'])
def mfa_setup():
    if 'mfa_secret' not in session:
        session['mfa_secret'] = pyotp.random_base32()

    secret = session['mfa_secret']
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name = session['name'],issuer_name="task_2-Flask-App")
    error = ""
    form = mfaForm()
    if form.validate_on_submit():
        code = form.code.data
        if totp.verify(code):

            user = User.query.filter_by(username=session['name']).first()
            login_user(user)
            user.secret = secret
            user.commitDB()

            return redirect(url_for("main.dashboard"))
        else:
            current_app.logger.warning(
                f'Invalid TOTP code for user: {session["name"]}, IP: {request.remote_addr}'
            )
            error = "Incorrect Code"
    return render_template("mfa_setup.html",uri=uri,secret = totp.secret,form=form,error=error)



