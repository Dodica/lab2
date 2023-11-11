from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from . import cache
import re

auth = Blueprint('auth', __name__)
MAX_LOGIN_ATTEMPTS = 5
RATE_LIMIT_DURATION = 3600
RATE_LIMIT_RESET_KEY = 'rate_limit_reset_{}'

def is_rate_limited(ip_address, cache):
    """
    Check if the IP address is rate-limited.
    """
    rate_limit_key = RATE_LIMIT_RESET_KEY.format(ip_address)
    count = cache.get(rate_limit_key)
    return count is not None and count >= MAX_LOGIN_ATTEMPTS

def reset_rate_limit(ip_address, cache):
    """
    Reset the rate limit for an IP address.
    """
    rate_limit_key = RATE_LIMIT_RESET_KEY.format(ip_address)
    cache.delete(rate_limit_key)

def increment_login_attempts(ip_address, cache):
    """
    Increment the login attempt count for an IP address.
    """
    rate_limit_key = RATE_LIMIT_RESET_KEY.format(ip_address)
    count = cache.get(rate_limit_key)
    if count is None:
        count = 0
    count += 1
    cache.set(rate_limit_key, count, timeout=RATE_LIMIT_DURATION)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        show_password_rules = 'showPasswordRules' in request.form
        user = User.query.filter_by(email=email).first()
        if is_rate_limited(request.remote_addr, cache):
            flash('Too many login attempts. Please try again later.', category='error')
            return redirect(url_for('auth.login'))

        if user:
            if not show_password_rules:
                if check_password_hash(user.password, password):
                    flash('Logged in successfully!', category='success')
                    login_user(user, remember=True)
                    reset_rate_limit(request.remote_addr, cache)
                    return redirect(url_for('views.home'))
                else:
                    flash('Incorrect password, try again.', category='error')
            else:
                if user.password == password:
                    flash('Logged in successfully!', category='success')
                    login_user(user, remember=True)
                    reset_rate_limit(request.remote_addr, cache)
                    return redirect(url_for('views.home'))
                else:
                    flash('Incorrect password, try again.', category='error')

        else:
            flash('Email does not exist.', category='error')

        increment_login_attempts(request.remote_addr, cache)

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        show_password_rules = 'showPasswordRules' in request.form

        user = User.query.filter_by(email=email).first()
        if not show_password_rules:
            if user:
                flash('Email already exists.', category='error')
            elif len(email) < 4:
                flash('Email must be greater than 3 characters.', category='error')
            elif len(first_name) < 2:
                flash('First name must be greater than 1 character.', category='error')
            elif password1 != password2:
                flash('Passwords don\'t match.', category='error')
            elif len(password1) < 7:
                flash('Password must be at least 7 characters.', category='error')
            elif not re.search("[A-Z]", password1):
                flash('Password must contain at least one capital letter.', category='error')
            elif not re.search("[\W]", password1):
                flash('Password must contain at least one non-alphanumeric character.', category='error')
            elif not re.search("[0-9]", password1):
                flash('Password must contain at least one numerical character.', category='error')
            else:
                new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                    password1, method='pbkdf2:sha256'))
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('Account created!', category='success')
                return redirect(url_for('views.home'))
        else:
            new_user = User(email=email, first_name=first_name, password=password1)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)
