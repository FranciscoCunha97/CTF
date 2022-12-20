from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User, Adverts
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename


ALLOWED_EXTENSIONS = {'pdf'}

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email=request.form.get('email')
        password = request.form.get('password1')

        user = User.query.filter_by(email='admin@user-admin.com').first()
        if user:
            if check_password_hash(user.password,password):
                flash('Logged in with admnistrator account', category='success')     
                return redirect(url_for('auth.upload_file'))

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('email does not exist.', category='error')
        
    return render_template("login.html", user=current_user)

@auth.route('/sign-up',  methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater tha 3 characters.', category='error')
        elif len(firstName) < 2:
            flash('First Name must be greater tha 1 characters.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, firstName=firstName, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))
            #add user to database
        
    return render_template("sign_up.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@auth.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        location = request.form.get('location')
        price = request.form.get('price')
        description = request.form.get('description')
        type = request.form.get('type')
        contact = request.form.get('contact')

        advert = Adverts(location=location, price=price, description=description, type=type, contact=contact)
        db.session.add(advert)
        db.session.commit()
        #login_user(user, remember=True)
        flash('Advert created!', category='success')
        return redirect(url_for('auth.flag'))
        #add user to database
        
    return render_template("upload_page.html", user=current_user)

@auth.route('/adverts')
def home():
    query = request.args.get('query')

    if query:
        myAdverts = Adverts.query.filter(Adverts.location.contains(query) | Adverts.type.contains(query))
    else:
        myAdverts = Adverts.query.all()
        return render_template('adverts.html',myAdverts=myAdverts)

@auth.route('/flag')
def flag():
    return render_template('flag.html')

