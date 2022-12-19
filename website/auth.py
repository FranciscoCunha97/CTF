from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User, Img
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename


ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email=request.form.get('email')
        password = request.form.get('password')

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
            login_user(user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))
            #add user to database
        
    return render_template("sign_up.html", user=current_user)



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@auth.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', category='error')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            mimetype = file.mimetype
            file = Img(name = filename, file = file.read(), mimetype=mimetype)
            db.session.add(file)
            db.session.commit()

    return render_template("upload_page.html")

        






"""
@auth.route('/upload', methods=['GET','POST'])
def upload_page():
    pic = request.files['pic']
    if not pic:
        flash('No pic uploaded', category='error')
    name = request.files[secure_filename(pic.name)]
    mimetype = request.files[(pic.mimetype)]
    img = Img(img=pic.read(), mimetype=mimetype, name=name)
    db.session.add(img)
    db.session.commit()
    return 'Image has been uploaded!', 200
    #return render_template("upload_page.html")
"""
