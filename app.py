#----------------------------------------------------------------------------#
# Imports
#----------------------------------------------------------------------------#

from flask import Flask, flash, render_template, request, url_for, redirect, session, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import *

import logging
from logging import Formatter, FileHandler
from forms import RegisterForm, LoginForm, ForgotForm

from werkzeug.security import generate_password_hash, check_password_hash

from flask.ext.login import LoginManager, login_user, logout_user, current_user, login_required

#----------------------------------------------------------------------------#
# App Config.
#----------------------------------------------------------------------------#
app = Flask(__name__)
app.debug = True
app.config.from_object('config')

#----------------------------------------------------------------------------#
# DB
#----------------------------------------------------------------------------#
db = SQLAlchemy(app)

# Set your classes here.
class Users(db.Model):
    __tablename__ = 'users'
    user_id = Column('user_id', String, primary_key=True)
    password_hash = Column('password_hash', String)
    address = Column('address', String)
    contact_number = Column('contact_number', String)

    def __init__(self, u, p, a, c):
        self.user_id = u
        self.set_password(p)
        self.address = a
        self.contact_number = c

    def set_password(self, p):
        self.password_hash = generate_password_hash(p)

    def check_password(self, p):
        return check_password_hash(self.password_hash, p)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def is_admin(self):
        return user_id == "admin"
    def get_id(self):
        return unicode(self.user_id)

    def __repr__(self):
        return "<User(user id='%s')>" % (self.user_id)

db.drop_all()
db.create_all()

# Register Admin
# (Anybody who has a better idea about admin? LOL LOL)
admin = Users("admin", "1", "", "")
db.session.add(admin)
db.session.commit()

#----------------------------------------------------------------------------#
# Login
#----------------------------------------------------------------------------#
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

# Automatically tear down SQLAlchemy.
'''
@app.teardown_request
def shutdown_session(exception=None):
    db_session.remove()
'''

# Login required decorator.
'''
def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return test(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))
    return wrap
'''

#----------------------------------------------------------------------------#
# Controllers.
#----------------------------------------------------------------------------#
@app.before_request
def before_request():
    g.user = current_user

@app.route('/')
def home():
    return render_template('pages/placeholder.home.html')


@app.route('/about')
def about():
    return render_template('pages/placeholder.about.html')


@app.route('/login', methods=["GET","POST"])
def login():
    form = LoginForm(request.form)
    if (request.method == "GET"):
        return render_template('forms/login.html', form = form)

    user_id = form.user_id.data
    password = form.password.data
    registered_user = Users.query.filter_by(user_id = user_id).first()
    if registered_user is None:
        flash('Username is invalid' , 'error')
        return redirect(url_for('login'))
    if not registered_user.check_password(password):
        flash('Password is invalid','error')
        return redirect(url_for('login'))
    login_user(registered_user, remember = False)
    flash('Logged in successfully')
    print(request.args.get('next'))
    return redirect(request.args.get('next') or url_for('home'))


@app.route('/register', methods=["GET","POST"])
def register():
    form = RegisterForm(request.form)
    if(request.method == "POST"):
        if not (form.validate_on_submit()):
            flash('User info is invalid. Try again')
            return render_template('forms/register.html', form=form)
        user = Users(form.user_id.data, form.password_hash.data, form.address.data, form.contact_number.data)
        db.session.add(user)
        db.session.commit()
        flash('User successfully registered')
        return redirect(url_for('login'))
    return render_template('forms/register.html', form=form)

@app.route('/forgot')
def forgot():
    form = ForgotForm(request.form)
    return render_template('forms/forgot.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

# Error handlers.
@app.errorhandler(500)
def internal_error(error):
    #db_session.rollback()
    return render_template('errors/500.html'), 500


@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

if not app.debug:
    file_handler = FileHandler('error.log')
    file_handler.setFormatter(
        Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    )
    app.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.info('errors')

#----------------------------------------------------------------------------#
# Launch.
#----------------------------------------------------------------------------#

# Default port:
if __name__ == '__main__':
    app.run()

# Or specify port manually:
'''
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
'''
