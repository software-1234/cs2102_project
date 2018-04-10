#----------------------------------------------------------------------------#
# Imports
#----------------------------------------------------------------------------#
from flask import Flask, flash, render_template, request, url_for, redirect, session, g

import logging
from logging import Formatter, FileHandler
from forms import *

from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import LoginManager, login_user, logout_user, current_user, login_required

#----------------------------------------------------------------------------#
# App Config.
#----------------------------------------------------------------------------#
app = Flask(__name__)
app.debug = True
app.config.from_object('config')

#----------------------------------------------------------------------------#
# DB
#----------------------------------------------------------------------------#
from models import db, Users, Tasks, Bids

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

#----------------------------------------------------------------------------#
# Controllers.
#----------------------------------------------------------------------------#
@app.before_request
def before_request():
    g.user = current_user

@app.route('/')
def home():
    tasks = Tasks.query.all()
    return render_template('pages/placeholder.home.html', **locals())


@app.route('/about')
def about():
    return render_template('pages/placeholder.about.html')

@login_required
@app.route('/add', methods=["GET","POST"])
def add():
    form = AddForm(request.form)
    if(request.method == "POST"):
        if not (form.validate_on_submit()):
            flash('Task info is invalid. Try again')
            return render_template('pages/placeholder.add.html', form=form)
        task = Tasks(form.datetime_start.data, form.datetime_end.data, form.address.data, form.title.data, form.description.data, form.min_bid.data, form.datetime_expire.data)
        db.session.add(task)
        db.session.commit()
        flash('A task successfully added')
        return redirect(request.args.get('next') or url_for('home'))
    return render_template('pages/placeholder.add.html', form=form)

@login_required
@app.route('/mytasks_employer')
def mytasks_employer():
    tasks = Tasks.query.filter_by(employer_user_id=current_user.get_id()).all()
    tasks_len = len(tasks)
    return render_template('pages/placeholder.mytasks.html', **locals())

@login_required
@app.route('/mytasks_empolyee')
def mytasks_employee():
    tasks = Tasks.query.filter_by(employee_user_id=current_user.get_id()).all()
    tasks_len = len(tasks)
    return render_template('pages/placeholder.mytasks.html', **locals())

@login_required
@app.route('/my_profile')
def my_profile():
    form = RegisterForm(request.form)
    profile = Users.query.filter_by(user_id=current_user.get_id()).first()
    return render_template('pages/placeholder.myprofile.html', **locals())

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
    return redirect(request.args.get('next') or url_for('home'))


@app.route('/register', methods=["GET","POST"])
def register():
    form = RegisterForm(request.form)
    if(request.method == "POST"):
        if not (form.validate_on_submit()):
            flash('User info is invalid. Try again')
            return render_template('forms/register.html', form=form)
        user = db.session.query(Users).filter_by(user_id = form.user_id.data).first()
        if user:
            flash('User name is already taken. Try again')
            return render_template('forms/register.html', form=form)
        user = Users(form.user_id.data, form.password_hash.data, form.address.data, form.contact_number.data, form.display_name.data)
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
