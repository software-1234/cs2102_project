#----------------------------------------------------------------------------#
# Imports
#----------------------------------------------------------------------------#
from flask import Flask, flash, render_template, request, url_for, redirect, session, g

import logging
from logging import Formatter, FileHandler
from forms import *

from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import LoginManager, login_user, logout_user, current_user, login_required, AnonymousUserMixin
from functools import wraps

#----------------------------------------------------------------------------#
# App Config.
#----------------------------------------------------------------------------#
app = Flask(__name__)
app.debug = True
app.config.from_object('config')

#----------------------------------------------------------------------------#
# DB
#----------------------------------------------------------------------------#
from models import db, Users, Tasks, Bids, create_db, add_admin, Anonymous

#----------------------------------------------------------------------------#
# Login
#----------------------------------------------------------------------------#
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.anonymous_user = Anonymous

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
    page = request.args.get('page', 1, type=int)
    tasks = Tasks.query.order_by(Tasks.last_updated.desc()).paginate(
        page, 20, False
    )
    next_url = None
    if tasks.has_next:
        next_url = url_for('home', page=tasks.next_num)
    prev_url = None
    if tasks.has_prev:
        prev_url = url_for('home', page=tasks.prev_num)
    tasks = tasks.items
    for task in tasks:
        bids = Bids.query.filter_by(task_id=task.task_id).order_by(Bids.status.desc()).all()
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
            print(form.errors)
            flash('Task info is invalid. Try again')
            return render_template('pages/placeholder.add.html', form=form)
        task = Tasks(form.datetime_start.data, form.datetime_end.data, form.address.data, form.title.data, form.description.data, form.min_bid.data, form.datetime_expire.data)
        db.session.add(task)
        db.session.commit()
        flash('A task successfully added')
        return redirect(request.args.get('next') or url_for('home'))
    return render_template('pages/placeholder.add.html', form=form)

@login_required
@app.route('/<int:tid>/delete', methods=["GET","POST"])
def delete(tid):
    if (request.method == "POST"):
        Tasks.query.filter_by(task_id = tid).delete()
        db.session.commit()
        flash('Task successfully deleted')
        return redirect(url_for('home'))
    else:
        return render_template('pages/placeholder.delete.html', tid=tid)

@login_required
@app.route('/<int:tid>/modify', methods=["GET","POST"])
def modify(tid):
    if(request.method == "POST"):
        form = AddForm(request.form)
        if not (form.validate_on_submit()):
            flash('Task info is invalid. Try again')
            return render_template('pages/placeholder.modify.html', form=form, task=task)
        Tasks.query.filter_by(task_id = tid).update({'title':form.title.data, 'description':form.description.data, 'datetime_start':form.datetime_start.data, 'datetime_end':form.datetime_end.data, 'address':form.address.data, 'min_bid':form.min_bid.data, 'datetime_expire':form.datetime_expire.data})
        db.session.commit()
        flash('A task successfully modified')
        return redirect(request.args.get('next') or url_for('home'))
    else:
        form = AddForm(request.form)
        task = Tasks.query.filter_by(task_id = tid).first()
        return render_template('pages/placeholder.modify.html', form=form, task=task)

@login_required
@app.route('/mytasks_employer')
def mytasks_employer():
    page = request.args.get('page', 1, type=int)
    tasks = Tasks.query.filter_by(employer_user_id=current_user.get_id()).order_by(Tasks.last_updated.desc()).paginate(
        page, 20, False
    )
    next_url = None
    if tasks.has_next:
        next_url = url_for('mytasks_employer', page=tasks.next_num)
    prev_url = None
    if tasks.has_prev:
        prev_url = url_for('mytasks_employer', page=tasks.prev_num)
    tasks = tasks.items
    for task in tasks:
        bids = Bids.query.filter_by(task_id=task.task_id).order_by(Bids.status.desc()).all()
    return render_template('pages/placeholder.mytasks.employer.html', **locals())

@login_required
@app.route('/mytasks_employee')
def mytasks_employee():
    page = request.args.get('page', 1, type=int)
    tasks = Tasks.query.filter_by(employee_user_id=current_user.get_id()).order_by(Tasks.last_updated.desc()).paginate(
        page, 20, False
    )
    next_url = None
    if tasks.has_next:
        next_url = url_for('mytasks_employee', page=tasks.next_num)
    prev_url = None
    if tasks.has_prev:
        prev_url = url_for('mytasks_employee', page=tasks.prev_num)
    tasks = tasks.items
    for task in tasks:
        bids = Bids.query.filter_by(task_id=task.task_id).order_by(Bids.status.desc()).all()
    return render_template('pages/placeholder.mytasks.employee.html', **locals())

@login_required
@app.route('/search', methods=["POST"])
def search():
    if(request.method == "POST"):
        search = request.form['search']
        page = request.args.get('page', 1, type=int)
        t1 = Tasks.query.filter(Tasks.title.ilike('%'+search+'%'))
        t2 = Tasks.query.filter(Tasks.description.ilike('%'+search+'%'))
        t3 = Tasks.query.filter(Tasks.address.ilike('%'+search+'%'))
        tasks = t1.union(t2).union(t3).order_by(Tasks.last_updated.desc()).paginate(
            page, 20, False
        )
        next_url = None
        if tasks.has_next:
            next_url = url_for('search', page=tasks.next_num)
        prev_url = None
        if tasks.has_prev:
            prev_url = url_for('search', page=tasks.prev_num)
        tasks = tasks.items
        for task in tasks:
            bids = Bids.query.filter_by(task_id=task.task_id).order_by(Bids.status.desc()).all()
        role = "employee"
        return render_template('pages/placeholder.search.html', **locals())


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
    create_db(drop_all=False)
    add_admin()
    app.run()


# Or specify port manually:
'''
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
'''
