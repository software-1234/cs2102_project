#----------------------------------------------------------------------------#
# Imports
#----------------------------------------------------------------------------#

from flask import Flask, flash, render_template, request, url_for, redirect, session
from wtforms import Form, BooleanField, TextField, PasswordField, validators, PasswordField, StringField
from flask.ext.sqlalchemy import SQLAlchemy
import logging
from logging import Formatter, FileHandler
from forms import RegisterForm, LoginForm, ForgotForm
from flask_wtf import Form
from sqlalchemy import create_engine
from sqlalchemy import Table, Column, String, MetaData

# Set your classes here.


#----------------------------------------------------------------------------#
# App Config.
#----------------------------------------------------------------------------#
app = Flask(__name__)
app.debug = True
app.config.from_object('config')
#db = SQLAlchemy(app)
db = create_engine("postgres://postgres:1@127.0.0.1:5432")
meta = MetaData(db)
users_table = Table('users', meta,
    Column('user_id', String, primary_key=True),
    Column('password_hash', String),
    Column('address', String),
    Column('contact_number', String))
users_table.drop()
users_table.create()


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


@app.route('/')
def home():
    return render_template('pages/placeholder.home.html')


@app.route('/about')
def about():
    return render_template('pages/placeholder.about.html')


@app.route('/login')
def login():
    form = LoginForm(request.form)
    return render_template('forms/login.html', form=form)


@app.route('/register', methods=["GET","POST"])
def register():
    form = RegisterForm(request.form)

    if(request.method == "POST"):
        insert_statement = users_table.insert().values(user_id = form.user_id.data, password_hash = form.password_hash.data, address = form.address.data, contact_number = form.contact_number.data)
        db.connect().execute(insert_statement)
        return redirect(url_for('login'))
    return render_template('forms/register.html', form=form)



@app.route('/forgot')
def forgot():
    form = ForgotForm(request.form)
    return render_template('forms/forgot.html', form=form)

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
