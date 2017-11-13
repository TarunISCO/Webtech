import urllib
import requests
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask import json
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
from flask.ext.googlemaps import GoogleMaps
from app_data import states

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mysql@3105'
app.config['MYSQL_DB'] = 'crop_management'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MYSQL
mysql = MySQL(app)

GoogleMaps(app)
# Index
@app.route('/')
def index():
    return render_template('home.html')


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50), validators.DataRequired()])
    email = StringField('Email', [validators.Email(), validators.DataRequired()])
    contact = StringField('Contact Number', [validators.Length(min=10, max=10)])
    password = PasswordField('Password', [
        validators.Length(max=25),
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


#Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        contact = form.contact.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO user(name, email, contact, password) VALUES(%s, %s, %s, %s)",
                    (name, email, contact, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        email = request.form['email']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by email
        result = cur.execute('SELECT * FROM user WHERE email = %s', [email])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                # Get user name by email
                name = data['name']
                session['username'] = name

                flash('You are now logged in', 'success')
                return redirect(url_for('index'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Email not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Mazor Crops
@app.route('/mazor_crops')
def mazor_crops():
    # Create Cursor
    cur = mysql.connection.cursor()

    # Get mazor crops
    result = cur.execute("SELECT * FROM crops")

    crops = cur.fetchall()

    if result > 0:
        return render_template('mazor_crops.html', mazor_crops=crops)
    else:
        msg = 'No Articles Found'
        return render_template('mazor_crops.html', msg=msg)
    # Close connection
    cur.close()


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('/login'))
    return wrap


# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('index'))


# Warehouse
@app.route('/warehouse')
def warehouse():

    return render_template('warehouse.html')


@app.route('/policies')
def policies():
    return render_template('policies.html')

@app.route('/laboratories', methods=['GET', 'POST'])
def laboratories():
    if request.method == 'POST':
        state = request.form['state']
        # Create Cursor
        cur = mysql.connection.cursor()

        # Get mazor crops
        result = cur.execute("SELECT * FROM diagnosticlabs WHERE State_Name = %s", [state])

        labs = cur.fetchall()

        if result > 0:
            return render_template('state_labs.html', state=state, labs=labs)
        else:
            msg = 'No Labs found'
            return render_template('state_labs.html', state=state, msg=msg)
        # Close connection
        cur.close()

        return render_template('state_labs.html',state=state)
    return render_template('laboratories.html', states=states)

@app.route('/testinglabs', methods=['GET', 'POST'])
def testinglabs():
    if request.method == 'POST':
        state = request.form['state']
        url_tag = state.replace(" ", "-")
        return render_template('test_labs.html',state=state)
    return render_template('testinglabs.html', states=states)

@app.route('/market', methods=['POST','GET'])
def trend():
    r = requests.get('https://newsapi.org/v1/articles?source=the-times-of-india&sortBy=latest&apiKey=e77d6e63c62547d5a6d0adc4d5cad012')
    response = r.text
    data = json.loads(response)
    news = data['articles']
    if 'ok' in data['status']:
        return render_template('news.html', news=news)
    else:
        msg = 'Sorry!! Try Later'
        return render_template('news.html', msg=msg)

@app.route('/weather')
def weather():
    return render_template('weather.html')

if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True)
