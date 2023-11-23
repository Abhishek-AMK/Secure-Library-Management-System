import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
import hashlib
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
import logging
from flask_limiter.util import get_remote_address


app = Flask(__name__, static_url_path='/static', template_folder='templates')

app.secret_key = os.urandom(24)  # Secure, random key
bcrypt = Bcrypt(app)
limiter = Limiter(app)

# Logging setup
logging.basicConfig(filename='app.log', level=logging.INFO)


# Replace this dictionary with a database in a real application
users = {}


@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('5/minute')  # Rate limiting
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Input validation
        if not username or not password:
            flash('Please enter both username and password')
            return redirect(url_for('login'))

        if username in users and bcrypt.check_password_hash(users[username], password):
            session['user'] = username
            return redirect(url_for('index'))
        else:
            # Generic error message
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception('Error: ')  # Log the error
    return render_template('500.html'), 500

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users:
            flash('Username already exists. Try a different username.', 'error')
        else:
            bcrypt_password = bcrypt.generate_password_hash(password).decode('utf-8')
            users[username] = bcrypt_password
            flash('Registration successful. You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

def hash_password_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_password_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()

if __name__ == '__main__':
    app.run(debug=True)
