from flask import Flask, render_template, request, redirect, url_for, flash, session
import hashlib
from flask_bcrypt import Bcrypt

app = Flask(__name__, static_url_path='/static', template_folder='templates')
app.secret_key = 'I_AM_ABHISHEK'  # Replace with a strong, random key
bcrypt = Bcrypt(app)

# Replace this dictionary with a database in a real application
users = {}

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users:
            stored_password = users[username]

            if bcrypt.check_password_hash(stored_password, password):
                session['user'] = username
                return redirect(url_for('index'))  # Corrected here
            elif stored_password == hash_password_md5(password):
                session['user'] = username
                return redirect(url_for('index'))  # Corrected here
            elif stored_password == hash_password_sha256(password):
                session['user'] = username
                return redirect(url_for('index'))  # Corrected here

        flash('Invalid username or password', 'error')

    return render_template('login.html')

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
