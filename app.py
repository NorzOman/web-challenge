from flask import Flask, render_template, redirect, url_for, request, session, make_response
from functools import wraps
import json
import base64
import re

app = Flask(__name__)
app.secret_key = 'really_super_duper_secret_that_no_man_can_guess_78798794546'

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def load_credentials():
    try:
        with open('credentials.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {'users': []}

def save_credentials(credentials):
    with open('credentials.json', 'w') as file:
        json.dump(credentials, file, indent=2)

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        session.pop('logged_in', None)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            return render_template('login.html', error='Email and password are required')
        credentials = load_credentials()
        for user in credentials['users']:
            if user['email'] == email and user['password'] == password:
                session['logged_in'] = True
                session['email'] = email
                return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid email or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        security_answer = request.form.get('security_answer')

        if not email or not password or not security_answer:
            return render_template('signup.html', error='All fields are required')

        if len(security_answer.split()) > 20:
            return render_template('signup.html', error='Security answer should not be more than 20 words')

        credentials = load_credentials()
        for user in credentials['users']:
            if user['email'] == email:
                return render_template('signup.html', error='Email already exists')

        new_user = {
            'email': email,
            'password': password,
            'answer': security_answer
        }
        credentials['users'].append(new_user)
        save_credentials(credentials)

        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        security_answer = request.form.get('security_answer')
        if not email or not security_answer:
            return render_template('forgot_password.html', error='Email and security answer are required')
        credentials = load_credentials()
        for user in credentials['users']:
            if user['email'] == email and user.get('answer') == security_answer:
                encoded_email = base64.b64encode(email.encode()).decode()
                response = make_response(redirect(url_for('new_pass')))
                response.set_cookie('ValidRecoveryAttempt', encoded_email)
                return response
        return render_template('forgot_password.html', error='Invalid email or security answer')
    return render_template('forgot_password.html')

@app.route('/new_pass')
def new_pass():
    encoded_email = request.cookies.get('ValidRecoveryAttempt')
    if encoded_email:
        try:
            email = base64.b64decode(encoded_email).decode()
            if email == "admin171@gmail.com":
                return render_template('new_pass.html', email=email, text="Succesfull Breach : Your Flag DJSISACA{pAss_1337_adm1n}")
            credentials = load_credentials()
            for user in credentials['users']:
                if user['email'] == email:
                    user['password'] = 'pass'
                    save_credentials(credentials)
                    return render_template('new_pass.html', email=email)
            return render_template('login.html', error="User not found")
        except Exception as e:
            app.logger.error(f"Error in new_pass: {str(e)}")
            return render_template('login.html', error="An error occurred during password reset")
    return render_template('login.html', error="Invalid password reset attempt")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
