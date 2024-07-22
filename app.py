from flask import Flask, redirect, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db'
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(200))
    last_name = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def check_password_strength(password):
    min_length = 8
    uppercase_regex = re.compile(r'[A-Z]')
    lowercase_regex = re.compile(r'[a-z]')
    digit_regex = re.compile(r'\d')

    messages = []

    if len(password) < min_length:
        messages.append(f"Password must be at least {min_length} characters long.")
    if not uppercase_regex.search(password):
        messages.append("Password must contain at least one uppercase letter.")
    if not lowercase_regex.search(password):
        messages.append("Password must contain at least one lowercase letter.")
    if not digit_regex.search(password):
        messages.append("Password must contain at least one digit.")

    return messages

@app.route('/', methods=['GET'])
@login_required
def get_home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/secretPage')
        else:
            flash('Invalid email or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!')
            return render_template('signup.html')
        
        # Check password constraints
        password_messages = check_password_strength(password)
        if password_messages:
            for message in password_messages:
                flash(message)
            return render_template('signup.html')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already used!')
            return render_template('signup.html')
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return render_template('thankyou.html')
    return render_template('signup.html')

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/secretPage', methods=['GET'])
@login_required
def secret_page():
    return render_template('secretPage.html')

def init_db():
    with app.app_context():
        db.create_all()
        print('Initialized the database.')

if __name__ == '__main__':
    init_db()  # Initialize the database before starting the server
    app.run(debug=True)
