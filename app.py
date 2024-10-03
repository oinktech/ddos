from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Statistics Model
class Stats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    visits = db.Column(db.Integer, nullable=False)
    interval = db.Column(db.Integer, nullable=False)

def create_database():
    with app.app_context():
        if not os.path.exists('users.db'):
            db.create_all()
            print("Database created.")

# Create the database if it doesn't exist
create_database()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        url = request.form['url']
        visits = request.form['visits']
        interval = request.form['interval']
        new_stat = Stats(url=url, visits=visits, interval=interval)
        db.session.add(new_stat)
        db.session.commit()
        flash('Statistics added successfully!')
    stats = Stats.query.all()
    return render_template('dashboard.html', stats=stats)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if request.method == 'POST':
        if request.form['username'] == os.getenv('ADMIN_USERNAME') and request.form['password'] == os.getenv('ADMIN_PASSWORD'):
            session['site_status'] = not session.get('site_status', True)
            if not session['site_status']:
                return redirect(url_for('update'))
    
    # Handle deleting statistics
    if 'delete_id' in request.args:
        stat_id = request.args.get('delete_id')
        stat_to_delete = Stats.query.get(stat_id)
        if stat_to_delete:
            db.session.delete(stat_to_delete)
            db.session.commit()
            flash('Statistic deleted successfully!')
    
    return render_template('admin.html')

@app.route('/update')
def update():
    return render_template('update.html')



@app.route('/')
def index():
    if session.get('site_status', True) == False:
        return render_template('update.html')
    return render_template('index.html')

@app.route('/download')
@login_required
def download():
    return send_file('users.db', as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)
