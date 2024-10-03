import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, FloatField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo
import requests
import threading
import time
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# 加載環境變數
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 用戶模型
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

# 訪問模型
class Visit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    num_visits = db.Column(db.Integer, nullable=False)
    interval = db.Column(db.Float, nullable=False)

# 系統狀態模型
class SystemStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_locked = db.Column(db.Boolean, default=False)

# 登入用戶
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 註冊表單
class RegisterForm(FlaskForm):
    username = StringField('用戶名', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('密碼', validators=[DataRequired(), Length(min=6, max=150)])
    confirm_password = PasswordField('確認密碼', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('註冊')

# 登入表單
class LoginForm(FlaskForm):
    username = StringField('用戶名', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('密碼', validators=[DataRequired(), Length(min=6, max=150)])
    submit = SubmitField('登入')

# 訪問表單
class VisitForm(FlaskForm):
    url = StringField('輸入網址', validators=[DataRequired()])
    num_visits = IntegerField('訪問次數', validators=[DataRequired()])
    interval = FloatField('訪問間隔時間（秒）', validators=[DataRequired()])
    submit = SubmitField('開始訪問')

@app.route('/dashboard')
@login_required
def dashboard():
    visits = Visit.query.all()
    system_status = SystemStatus.query.first()
    return render_template('dashboard.html', visits=visits, username=current_user.username, is_locked=system_status.is_locked)

@app.route('/visit', methods=['POST'])
@login_required
def visit():
    form = VisitForm()
    if form.validate_on_submit():
        url = form.url.data
        num_visits = form.num_visits.data
        interval = form.interval.data

        new_visit = Visit(url=url, num_visits=num_visits, interval=interval)
        db.session.add(new_visit)
        db.session.commit()

        def make_requests(visit):
            for _ in range(visit.num_visits):
                try:
                    response = requests.get(visit.url)
                    print(f"Visited {visit.url}: Status Code {response.status_code}")
                except requests.exceptions.RequestException as e:
                    print(f"Failed to visit {visit.url}: {e}")
                time.sleep(visit.interval)

        threading.Thread(target=make_requests, args=(new_visit,)).start()
        flash('訪問開始!', 'success')
        return redirect(url_for('dashboard'))
    flash('訪問失敗，請檢查輸入.', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/stop/<int:visit_id>', methods=['POST'])
@login_required
def stop_visit(visit_id):
    visit = Visit.query.get_or_404(visit_id)
    db.session.delete(visit)
    db.session.commit()
    flash('訪問已停止!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('登入失敗，請檢查您的用戶名和密碼', 'danger')
    return render_template('login.html', form=form)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('註冊成功，請登入!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/api/visits', methods=['GET'])
@login_required
def get_visits():
    visits = Visit.query.all()
    visits_data = [{'id': visit.id, 'url': visit.url, 'num_visits': visit.num_visits, 'interval': visit.interval} for visit in visits]
    return jsonify(visits_data)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # 驗證管理員帳號和密碼（從環境變數引入）
        admin_username = os.getenv('ADMIN_USERNAME', 'admin')
        admin_password = os.getenv('ADMIN_PASSWORD', 'password')

        if username == admin_username and password == admin_password:
            return render_template('admin.html', is_locked=SystemStatus.query.first().is_locked)

        flash('帳號或密碼錯誤', 'danger')

    return render_template('admin_login.html')

@app.route('/admin/lock', methods=['POST'])
@login_required
def lock_system():
    system_status = SystemStatus.query.first()
    if not system_status:
        system_status = SystemStatus(is_locked=True)
        db.session.add(system_status)
    else:
        system_status.is_locked = True
    db.session.commit()
    flash('系統已鎖定，稍後將無法訪問!', 'warning')
    return redirect(url_for('admin'))

@app.route('/admin/unlock', methods=['POST'])
@login_required
def unlock_system():
    system_status = SystemStatus.query.first()
    if system_status:
        system_status.is_locked = False
        db.session.commit()
        flash('系統已啟用，現在可以訪問!', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/download_db', methods=['GET'])
@login_required
def download_db():
    return send_file('users.db', as_attachment=True)

if __name__ == '__main__':
    if not os.path.exists('users.db'):
        db.create_all()
        # 初始化系統狀態
        db.session.add(SystemStatus())
        db.session.commit()
    app.run(port=10000, host='0.0.0.0', debug=True)
