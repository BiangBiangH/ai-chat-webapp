# app.py
from flask import Flask, render_template, request, jsonify, current_app, redirect, url_for  # 新增 redirect 和 url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import requests

# 加载环境变量
load_dotenv()

# 创建Flask应用实例（必须放在最前面）
app = Flask(__name__)

# 配置应用
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SF_API_KEY'] = os.getenv('SF_API_KEY')

# 初始化扩展
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# 用户模型定义
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# 添加在现有路由之前或之后均可（建议放在前面）
@app.route('/')
def index():
    # 如果用户已登录，跳转到聊天页；否则跳转到登录页
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    else:
        return redirect(url_for('login'))


# 用户加载器
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('chat'))
        return '无效的用户名或密码'
    return render_template('login.html')


# 登出路由
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


# 聊天路由
@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == 'POST':
        user_input = request.form.get('message')
        if not user_input:
            return jsonify({'error': '消息内容不能为空'}), 400

        response = get_ai_response(user_input)
        return jsonify({'response': response})
    return render_template('chat.html')


# API调用函数
def get_ai_response(prompt):
    headers = {
        "Authorization": f"Bearer {current_app.config['SF_API_KEY']}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "deepseek-ai/DeepSeek-V3",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 512
    }

    try:
        response = requests.post(
            "https://api.siliconflow.cn/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"API请求失败: {str(e)}")
        return "服务暂时不可用，请稍后再试"
    except KeyError:
        current_app.logger.error("API响应格式异常")
        return "收到意外的响应格式"

# 在文件底部添加以下代码（不要删除已有路由）

@app.cli.command('init-db')
def init_db():
    """初始化数据库命令"""
    with app.app_context():
        db.create_all()
    print('✅ 数据库初始化完成')

if __name__ == '__main__':
    # 开发环境直接运行
    with app.app_context():
        db.create_all()
    app.run(debug=True)

