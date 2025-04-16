from flask import Flask, redirect, url_for, render_template, request, session, jsonify
from flask_wtf.csrf import CSRFProtect
import os
import zokrates_cmd
import untils
import user_manager
import merkle_tree
import hashlib
import onchain_verify

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['WTF_CSRF_ENABLED'] = True
csrf = CSRFProtect(app)

Users = user_manager.UserManager()
MerkleTree = merkle_tree.MerkleTree()

zokrates_cmd.setup('merkle.zok')
anvil_process = onchain_verify.start_anvil()
onchain_verify.compile_verifier()
verifier_address = onchain_verify.deploy_zk_verifier()


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if 'token_file' not in request.files:
            return render_template('login.html', error='请选择令牌文件')

        if 'password' not in request.form:
            return render_template('login.html', error='请输入密码')

        file = request.files['token_file']
        password = request.form['password']

        if not file.filename.endswith('.zys'):
            return render_template('login.html', error='只能上传 .zys 文件')

        if file.filename == '':
            return render_template('login.html', error='无效的文件')

        try:
            token = file.read().decode('utf-8').strip()
            assert untils.check_format(token)
            abc, inputs = untils.decode_user_proof(token, password)
            assert onchain_verify.verify(abc, inputs, verifier_address)
            user_root = untils.convert_u32_list_to_u256(inputs)
            user_root = hex(user_root)[2:].zfill(64)
            login_user = Users.get_user_by_root(user_root)
            session['userid'] = login_user.user_id
            session['username'] = login_user.username
            session['role'] = login_user.role
            return redirect(url_for('dashboard' if login_user.role == 'user' else 'dashboard'))

        except Exception as e:
            print(f"登录失败: {e}")
            return render_template('login.html', error='无效的令牌或密码')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            username = request.form.get('username', '').strip()
            role = request.form.get('role', '').strip()
            mail = request.form.get('mail', '').strip()
            password = request.form.get('password', '').strip()

            if not username or not role or not mail or not password:
                return jsonify({'success': False, 'error': '请填写完整'})

            if not untils.check_mail_format(mail):
                return jsonify({'success': False, 'error': '无效的邮箱地址'})

            user_num_now = Users.user_num
            user_hash = hashlib.sha256(
                f'{user_num_now+1}{username}{role}{mail}'.encode()).hexdigest()
            MerkleTree.update_leaf(user_num_now, user_hash)
            root_now = MerkleTree.get_merkle_root()
            root, leaf, direction, path = MerkleTree.generate_proof_path_and_direction(
                user_num_now)
            zokrates_cmd.generate_proof(
                root, leaf, direction, path, user_num_now+1)
            user_token = untils.generate_user_key_format(
                user_num_now+1, password)
            Users.register(username, role, mail,
                           root_now, password, user_token)
            zokrates_cmd.clear_user_proof(user_num_now+1)

            return jsonify({
                'success': True,
                'token_content': user_token,
                'filename': f'{username}_token.zys'
            })

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'userid' not in session or 'username' not in session or 'role' not in session:
        return redirect(url_for('login'))

    if session['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))

    user_id = session['userid']
    username = session['username']

    return render_template('dashboard.html', user_id=user_id, username=username)


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'userid' not in session or 'username' not in session or 'role' not in session:
        return redirect(url_for('login'))

    if session['role'] == 'user':
        return redirect(url_for('dashboard'))

    user_id = session['userid']
    username = session['username']

    return render_template('admin_dashboard.html', user_id=user_id, username=username)


@app.route('/user_update_information', methods=['GET', 'POST'])
def update_information():
    if request.method == 'POST':
        if 'userid' not in session or 'username' not in session or 'role' not in session:
            return redirect(url_for('login'))

        user_id = session['userid']
        current_user = Users.get_user(user_id)
        new_name = request.form.get('new_name', '').strip()
        new_mail = request.form.get('new_mail', '').strip()
        new_password = request.form.get('new_password', '').strip()

        if (new_password == ''):
            return jsonify({'success': False, 'error': '密码为必填项'})

        if (new_name == ''):
            new_name = current_user.username
        if (new_mail == ''):
            new_mail = current_user.mail

        if not untils.check_mail_format(new_mail):
            return jsonify({'success': False, 'error': '无效的邮箱地址'})

        new_user_hash = hashlib.sha256(
            f'{user_id}{new_name}{current_user.role}{new_mail}'.encode()).hexdigest()
        MerkleTree.update_leaf(user_id-1, new_user_hash)
        root, leaf, direction, path = MerkleTree.generate_proof_path_and_direction(
            user_id-1)
        zokrates_cmd.generate_proof(
            root, leaf, direction, path, user_id)
        user_token = untils.generate_user_key_format(
            user_id, new_password)
        zokrates_cmd.clear_user_proof(user_id)
        Users.update_information(user_id, new_name, current_user.role,
                                 new_mail, MerkleTree.get_merkle_root(), new_password, user_token)

        return jsonify({
            'success': True,
            'token_content': user_token,
            'filename': f'{new_name}_token.zys'
        })
    return render_template('user_update_info.html')


@app.route('/admin_check_information')
def admin_check_information():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    users = []
    with Users.get_conn() as conn:
        cursor = conn.execute(
            "SELECT id, username, role, mail, root_now FROM users")
        for row in cursor.fetchall():
            users.append({
                'id': row[0],
                'username': row[1],
                'role': row[2],
                'mail': row[3],
                'root_now': row[4]
            })

    return render_template('admin_panel.html', users=users)


@app.route('/admin_download_user_token', methods=['POST'])
def admin_download_user_token():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    userid = request.form.get('userid', '').strip()
    user_token = Users.get_user_login_token(userid)
    username = Users.get_user(userid).username

    return jsonify({
        'success': True,
        'token_content': user_token,
        'filename': f'{username}_token.zys'
    })


@app.route('/logout')
def logout():
    session.pop('userid', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))


if __name__ == '__main__':

    app.run()
