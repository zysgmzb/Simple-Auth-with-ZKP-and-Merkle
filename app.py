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
            return redirect(url_for('dashboard'))

        except Exception as e:
            print(f"登录失败: {e}")
            return render_template('login.html', error='无效的令牌或密码')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            username = request.form.get('username', '').strip()
            gender = request.form.get('gender', '').strip()
            birth = request.form.get('birthdate', '').strip()
            password = request.form.get('password', '').strip()

            if not username or not gender or not birth or not password:
                return jsonify({'success': False, 'error': '请填写完整'})

            user_num_now = Users.user_num
            user_hash = hashlib.sha256(
                f'{user_num_now}{username}{gender}{birth}'.encode()).hexdigest()
            MerkleTree.update_leaf(user_num_now, user_hash)
            root_now = MerkleTree.get_merkle_root()
            Users.register(username, gender, birth, root_now, password)
            root, leaf, direction, path = MerkleTree.generate_proof_path_and_direction(
                user_num_now)
            zokrates_cmd.generate_proof(
                root, leaf, direction, path, user_num_now)
            user_token = untils.generate_user_key_format(
                user_num_now, password)
            zokrates_cmd.clear_user_proof(user_num_now)

            return jsonify({
                'success': True,
                'token_content': user_token,
                'filename': f'{username}_token.zys'
            })

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    if 'userid' not in session or 'username' not in session:
        return redirect(url_for('login'))

    user_id = session['userid']
    username = session['username']

    return render_template('dashboard.html', user_id=user_id, username=username)


@app.route('/logout')
def logout():
    session.pop('userid', None)
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':

    app.run()
