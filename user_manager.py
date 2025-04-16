import sqlite3
import hashlib
import threading


class User:
    def __init__(self, user_id, username, role, mail, root_now, password_hash):
        self.user_id = user_id
        self.username = username
        self.role = role
        self.mail = mail
        self.root_now = root_now
        self.password_hash = password_hash


class UserManager:
    def __init__(self):
        self.local = threading.local()
        self.create_table()
        self.user_num = 0
        self.MAX_USER_NUM = 128

    def get_conn(self):
        if not hasattr(self.local, 'conn'):
            self.local.conn = sqlite3.connect(
                'users.db', check_same_thread=False)
        return self.local.conn

    def create_table(self):
        with self.get_conn() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS users(
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            role TEXT,
                            mail TEXT,
                            root_now TEXT,
                            password_hash TEXT NOT NULL,
                            login_token TEXT);''')

    def register(self, username, role, mail, root_now, password, login_token):
        if self.user_num >= self.MAX_USER_NUM:
            return False
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        try:
            with self.get_conn() as conn:
                conn.execute("INSERT INTO users (username, role, mail, root_now, password_hash, login_token) VALUES (?, ?, ?, ?, ?, ?)",
                             (username, role, mail, root_now, password_hash, login_token))
            self.user_num += 1
            return True
        except sqlite3.IntegrityError:
            return False

    def update_information(self, user_id, username, role, mail, root, password, login_token):
        user = self.get_user(user_id)
        if not user:
            return False
        new_password_hash = hashlib.sha256(
            password.encode()).hexdigest() if password else user.password_hash
        with self.get_conn() as conn:
            conn.execute("UPDATE users SET username=?, role=?, mail=?, root_now=?, password_hash=?, login_token=? WHERE id=?",
                         (username, role, mail, root, new_password_hash, login_token, user_id))
        return True

    def get_user(self, user_id):
        with self.get_conn() as conn:
            cursor = conn.execute(
                "SELECT id, username, role, mail, root_now, password_hash FROM users WHERE id=?", (user_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            return User(row[0], row[1], row[2], row[3], row[4], row[5])

    def get_user_by_root(self, user_root):
        with self.get_conn() as conn:
            cursor = conn.execute(
                "SELECT id, username, role, mail, root_now, password_hash FROM users WHERE root_now=?", (user_root,))
            row = cursor.fetchone()
            if row is None:
                return None
            return User(row[0], row[1], row[2], row[3], row[4], row[5])

    def get_user_login_token(self, user_id):
        with self.get_conn() as conn:
            cursor = conn.execute(
                "SELECT login_token FROM users WHERE id=?", (user_id,))
            row = cursor.fetchone()
            if row is None:
                return None
            return row[0]
