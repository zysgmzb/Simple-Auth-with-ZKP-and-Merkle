from nicegui import app, ui
import hashlib
import json
import os
import zokrates_cmd

USER_DATA_FILE = "users.json"

if os.path.exists(USER_DATA_FILE):
    with open(USER_DATA_FILE, "r") as f:
        app.storage.general["users"] = json.load(f)
else:
    app.storage.general["users"] = {}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


@ui.page('/register')
def register_page():
    ui.label("用户注册").classes("text-h4")
    username = ui.input("用户名").classes("w-64")
    password = ui.input("密码", password=True).classes("w-64")
    confirm_password = ui.input("确认密码", password=True).classes("w-64")
    error = ui.label("").classes("text-red-500")

    def submit():
        if not username.value or not password.value:
            error.text = "用户名和密码不能为空"
            return

        if password.value != confirm_password.value:
            error.text = "两次输入密码不一致"
            return

        if username.value in app.storage.general["users"]:
            error.text = "用户名已存在"
            return

        # 保存哈希后的密码
        app.storage.general["users"][username.value] = {
            "password_hash": hash_password(password.value)
        }
        save_users()  # 持久化到文件
        ui.notify("注册成功！")
        ui.navigate.to("/login")

    ui.button("注册", on_click=submit).classes("w-32")

# 登录页面


@ui.page('/login')
def login_page():
    ui.label("用户登录").classes("text-h4")
    username = ui.input("用户名").classes("w-64")
    password = ui.input("密码", password=True).classes("w-64")
    error = ui.label("").classes("text-red-500")

    def submit():
        user_data = app.storage.general["users"].get(username.value)
        if not user_data:
            error.text = "用户名不存在"
            return

        if hash_password(password.value) != user_data["password_hash"]:
            error.text = "密码错误"
            return

        # 设置用户会话
        app.storage.user.update({
            "authenticated": True,
            "username": username.value
        })
        ui.navigate.to("/dashboard")

    ui.button("登录", on_click=submit).classes("w-32")
    ui.button("注册", on_click=lambda: ui.navigate.to(
        "/register")).classes("w-32")

# 主页（需要登录）


@ui.page('/dashboard')
def main_page():
    if not app.storage.user.get("authenticated"):
        ui.navigate.to("/login")
        return

    # 显示用户信息
    ui.label(f"欢迎回来，{app.storage.user['username']}!").classes("text-h4")

    # 注销按钮
    def logout():
        app.storage.user.clear()
        ui.navigate.to("/login")
    ui.button("注销", on_click=logout).classes("w-32")

# 保存用户数据到文件


def save_users():
    with open(USER_DATA_FILE, "w") as f:
        json.dump(app.storage.general["users"], f)


# 关闭时自动保存数据
app.on_shutdown(save_users)

# 启动应用
ui.run(title="用户认证系统", storage_secret="test")
