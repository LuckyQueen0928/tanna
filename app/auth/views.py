# -*- coding: utf-8 -*-

from flask import (
render_template,
request,
session,
redirect,
url_for,
render_template_string
)
from ..models import user_t
from sqlalchemy import and_
from . import auth
from hashlib import md5
from app import db


# 登录页面
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = user_t.query.filter(
            and_(user_t.username == username, user_t.userpassword == md5(password).hexdigest())
            ).first()
        if user:
            session['auth'] = True
            session['username'] = user.username
            return redirect(url_for('main.login_guide'))
        else:
            return render_template(
                'message.html', message="登录错误".decode('utf-8')
            )
    return render_template('auth/loginnew.html')


# 注册页面
@auth.route('/regedit', methods=['GET', 'POST'])
def regedit():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        repassword = request.form['repassword']
        if user_t.query.filter_by(username=username).first():
            return render_template('message.html', message="用户名重复".decode('utf-8'))
        if str(password) != str(repassword):
            return render_template('message.html', message="两次密码不匹配".decode('utf-8'))
        user = user_t(username=username, userpassword=md5(password).hexdigest())
        db.session.add(user)
        db.session.commit()
        return render_template_string(
            '<script>alert("用户创建成功！");window.location.href = "/auth/login";</script>'
        )
    return render_template('auth/regedit.html')


# 重置密码页面
@auth.route('/resetpassword', methods=['GET', 'POST'])
def resetpassword():
    if request.method == 'POST':
        oldpassword = request.form['oldpassword']
        newpassword = request.form['newpassword']
        repassword = request.form['repassword']
        username = session['username']
        if str(newpassword) != str(repassword):
            return render_template('message.html', message="两次密码不匹配".decode('utf-8'))
        # 验证密码
        user = user_t.query.filter(
            and_(user_t.username == username, user_t.userpassword == md5(oldpassword).hexdigest())
            ).first()
        if user:
            user.userpassword = md5(newpassword).hexdigest()
            db.session.commit()
            return render_template_string(
            '<script>alert("Password has changed!Plz login again!");window.location.href = "/auth/logout";</script>'
        )
        else:
            return render_template(
                'message.html', message="密码错误".decode('utf-8')
            )
    return render_template('auth/resetpassword.html')


# 退出登录
@auth.route('/logout', methods=['GET'])
def logout():
    session['username'] = ''
    session['auth'] = ''
    return redirect(url_for('auth.login'))
