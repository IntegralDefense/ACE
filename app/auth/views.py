from flask import render_template, redirect, request, url_for, flash, session
from flask.ext.login import login_user, logout_user, login_required
from . import auth
from .forms import LoginForm
from ..models import User
from .. import db
import logging

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(username=form.username.data).one()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            
            if 'current_storage_dir' in session:
                del session['current_storage_dir']

            response = redirect(request.args.get('next') or url_for('main.index'))
            # remember the username so we can autofill the field
            response.set_cookie('username', user.username)
            return response

        flash('Invalid username or password.')

    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    if 'cid' in session:
        del session['cid']
    flash('You have been logged out.')
    return redirect(url_for('main.index'))
