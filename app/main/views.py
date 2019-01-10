# vim: sw=4:ts=4:et

import logging
from . import main
from .forms import AppModeSelectionForm
from flask import render_template, session, redirect, url_for, flash
from flask_login import current_user

@main.route('/', methods=['GET', 'POST'])
def index():
    # are we logged in?
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    form = AppModeSelectionForm()
    if form.validate_on_submit():
        if form.manage_alerts.data: # submit form .data value is True when clicked
            flash("Feature is not implemented yet.")
        else:
            return redirect(url_for('analysis.index'))

    return render_template('index.html', form=form)#, ace_config=saq.CONFIG)
