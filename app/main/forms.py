# vim: sw=4:ts=4:et

from flask.ext.wtf import Form
from wtforms import StringField, SubmitField
from wtforms.validators import Required

class AppModeSelectionForm(Form):
    manage_alerts = SubmitField('Manage Alerts')
    analyze_alerts = SubmitField('Analyze Alerts')
    metrics = SubmitField('Metrics')
